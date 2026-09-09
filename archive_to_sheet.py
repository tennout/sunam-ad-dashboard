#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
선암파머스 · 광고 데이터 구글시트 아카이브
==========================================
매일 광고 수집(네이버+메타) 직후 실행 — 구글시트에 일자별 한 줄씩 누적.
탭 3개: 네이버검색광고 / 메타 / 메타_캠페인별
- 시트에 없는 날짜만 추가 (최초 실행 시 보유 이력 전체 백필)
- 공휴일·일요일 행은 연한 빨강 배경
- 시트는 추가만 하고 기존 행은 절대 수정하지 않음

준비 (1회)
  1. 구글시트 새로 만들기 → 공유: dashboard-reader@sunam-dashboard.iam.gserviceaccount.com (편집자)
  2. 시트 URL의 /d/와 /edit 사이 ID를 GitHub Secrets에 ARCHIVE_SHEET_ID로 등록

환경변수
  ARCHIVE_SHEET_ID     대상 스프레드시트 ID (필수)
  GA4_SA_JSON          서비스 계정 키 JSON (필수 — 시트 쓰기 인증)
  IMWEB_DASH_PASSWORD  (선택) 있으면 메타 탭에 GA4 실측 매출·ROAS 컬럼 채움
"""
import base64
import datetime
import glob
import json
import os
import sys

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

try:
    import holidays as _hol
    KR_HOLIDAYS = _hol.KR(years=range(2024, 2031))
except Exception:
    KR_HOLIDAYS = {}

KST = datetime.timezone(datetime.timedelta(hours=9))
SHEETS = 'https://sheets.googleapis.com/v4/spreadsheets'

TAB_NAVER = '네이버검색광고'
TAB_META = '메타'
TAB_META_CAMP = '메타_캠페인별'
HDR_NAVER = ['날짜', '노출', '클릭', 'CTR(%)', 'CPC', '광고비', '전환수', '전환매출', 'ROAS(%)']
HDR_META = ['날짜', '노출', '클릭', 'CTR(%)', 'CPC', '지출', '구매', '메타매출', '메타ROAS(%)',
            '실측매출(GA4)', '실측ROAS(%)']
HDR_MCAMP = ['날짜', '캠페인', '노출', '클릭', 'CTR(%)', 'CPC', '지출', '구매', '메타매출', 'ROAS(%)']
RED = {'red': 1.0, 'green': 0.93, 'blue': 0.90}   # 빨간날 행 — 연한 빨강
WHITE = {'red': 1, 'green': 1, 'blue': 1}
INK = {'red': 0.13, 'green': 0.13, 'blue': 0.13}


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def sheets_token(sa):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    header = {'alg': 'RS256', 'typ': 'JWT'}
    claims = {'iss': sa['client_email'],
              'scope': 'https://www.googleapis.com/auth/spreadsheets',
              'aud': 'https://oauth2.googleapis.com/token', 'iat': now, 'exp': now + 3600}
    si = _b64url(json.dumps(header).encode()) + '.' + _b64url(json.dumps(claims).encode())
    pk = serialization.load_pem_private_key(sa['private_key'].encode(), password=None)
    sig = pk.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256())
    r = requests.post('https://oauth2.googleapis.com/token',
                      data={'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                            'assertion': si + '.' + _b64url(sig)}, timeout=30)
    r.raise_for_status()
    return r.json()['access_token']


def is_red_day(dstr):
    try:
        d = datetime.date.fromisoformat(dstr)
        return d.weekday() >= 5 or d in KR_HOLIDAYS   # 토·일 + 공휴일
    except Exception:
        return False


def decrypt_json(raw, pw):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    o = json.loads(raw)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=base64.b64decode(o['salt']), iterations=int(o['iter']))
    key = kdf.derive(pw.encode())
    pt = AESGCM(key).decrypt(base64.b64decode(o['iv']), base64.b64decode(o['ct']), None)
    return json.loads(pt.decode())


class Sheet:
    def __init__(self, sid, token):
        self.sid = sid
        self.h = {'Authorization': f'Bearer {token}'}
        meta = requests.get(f'{SHEETS}/{sid}', headers=self.h, timeout=30).json()
        if 'sheets' not in meta:
            sys.exit(f'시트 접근 실패 — 공유(편집자) 확인: {json.dumps(meta)[:200]}')
        self.tabs = {s['properties']['title']: s['properties']['sheetId'] for s in meta['sheets']}

    def ensure_tab(self, title, header, widths=None, numfmt=None, freeze_cols=1):
        if title not in self.tabs:
            r = requests.post(f'{SHEETS}/{self.sid}:batchUpdate', headers=self.h,
                              json={'requests': [{'addSheet': {'properties': {'title': title}}}]},
                              timeout=30)
            r.raise_for_status()
            self.tabs[title] = r.json()['replies'][0]['addSheet']['properties']['sheetId']
        col_a = self.col_a(title)
        if not col_a:
            requests.put(f'{SHEETS}/{self.sid}/values/{title}!A1',
                         headers=self.h, params={'valueInputOption': 'RAW'},
                         json={'values': [header]}, timeout=30).raise_for_status()
            self._style_tab(title, header, widths or [], numfmt or {}, freeze_cols)

    def _style_tab(self, title, header, widths, numfmt, freeze_cols):
        """최초 생성 시 1회: 헤더 스타일·틀고정·열너비·숫자서식·필터"""
        gid = self.tabs[title]
        n = len(header)
        reqs = [
            # 틀고정: 헤더 1행 + 날짜(등) 좌측 열
            {'updateSheetProperties': {'properties': {'sheetId': gid, 'gridProperties': {
                'frozenRowCount': 1, 'frozenColumnCount': freeze_cols}},
                'fields': 'gridProperties.frozenRowCount,gridProperties.frozenColumnCount'}},
            # 헤더: 짙은 배경·흰 글씨·볼드·가운데 정렬
            {'repeatCell': {'range': {'sheetId': gid, 'startRowIndex': 0, 'endRowIndex': 1,
                                      'startColumnIndex': 0, 'endColumnIndex': n},
                'cell': {'userEnteredFormat': {
                    'backgroundColor': {'red': 0.18, 'green': 0.23, 'blue': 0.20},
                    'textFormat': {'foregroundColor': {'red': 1, 'green': 1, 'blue': 1}, 'bold': True},
                    'horizontalAlignment': 'CENTER', 'verticalAlignment': 'MIDDLE'}},
                'fields': 'userEnteredFormat(backgroundColor,textFormat,horizontalAlignment,verticalAlignment)'}},
            # 기본 필터 (헤더 클릭 정렬·필터)
            {'setBasicFilter': {'filter': {'range': {'sheetId': gid, 'startRowIndex': 0,
                                                     'startColumnIndex': 0, 'endColumnIndex': n}}}},
        ]
        # 열 너비
        for i, w in enumerate(widths):
            if w:
                reqs.append({'updateDimensionProperties': {
                    'range': {'sheetId': gid, 'dimension': 'COLUMNS', 'startIndex': i, 'endIndex': i + 1},
                    'properties': {'pixelSize': w}, 'fields': 'pixelSize'}})
        # 숫자 서식 (데이터 영역 전체 열에 적용 → 이후 append 행도 자동 상속)
        for i, pat in numfmt.items():
            reqs.append({'repeatCell': {
                'range': {'sheetId': gid, 'startRowIndex': 1,
                          'startColumnIndex': i, 'endColumnIndex': i + 1},
                'cell': {'userEnteredFormat': {'numberFormat': {'type': 'NUMBER', 'pattern': pat}}},
                'fields': 'userEnteredFormat.numberFormat'}})
        requests.post(f'{SHEETS}/{self.sid}:batchUpdate', headers=self.h,
                      json={'requests': reqs}, timeout=60).raise_for_status()

    def col_a(self, title):
        r = requests.get(f'{SHEETS}/{self.sid}/values/{title}!A:A', headers=self.h, timeout=30)
        return [row[0] if row else '' for row in r.json().get('values', [])]

    def append(self, title, rows):
        if not rows:
            return 0
        r = requests.post(f'{SHEETS}/{self.sid}/values/{title}!A1:append',
                          headers=self.h,
                          params={'valueInputOption': 'RAW', 'insertDataOption': 'INSERT_ROWS'},
                          json={'values': rows}, timeout=60)
        r.raise_for_status()
        return len(rows)

    def normalize_rows(self, title, start, count, ncols, red_rows, left_cols=1, numfmt=None):
        """append는 윗줄 서식을 상속하므로, 새 행을 기본 서식(흰 배경·일반 글씨)으로
        초기화하고 빨간날만 연한 빨강. start=0-based 시작 행, red_rows=0-based 행 목록."""
        if not count:
            return
        gid = self.tabs[title]
        reqs = [
            # 기본: 흰 배경 · 볼드 해제 · 진회색 글씨 · 숫자 우측 정렬
            {'repeatCell': {'range': {'sheetId': gid, 'startRowIndex': start, 'endRowIndex': start + count,
                                      'startColumnIndex': 0, 'endColumnIndex': ncols},
                'cell': {'userEnteredFormat': {'backgroundColor': WHITE,
                    'textFormat': {'bold': False, 'foregroundColor': INK},
                    'horizontalAlignment': 'RIGHT'}},
                'fields': 'userEnteredFormat(backgroundColor,textFormat,horizontalAlignment)'}},
            # 날짜(·캠페인) 열은 좌측 정렬
            {'repeatCell': {'range': {'sheetId': gid, 'startRowIndex': start, 'endRowIndex': start + count,
                                      'startColumnIndex': 0, 'endColumnIndex': left_cols},
                'cell': {'userEnteredFormat': {'horizontalAlignment': 'LEFT'}},
                'fields': 'userEnteredFormat.horizontalAlignment'}},
        ]
        # 숫자 서식 (₩·콤마·%) — append 상속이 서식을 지우므로 새 행에 매번 재적용
        for ci, pat in (numfmt or {}).items():
            reqs.append({'repeatCell': {
                'range': {'sheetId': gid, 'startRowIndex': start, 'endRowIndex': start + count,
                          'startColumnIndex': ci, 'endColumnIndex': ci + 1},
                'cell': {'userEnteredFormat': {'numberFormat': {'type': 'NUMBER', 'pattern': pat}}},
                'fields': 'userEnteredFormat.numberFormat'}})
        reqs += [{'repeatCell': {
            'range': {'sheetId': gid, 'startRowIndex': i, 'endRowIndex': i + 1,
                      'startColumnIndex': 0, 'endColumnIndex': ncols},
            'cell': {'userEnteredFormat': {'backgroundColor': RED}},
            'fields': 'userEnteredFormat.backgroundColor'}} for i in red_rows]
        for i in range(0, len(reqs), 100):
            requests.post(f'{SHEETS}/{self.sid}:batchUpdate', headers=self.h,
                          json={'requests': reqs[i:i + 100]}, timeout=60).raise_for_status()


def agg_daily(rows):
    """[{date,imp,clk,cost,conv,rev}] → {date: totals}"""
    out = {}
    for r in rows:
        d = r.get('date') or ''
        if not d:
            continue
        o = out.setdefault(d, {'imp': 0, 'clk': 0, 'cost': 0, 'conv': 0, 'rev': 0})
        for k in o:
            o[k] += r.get(k, 0) or 0
    return out


def kpi_row(d, o, extra=None):
    ctr = round(o['clk'] / o['imp'] * 100, 2) if o['imp'] else 0
    cpc = round(o['cost'] / o['clk']) if o['clk'] else 0
    roas = round(o['rev'] / o['cost'] * 100) if o['cost'] else 0
    row = [d, o['imp'], o['clk'], ctr, cpc, o['cost'], o['conv'], o['rev'], roas]
    if extra is not None:
        row += extra
    return row


FMT_INT='#,##0'; FMT_WON='₩#,##0'; FMT_PCT='0.00"%"'; FMT_ROAS='0"%"'
STYLE = {
    TAB_NAVER: dict(widths=[90,80,70,70,80,95,70,105,70],
                    numfmt={1:FMT_INT,2:FMT_INT,3:FMT_PCT,4:FMT_WON,5:FMT_WON,6:FMT_INT,7:FMT_WON,8:FMT_ROAS}, freeze=1),
    TAB_META:  dict(widths=[90,80,70,70,80,95,60,105,95,105,95],
                    numfmt={1:FMT_INT,2:FMT_INT,3:FMT_PCT,4:FMT_WON,5:FMT_WON,6:FMT_INT,7:FMT_WON,8:FMT_ROAS,9:FMT_WON,10:FMT_ROAS}, freeze=1),
    TAB_META_CAMP: dict(widths=[90,230,80,70,70,80,95,60,105,80],
                    numfmt={2:FMT_INT,3:FMT_INT,4:FMT_PCT,5:FMT_WON,6:FMT_WON,7:FMT_INT,8:FMT_WON,9:FMT_ROAS}, freeze=2),
}

def sync_tab(sh, title, header, want_rows, key_fn):
    """want_rows: [(key, row)] — 시트에 없는 key만 추가하고 빨간날 색칠"""
    st=STYLE.get(title,{})
    sh.ensure_tab(title, header, st.get('widths'), st.get('numfmt'), st.get('freeze',1))
    col_a = sh.col_a(title)
    existing_keys = set()
    for i, v in enumerate(col_a):
        if i == 0:
            continue
        existing_keys.add(key_fn(i, v))
    new = [(k, row) for k, row in want_rows if k not in existing_keys]
    start = len(col_a)                     # 0-based 다음 행 인덱스
    sh.append(title, [row for _, row in new])
    reds = [start + i for i, (_, row) in enumerate(new) if is_red_day(str(row[0]))]
    sh.normalize_rows(title, start, len(new), len(header), reds,
                      left_cols=2 if title == TAB_META_CAMP else 1,
                      numfmt=st.get('numfmt'))
    print(f'  {title}: +{len(new)}행 (빨간날 {len(reds)})')


def main():
    sid = os.environ.get('ARCHIVE_SHEET_ID', '').strip()
    sa_raw = os.environ.get('GA4_SA_JSON', '').strip()
    pw = os.environ.get('IMWEB_DASH_PASSWORD', '').strip()
    if not sid or not sa_raw:
        print('ARCHIVE_SHEET_ID / GA4_SA_JSON 미설정 — 아카이브 건너뜀')
        sys.exit(0)
    token = sheets_token(json.loads(sa_raw))
    sh = Sheet(sid, token)
    today = datetime.datetime.now(KST).date().isoformat()

    # ── 네이버 (data/{customerId}.json — 숫자 파일명) ──
    naver_rows = []
    for f in glob.glob('data/[0-9]*.json'):
        try:
            naver_rows += json.load(open(f, encoding='utf-8')).get('daily', [])
        except Exception as e:
            print(f'! {f} 로드 실패: {e}')
    nv = agg_daily(naver_rows)
    want = [(d, kpi_row(d, nv[d])) for d in sorted(nv) if d < today]   # 오늘(미완성 데이터)은 제외
    sync_tab(sh, TAB_NAVER, HDR_NAVER, want, lambda i, v: v)

    # ── 메타 ──
    meta_rows = []
    try:
        meta_rows = json.load(open('data/meta.json', encoding='utf-8')).get('daily', [])
    except Exception as e:
        print(f'! data/meta.json 로드 실패: {e}')
    mt = agg_daily(meta_rows)
    # GA4 실측 (선택)
    ga_day = {}
    if pw and os.path.exists('data/ga4_daily.json.enc'):
        try:
            g = decrypt_json(open('data/ga4_daily.json.enc', encoding='utf-8').read(), pw)
            for r in g.get('daily', []):
                ga_day[r['date']] = max(0, (r.get('rev', 0) or 0) - (r.get('orgRev', 0) or 0))
        except Exception as e:
            print(f'! GA4 복호화 실패(실측 컬럼 생략): {e}')
    want = []
    for d in sorted(mt):
        if d >= today:
            continue
        o = mt[d]
        gr = ga_day.get(d)
        groas = round(gr / o['cost'] * 100) if (gr is not None and o['cost']) else ''
        want.append((d, kpi_row(d, o, extra=[gr if gr is not None else '', groas])))
    sync_tab(sh, TAB_META, HDR_META, want, lambda i, v: v)

    # ── 메타 캠페인별 (키 = 날짜|캠페인) ──
    camp = {}
    for r in meta_rows:
        d, c = r.get('date') or '', r.get('campaign') or ''
        if not d or not c or d >= today:
            continue
        o = camp.setdefault((d, c), {'imp': 0, 'clk': 0, 'cost': 0, 'conv': 0, 'rev': 0})
        for k in o:
            o[k] += r.get(k, 0) or 0
    # 시트의 기존 키 복원용: B열(캠페인)도 필요 → col B 읽기
    _st=STYLE[TAB_META_CAMP]
    sh.ensure_tab(TAB_META_CAMP, HDR_MCAMP, _st['widths'], _st['numfmt'], _st['freeze'])
    ra = requests.get(f'{SHEETS}/{sid}/values/{TAB_META_CAMP}!A:B', headers=sh.h, timeout=30)
    vals = ra.json().get('values', [])
    existing = {(row[0], row[1] if len(row) > 1 else '') for row in vals[1:]}
    new = []
    for (d, c) in sorted(camp):
        if (d, c) in existing:
            continue
        o = camp[(d, c)]
        ctr = round(o['clk'] / o['imp'] * 100, 2) if o['imp'] else 0
        cpc = round(o['cost'] / o['clk']) if o['clk'] else 0
        roas = round(o['rev'] / o['cost'] * 100) if o['cost'] else 0
        new.append([d, c, o['imp'], o['clk'], ctr, cpc, o['cost'], o['conv'], o['rev'], roas])
    start = len(vals)
    sh.append(TAB_META_CAMP, new)
    reds = [start + i for i, row in enumerate(new) if is_red_day(str(row[0]))]
    sh.normalize_rows(TAB_META_CAMP, start, len(new), len(HDR_MCAMP), reds, left_cols=2, numfmt=_st['numfmt'])
    print(f'  {TAB_META_CAMP}: +{len(new)}행 (빨간날 {len(reds)})')
    print('아카이브 완료')


if __name__ == '__main__':
    main()
