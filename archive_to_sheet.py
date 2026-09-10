#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
선암파머스 · 광고 데이터 구글시트 아카이브 (v2 — 헤더 매핑)
==========================================================
매일 광고 수집(네이버+메타) 직후 실행 — 구글시트에 일자별 한 줄씩 누적.
탭 3개: 네이버검색광고 / 메타 / 메타_캠페인별

v2: 열 위치를 헤더 이름으로 찾아서 기록 — 사용자가 열 순서를 바꾸거나
    중간에 메모 열을 추가해도 항상 올바른 열에 쌓임.
- 시트에 없는 날짜만 추가 (최초 실행 시 보유 이력 전체 백필)
- 토·일·공휴일 행은 연한 빨강 배경
- 기존 행은 절대 수정하지 않음 · 필요한 헤더가 없으면 맨 오른쪽에 추가

환경변수
  ARCHIVE_SHEET_ID     대상 스프레드시트 ID (필수)
  GA4_SA_JSON          서비스 계정 키 JSON (필수 — 시트 쓰기 인증)
  IMWEB_DASH_PASSWORD  (선택) 메타 탭 실측 컬럼용
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
HDR_NAVER = ['날짜', '일예산', '노출', '클릭', 'CTR(%)', 'CPC', '광고비', '전환수', '전환매출', 'ROAS(%)']
HDR_META = ['날짜', '일예산', '노출', '클릭', 'CTR(%)', 'CPC', '지출', '구매', '메타매출', '메타ROAS(%)',
            '실측매출(GA4)', '실측ROAS(%)']
HDR_MCAMP = ['날짜', '캠페인', '일예산', '노출', '클릭', 'CTR(%)', 'CPC', '지출', '구매', '메타매출', 'ROAS(%)']

RED = {'red': 1.0, 'green': 0.93, 'blue': 0.90}   # 빨간날(토·일·공휴일) 행
WHITE = {'red': 1, 'green': 1, 'blue': 1}
INK = {'red': 0.13, 'green': 0.13, 'blue': 0.13}
FMT_INT = '#,##0'
FMT_WON = '₩#,##0'
FMT_PCT = '0.00"%"'
FMT_ROAS = '0"%"'
# 헤더 이름 → 숫자 서식 (열 위치와 무관하게 이름으로 판단)
NUMFMT_BY_HEADER = {
    '일예산': FMT_WON, '지출': FMT_WON, '광고비': FMT_WON, 'CPC': FMT_WON,
    '메타매출': FMT_WON, '전환매출': FMT_WON, '실측매출(GA4)': FMT_WON,
    '노출': FMT_INT, '클릭': FMT_INT, '구매': FMT_INT, '전환수': FMT_INT,
    'CTR(%)': FMT_PCT, 'ROAS(%)': FMT_ROAS, '메타ROAS(%)': FMT_ROAS, '실측ROAS(%)': FMT_ROAS,
}
LEFT_HEADERS = {'날짜', '캠페인'}   # 좌측 정렬 열
WIDTH_BY_HEADER = {'날짜': 90, '캠페인': 230, '일예산': 90, '노출': 80, '클릭': 70, 'CTR(%)': 70,
                   'CPC': 80, '지출': 95, '광고비': 95, '구매': 60, '전환수': 70,
                   '메타매출': 105, '전환매출': 105, 'ROAS(%)': 80, '메타ROAS(%)': 95,
                   '실측매출(GA4)': 105, '실측ROAS(%)': 95}


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


def col_letter(i):
    """0-based 열 번호 → A1 표기 (0→A, 26→AA)"""
    s = ''
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


class Sheet:
    def __init__(self, sid, token):
        self.sid = sid
        self.h = {'Authorization': f'Bearer {token}'}
        meta = requests.get(f'{SHEETS}/{sid}', headers=self.h, timeout=30).json()
        if 'sheets' not in meta:
            sys.exit(f'시트 접근 실패 — 공유(편집자) 확인: {json.dumps(meta)[:200]}')
        self.tabs = {s['properties']['title']: s['properties']['sheetId'] for s in meta['sheets']}

    def _get_values(self, rng):
        r = requests.get(f'{SHEETS}/{self.sid}/values/{rng}', headers=self.h, timeout=30)
        return r.json().get('values', [])

    def ensure_tab(self, title, default_header):
        """탭·헤더 보장 후 현재 헤더(열 순서) 반환. 필요한 헤더가 없으면 맨 오른쪽에 추가."""
        created = False
        if title not in self.tabs:
            r = requests.post(f'{SHEETS}/{self.sid}:batchUpdate', headers=self.h,
                              json={'requests': [{'addSheet': {'properties': {'title': title}}}]},
                              timeout=30)
            r.raise_for_status()
            self.tabs[title] = r.json()['replies'][0]['addSheet']['properties']['sheetId']
            created = True
        hdr_rows = self._get_values(f'{title}!1:1')
        headers = [h.strip() for h in (hdr_rows[0] if hdr_rows else [])]
        if not headers:
            headers = list(default_header)
            requests.put(f'{SHEETS}/{self.sid}/values/{title}!A1',
                         headers=self.h, params={'valueInputOption': 'RAW'},
                         json={'values': [headers]}, timeout=30).raise_for_status()
            created = True
        else:
            missing = [h for h in default_header if h not in headers]
            if missing:
                start = col_letter(len(headers))
                requests.put(f'{SHEETS}/{self.sid}/values/{title}!{start}1',
                             headers=self.h, params={'valueInputOption': 'RAW'},
                             json={'values': [missing]}, timeout=30).raise_for_status()
                headers += missing
                print(f'  {title}: 누락 헤더 {missing} → 맨 오른쪽에 추가')
        if created:
            self._style_tab(title, headers)
        return headers

    def _style_tab(self, title, headers):
        """탭 최초 생성 시 1회: 헤더 스타일·틀고정·열너비·필터"""
        gid = self.tabs[title]
        n = len(headers)
        freeze = 2 if '캠페인' in headers[:2] else 1
        reqs = [
            {'updateSheetProperties': {'properties': {'sheetId': gid, 'gridProperties': {
                'frozenRowCount': 1, 'frozenColumnCount': freeze}},
                'fields': 'gridProperties.frozenRowCount,gridProperties.frozenColumnCount'}},
            {'repeatCell': {'range': {'sheetId': gid, 'startRowIndex': 0, 'endRowIndex': 1,
                                      'startColumnIndex': 0, 'endColumnIndex': n},
                'cell': {'userEnteredFormat': {
                    'backgroundColor': {'red': 0.18, 'green': 0.23, 'blue': 0.20},
                    'textFormat': {'foregroundColor': WHITE, 'bold': True},
                    'horizontalAlignment': 'CENTER', 'verticalAlignment': 'MIDDLE'}},
                'fields': 'userEnteredFormat(backgroundColor,textFormat,horizontalAlignment,verticalAlignment)'}},
            {'setBasicFilter': {'filter': {'range': {'sheetId': gid, 'startRowIndex': 0,
                                                     'startColumnIndex': 0, 'endColumnIndex': n}}}},
        ]
        for i, hname in enumerate(headers):
            w = WIDTH_BY_HEADER.get(hname)
            if w:
                reqs.append({'updateDimensionProperties': {
                    'range': {'sheetId': gid, 'dimension': 'COLUMNS', 'startIndex': i, 'endIndex': i + 1},
                    'properties': {'pixelSize': w}, 'fields': 'pixelSize'}})
        requests.post(f'{SHEETS}/{self.sid}:batchUpdate', headers=self.h,
                      json={'requests': reqs}, timeout=60).raise_for_status()

    def existing_keys(self, title, headers, key_headers):
        """key_headers 열들의 값 튜플 집합 + 현재 데이터 행 수 반환"""
        idxs = [headers.index(k) for k in key_headers]
        last = col_letter(max(idxs))
        vals = self._get_values(f'{title}!A:{last}')
        keys = set()
        for row in vals[1:]:
            keys.add(tuple((row[i] if i < len(row) else '') for i in idxs))
        return keys, len(vals)

    def append_records(self, title, headers, records):
        """records: [dict(헤더명→값)] — 현재 열 순서에 맞춰 배치해서 추가"""
        if not records:
            return 0
        rows = [[rec.get(h, '') for h in headers] for rec in records]
        r = requests.post(f'{SHEETS}/{self.sid}/values/{title}!A1:append',
                          headers=self.h,
                          params={'valueInputOption': 'RAW', 'insertDataOption': 'INSERT_ROWS'},
                          json={'values': rows}, timeout=60)
        r.raise_for_status()
        return len(rows)

    def normalize_rows(self, title, headers, start, count, red_rows):
        """새 행 서식: 흰 배경·일반 글씨 초기화 + 헤더 이름 기반 숫자서식·정렬 + 빨간날"""
        if not count:
            return
        gid = self.tabs[title]
        n = len(headers)
        reqs = [
            {'repeatCell': {'range': {'sheetId': gid, 'startRowIndex': start, 'endRowIndex': start + count,
                                      'startColumnIndex': 0, 'endColumnIndex': n},
                'cell': {'userEnteredFormat': {'backgroundColor': WHITE,
                    'textFormat': {'bold': False, 'foregroundColor': INK},
                    'horizontalAlignment': 'RIGHT'}},
                'fields': 'userEnteredFormat(backgroundColor,textFormat,horizontalAlignment)'}},
        ]
        for i, hname in enumerate(headers):
            if hname in LEFT_HEADERS:
                reqs.append({'repeatCell': {'range': {'sheetId': gid, 'startRowIndex': start,
                                                      'endRowIndex': start + count,
                                                      'startColumnIndex': i, 'endColumnIndex': i + 1},
                    'cell': {'userEnteredFormat': {'horizontalAlignment': 'LEFT'}},
                    'fields': 'userEnteredFormat.horizontalAlignment'}})
            pat = NUMFMT_BY_HEADER.get(hname)
            if pat:
                reqs.append({'repeatCell': {'range': {'sheetId': gid, 'startRowIndex': start,
                                                      'endRowIndex': start + count,
                                                      'startColumnIndex': i, 'endColumnIndex': i + 1},
                    'cell': {'userEnteredFormat': {'numberFormat': {'type': 'NUMBER', 'pattern': pat}}},
                    'fields': 'userEnteredFormat.numberFormat'}})
        reqs += [{'repeatCell': {
            'range': {'sheetId': gid, 'startRowIndex': i, 'endRowIndex': i + 1,
                      'startColumnIndex': 0, 'endColumnIndex': n},
            'cell': {'userEnteredFormat': {'backgroundColor': RED}},
            'fields': 'userEnteredFormat.backgroundColor'}} for i in red_rows]
        for i in range(0, len(reqs), 100):
            requests.post(f'{SHEETS}/{self.sid}:batchUpdate', headers=self.h,
                          json={'requests': reqs[i:i + 100]}, timeout=60).raise_for_status()


def sync(sh, title, default_header, records, key_headers):
    """records(dict 목록)를 헤더 매핑으로 기록 — key_headers 조합이 이미 있으면 스킵"""
    headers = sh.ensure_tab(title, default_header)
    keys, nrows = sh.existing_keys(title, headers, key_headers)
    new = [r for r in records if tuple(str(r.get(k, '')) for k in key_headers) not in keys]
    sh.append_records(title, headers, new)
    reds = [nrows + i for i, r in enumerate(new) if is_red_day(str(r.get('날짜', '')))]
    sh.normalize_rows(title, headers, nrows, len(new), reds)
    print(f'  {title}: +{len(new)}행 (빨간날 {len(reds)})')


# ── 수집 데이터 → 레코드 ──────────────────────────────
def agg_daily(rows):
    out = {}
    for r in rows:
        d = r.get('date') or ''
        if not d:
            continue
        o = out.setdefault(d, {'imp': 0, 'clk': 0, 'cost': 0, 'conv': 0, 'rev': 0})
        for k in o:
            o[k] += r.get(k, 0) or 0
    return out


def perf_fields(o):
    ctr = round(o['clk'] / o['imp'] * 100, 2) if o['imp'] else 0
    cpc = round(o['cost'] / o['clk']) if o['clk'] else 0
    roas = round(o['rev'] / o['cost'] * 100) if o['cost'] else 0
    return ctr, cpc, roas


NV_HIST_PATH = 'data/naver_budget_history.json'


def naver_budgets():
    """accounts.json으로 네이버 캠페인 일예산 조회 + 이력 파일(data/) 자체 관리"""
    budgets = []
    try:
        accts = json.load(open('accounts.json', encoding='utf-8'))
        acct = accts[0]
        import hmac as _hmac, hashlib as _hashlib, time as _time
        ts = str(int(_time.time() * 1000))
        uri = '/ncc/campaigns'
        msg = f'{ts}.GET.{uri}'.encode()
        sig = base64.b64encode(_hmac.new(acct['secretKey'].encode(), msg, _hashlib.sha256).digest()).decode()
        r = requests.get('https://api.searchad.naver.com' + uri, headers={
            'X-Timestamp': ts, 'X-API-KEY': acct['apiKey'],
            'X-Customer': str(acct['customerId']), 'X-Signature': sig}, timeout=30)
        r.raise_for_status()
        for c in r.json() or []:
            db = c.get('dailyBudget')
            budgets.append({'id': c.get('nccCampaignId'), 'name': c.get('name', ''),
                            'budget': int(db) if db else None, 'status': c.get('status', '')})
        print(f'  네이버 캠페인 예산 {sum(1 for b in budgets if b["budget"])}개 확보')
    except Exception as e:
        print(f'  ! 네이버 예산 조회 실패(이력 파일 사용): {e}')
    store = {'budgets': [], 'history': []}
    try:
        store = json.load(open(NV_HIST_PATH, encoding='utf-8'))
    except Exception:
        pass
    if budgets:
        prev_map = {b['id']: b.get('budget') for b in store.get('budgets', [])}
        today_s = datetime.datetime.now(KST).date().isoformat()
        for b in budgets:
            old = prev_map.get(b['id'])
            if old is not None and b['budget'] is not None and old != b['budget']:
                store['history'].append({'date': today_s, 'id': b['id'], 'name': b['name'],
                                         'from': old, 'to': b['budget']})
        store['budgets'] = budgets
        store['history'] = store['history'][-200:]
        try:
            json.dump(store, open(NV_HIST_PATH, 'w', encoding='utf-8'), ensure_ascii=False)
        except Exception as e:
            print(f'  ! 이력 저장 실패: {e}')
    return store.get('budgets', []), store.get('history', [])


def make_budget_at(cur_map, hist, key):
    hist = sorted(hist, key=lambda h: h.get('date', ''), reverse=True)

    def budget_at(cid, d):
        v = cur_map.get(cid)
        for h in hist:
            if h.get(key) == cid and h.get('date', '') > d:
                v = h.get('from')
        return v
    return budget_at


def main():
    sid = os.environ.get('ARCHIVE_SHEET_ID', '').strip()
    sa_raw = os.environ.get('GA4_SA_JSON', '').strip()
    pw = os.environ.get('IMWEB_DASH_PASSWORD', '').strip()
    if not sid or not sa_raw:
        print('ARCHIVE_SHEET_ID / GA4_SA_JSON 미설정 — 아카이브 건너뜀')
        sys.exit(0)
    sh = Sheet(sid, sheets_token(json.loads(sa_raw)))
    today = datetime.datetime.now(KST).date().isoformat()

    # ── 네이버 ──
    naver_rows = []
    for f in glob.glob('data/[0-9]*.json'):
        try:
            naver_rows += json.load(open(f, encoding='utf-8')).get('daily', [])
        except Exception as e:
            print(f'! {f} 로드 실패: {e}')
    nv = agg_daily(naver_rows)
    nv_budgets, nv_hist = naver_budgets()
    nv_at = make_budget_at({b['id']: b.get('budget') for b in nv_budgets}, nv_hist, 'id')
    nv_days = {}
    for r in naver_rows:
        if r.get('date') and r.get('campaign') and (r.get('cost', 0) or r.get('imp', 0)):
            nv_days.setdefault(r['date'], set()).add(r['campaign'])
    recs = []
    for d in sorted(nv):
        if d >= today:
            continue
        o = nv[d]
        ctr, cpc, roas = perf_fields(o)
        bud = sum(nv_at(c, d) or 0 for c in nv_days.get(d, ()))
        recs.append({'날짜': d, '일예산': bud or '', '노출': o['imp'], '클릭': o['clk'],
                     'CTR(%)': ctr, 'CPC': cpc, '광고비': o['cost'],
                     '전환수': o['conv'], '전환매출': o['rev'], 'ROAS(%)': roas})
    sync(sh, TAB_NAVER, HDR_NAVER, recs, ['날짜'])

    # ── 메타 ──
    meta_rows, mj = [], {}
    try:
        mj = json.load(open('data/meta.json', encoding='utf-8'))
        meta_rows = mj.get('daily', [])
    except Exception as e:
        print(f'! data/meta.json 로드 실패: {e}')
    mt = agg_daily(meta_rows)
    mt_at = make_budget_at({b['campaign']: b.get('budget') for b in mj.get('budgets', [])},
                           mj.get('budgetHistory', []), 'campaign')
    mt_days = {}
    for r in meta_rows:
        if r.get('date') and r.get('campaign'):
            mt_days.setdefault(r['date'], set()).add(r['campaign'])
    ga_day = {}
    if pw and os.path.exists('data/ga4_daily.json.enc'):
        try:
            g = decrypt_json(open('data/ga4_daily.json.enc', encoding='utf-8').read(), pw)
            for r in g.get('daily', []):
                ga_day[r['date']] = max(0, (r.get('rev', 0) or 0) - (r.get('orgRev', 0) or 0))
        except Exception as e:
            print(f'! GA4 복호화 실패(실측 컬럼 생략): {e}')
    recs = []
    for d in sorted(mt):
        if d >= today:
            continue
        o = mt[d]
        ctr, cpc, roas = perf_fields(o)
        bud = sum(mt_at(c, d) or 0 for c in mt_days.get(d, ()))
        gr = ga_day.get(d)
        recs.append({'날짜': d, '일예산': bud or '', '노출': o['imp'], '클릭': o['clk'],
                     'CTR(%)': ctr, 'CPC': cpc, '지출': o['cost'], '구매': o['conv'],
                     '메타매출': o['rev'], '메타ROAS(%)': roas,
                     '실측매출(GA4)': gr if gr is not None else '',
                     '실측ROAS(%)': round(gr / o['cost'] * 100) if (gr is not None and o['cost']) else ''})
    sync(sh, TAB_META, HDR_META, recs, ['날짜'])

    # ── 메타 캠페인별 ──
    camp = {}
    for r in meta_rows:
        d, c = r.get('date') or '', r.get('campaign') or ''
        if not d or not c or d >= today:
            continue
        o = camp.setdefault((d, c), {'imp': 0, 'clk': 0, 'cost': 0, 'conv': 0, 'rev': 0})
        for k in o:
            o[k] += r.get(k, 0) or 0
    recs = []
    for (d, c) in sorted(camp):
        o = camp[(d, c)]
        ctr, cpc, roas = perf_fields(o)
        recs.append({'날짜': d, '캠페인': c, '일예산': mt_at(c, d) or '', '노출': o['imp'],
                     '클릭': o['clk'], 'CTR(%)': ctr, 'CPC': cpc, '지출': o['cost'],
                     '구매': o['conv'], '메타매출': o['rev'], 'ROAS(%)': roas})
    sync(sh, TAB_META_CAMP, HDR_MCAMP, recs, ['날짜', '캠페인'])
    print('아카이브 완료')


if __name__ == '__main__':
    main()
