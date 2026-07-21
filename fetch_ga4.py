#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
선암파머스 · GA4 트래픽 수집 (자사몰 sunamfarmers.kr)
=====================================================
GA4 Data API로 일별 방문자·세션·페이지뷰·오가닉 세션을 수집해
data/ga4_daily.json.enc (AES 암호화, 대시보드 비밀번호와 동일 키)로 저장.

환경변수 (GitHub Secrets)
  GA4_PROPERTY_ID      GA4 속성 ID (숫자만, 예: 123456789)
  GA4_SA_JSON          서비스 계정 키 JSON 전체 내용
  IMWEB_DASH_PASSWORD  대시보드 비밀번호 (암호화 키)

사전 준비 (1회)
  1. 아임웹 관리자 > 환경설정 > 마케팅 연동에 GA4 측정 ID(G-XXXX) 등록
  2. Google Cloud 콘솔에서 서비스 계정 생성 + 키(JSON) 발급
  3. GA4 관리 > 속성 액세스 관리에 서비스 계정 이메일을 '뷰어'로 추가
"""
import base64
import datetime
import json
import os
import sys

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

KDF_ITER = 150000
DAYS = 130
# GA4 기본 채널 그룹 중 '유료' 취급 (나머지 = 오가닉)
PAID_GROUPS = {'Paid Search', 'Paid Social', 'Paid Shopping', 'Paid Video',
               'Paid Other', 'Display', 'Cross-network', 'Audio'}


def encrypt_json(obj, pw):
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITER)
    key = kdf.derive(pw.encode('utf-8'))
    ct = AESGCM(key).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode('utf-8'), None)
    return json.dumps({'v': 1, 'kdf': 'PBKDF2-SHA256', 'iter': KDF_ITER,
                       'salt': base64.b64encode(salt).decode(),
                       'iv': base64.b64encode(iv).decode(),
                       'ct': base64.b64encode(ct).decode()})


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def get_access_token(sa: dict) -> str:
    """서비스 계정 JWT → OAuth2 액세스 토큰 (google-auth 불필요, cryptography만 사용)"""
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    header = {'alg': 'RS256', 'typ': 'JWT'}
    claims = {'iss': sa['client_email'],
              'scope': 'https://www.googleapis.com/auth/analytics.readonly',
              'aud': 'https://oauth2.googleapis.com/token',
              'iat': now, 'exp': now + 3600}
    signing_input = (_b64url(json.dumps(header).encode()) + '.'
                     + _b64url(json.dumps(claims).encode()))
    pkey = serialization.load_pem_private_key(sa['private_key'].encode(), password=None)
    sig = pkey.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    jwt = signing_input + '.' + _b64url(sig)
    r = requests.post('https://oauth2.googleapis.com/token',
                      data={'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                            'assertion': jwt}, timeout=30)
    r.raise_for_status()
    return r.json()['access_token']


def run_report(pid: str, token: str, dims: list, days: int, limit: int = 100000,
               order_by_sessions: bool = False) -> list:
    body = {
        'dateRanges': [{'startDate': f'{days}daysAgo', 'endDate': 'today'}],
        'dimensions': [{'name': d} for d in dims],
        'metrics': [{'name': 'sessions'}, {'name': 'totalUsers'},
                    {'name': 'screenPageViews'}, {'name': 'purchaseRevenue'},
                    {'name': 'transactions'}],
        'limit': limit,
    }
    if order_by_sessions:
        body['orderBys'] = [{'metric': {'metricName': 'sessions'}, 'desc': True}]
    r = requests.post(f'https://analyticsdata.googleapis.com/v1beta/properties/{pid}:runReport',
                      headers={'Authorization': f'Bearer {token}'}, json=body, timeout=60)
    r.raise_for_status()
    return r.json().get('rows', [])


def _mvals(row):
    v = row['metricValues']
    return (int(v[0]['value'] or 0), int(v[1]['value'] or 0), int(v[2]['value'] or 0),
            round(float(v[3]['value'] or 0)), int(v[4]['value'] or 0))


WINDOWS = (7, 14, 30, 60, 130)


def norm_page(p):
    """랜딩 URL 정규화: utm 등 노이즈 제거, 상품 구분자(idx)만 유지"""
    p = str(p or '')
    if '?' not in p:
        return p
    path, q = p.split('?', 1)
    keep = [kv for kv in q.split('&') if kv.split('=')[0] in ('idx', 'category')]
    return path + (('?' + '&'.join(keep)) if keep else '')


def dim_report(pid, token, dim, skip_vals=()):
    """구간별 상위 20개 (캠페인·랜딩페이지용)"""
    out = {}
    for w in WINDOWS:
        rows = run_report(pid, token, [dim], w, limit=20, order_by_sessions=True)
        lst = []
        for row in rows:
            name = row['dimensionValues'][0]['value']
            if name in skip_vals:
                continue
            sess, users, pv, rev, trans = _mvals(row)
            lst.append({'name': name, 'sess': sess, 'rev': rev, 'trans': trans})
        out[str(w)] = lst
    return out


def main():
    pid = os.environ.get('GA4_PROPERTY_ID', '').strip()
    sa_raw = os.environ.get('GA4_SA_JSON', '').strip()
    pw = os.environ.get('IMWEB_DASH_PASSWORD', '').strip()
    if not pid or not sa_raw:
        print('GA4 미설정 (GA4_PROPERTY_ID / GA4_SA_JSON 없음) — 건너뜀')
        sys.exit(0)
    if not pw:
        print('IMWEB_DASH_PASSWORD 없음', file=sys.stderr)
        sys.exit(1)

    sa = json.loads(sa_raw)
    token = get_access_token(sa)
    rows = run_report(pid, token, ['date', 'sessionDefaultChannelGroup'], DAYS)
    print(f'GA4 행 {len(rows)}건 수신')

    daily, channels = {}, []
    for row in rows:
        d8 = row['dimensionValues'][0]['value']          # YYYYMMDD
        grp = row['dimensionValues'][1]['value']
        dt = f'{d8[:4]}-{d8[4:6]}-{d8[6:]}'
        sess, users, pv, rev, trans = _mvals(row)
        r = daily.setdefault(dt, {'date': dt, 'sessions': 0, 'users': 0, 'pv': 0, 'orgSessions': 0,
                                  'rev': 0, 'orgRev': 0, 'trans': 0})
        r['sessions'] += sess
        r['users'] += users   # 채널 합산 근사 (교차 채널 중복 소폭 포함)
        r['pv'] += pv
        r['rev'] += rev
        r['trans'] += trans
        if grp not in PAID_GROUPS:
            r['orgSessions'] += sess
            r['orgRev'] += rev
        channels.append({'date': dt, 'ch': grp, 'sess': sess, 'rev': rev, 'trans': trans})

    print('캠페인(UTM)별 수집...')
    campaigns = dim_report(pid, token, 'sessionCampaignName', skip_vals=('(not set)',))
    print('랜딩페이지별 수집...')
    landing = {}
    for w in WINDOWS:
        agg_l = {}
        for row in run_report(pid, token, ['landingPagePlusQueryString'], w,
                              limit=300, order_by_sessions=True):
            name = norm_page(row['dimensionValues'][0]['value'])
            sess, users, pv, rev, trans = _mvals(row)
            a = agg_l.setdefault(name, {'name': name, 'sess': 0, 'rev': 0, 'trans': 0})
            a['sess'] += sess; a['rev'] += rev; a['trans'] += trans
        landing[str(w)] = sorted(agg_l.values(), key=lambda x: -x['sess'])[:20]

    # 캠페인 × 랜딩페이지 (캠페인 클릭 드릴다운용)
    print('캠페인×랜딩 수집...')
    camp_landing = {}
    for w in WINDOWS:
        rows3 = run_report(pid, token, ['sessionCampaignName', 'landingPagePlusQueryString'],
                           w, limit=500, order_by_sessions=True)
        agg_c = {}
        for row in rows3:
            camp = row['dimensionValues'][0]['value']
            page = norm_page(row['dimensionValues'][1]['value'])
            if camp == '(not set)':
                continue
            sess, users, pv, rev, trans = _mvals(row)
            a = agg_c.setdefault((camp, page), {'camp': camp, 'name': page, 'sess': 0, 'rev': 0, 'trans': 0})
            a['sess'] += sess; a['rev'] += rev; a['trans'] += trans
        camp_landing[str(w)] = sorted(agg_c.values(), key=lambda x: -x['sess'])[:300]

    # 채널 × 소스 상세 (도넛 클릭 드릴다운용)
    print('채널×소스별 수집...')
    ch_sources = {}
    for w in WINDOWS:
        rows2 = run_report(pid, token, ['sessionDefaultChannelGroup', 'sessionSourceMedium'],
                           w, limit=120, order_by_sessions=True)
        lst = []
        for row in rows2:
            ch = row['dimensionValues'][0]['value']
            srcm = row['dimensionValues'][1]['value']
            sess, users, pv, rev, trans = _mvals(row)
            lst.append({'ch': ch, 'name': srcm, 'sess': sess, 'rev': rev, 'trans': trans})
        ch_sources[str(w)] = lst

    out = {'updated': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'daily': [daily[k] for k in sorted(daily)],
           'channels': channels,
           'campaigns': campaigns,
           'landing': landing,
           'chSources': ch_sources,
           'campLanding': camp_landing}
    os.makedirs('data', exist_ok=True)
    with open('data/ga4_daily.json.enc', 'w', encoding='utf-8') as f:
        f.write(encrypt_json(out, pw))
    print(f'저장 완료 — {len(out["daily"])}일치')


if __name__ == '__main__':
    main()
