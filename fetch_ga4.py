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


def run_report(pid: str, token: str) -> list:
    body = {
        'dateRanges': [{'startDate': f'{DAYS}daysAgo', 'endDate': 'today'}],
        'dimensions': [{'name': 'date'}, {'name': 'sessionDefaultChannelGroup'}],
        'metrics': [{'name': 'sessions'}, {'name': 'totalUsers'},
                    {'name': 'screenPageViews'}],
        'limit': 100000,
    }
    r = requests.post(f'https://analyticsdata.googleapis.com/v1beta/properties/{pid}:runReport',
                      headers={'Authorization': f'Bearer {token}'}, json=body, timeout=60)
    r.raise_for_status()
    return r.json().get('rows', [])


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
    rows = run_report(pid, token)
    print(f'GA4 행 {len(rows)}건 수신')

    daily = {}
    for row in rows:
        d8 = row['dimensionValues'][0]['value']          # YYYYMMDD
        grp = row['dimensionValues'][1]['value']
        dt = f'{d8[:4]}-{d8[4:6]}-{d8[6:]}'
        sess = int(row['metricValues'][0]['value'] or 0)
        users = int(row['metricValues'][1]['value'] or 0)
        pv = int(row['metricValues'][2]['value'] or 0)
        r = daily.setdefault(dt, {'date': dt, 'sessions': 0, 'users': 0, 'pv': 0, 'orgSessions': 0})
        r['sessions'] += sess
        r['users'] += users   # 채널 합산 근사 (교차 채널 중복 소폭 포함)
        r['pv'] += pv
        if grp not in PAID_GROUPS:
            r['orgSessions'] += sess

    out = {'updated': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'daily': [daily[k] for k in sorted(daily)]}
    os.makedirs('data', exist_ok=True)
    with open('data/ga4_daily.json.enc', 'w', encoding='utf-8') as f:
        f.write(encrypt_json(out, pw))
    print(f'저장 완료 — {len(out["daily"])}일치')


if __name__ == '__main__':
    main()
