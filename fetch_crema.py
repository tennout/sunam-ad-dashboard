#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
선암파머스 · 크리마(CREMA) 리뷰 수집
====================================
CREMA Review API로 리뷰(별점·본문·사진·상품코드)를 수집해
data/crema_reviews.json.enc (AES 암호화, 대시보드 비밀번호와 동일 키)로 저장.
매 실행마다 최근 45일을 다시 받아 기존 데이터와 병합 (수정·삭제 반영 + 영구 보존).

환경변수 (GitHub Secrets)
  CREMA_APP_ID         크리마 API 키 APP_ID
  CREMA_SECRET         크리마 API 키 SECRET
  IMWEB_DASH_PASSWORD  대시보드 비밀번호 (암호화 키)
  CREMA_BACKFILL_DAYS  (선택) 최초 소급 일수. 기본 365
"""
import base64
import datetime
import json
import os
import sys
import time

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF_ITER = 150000
API = 'https://api.cre.ma'
OUT = 'data/crema_reviews.json.enc'
CHUNK_DAYS = 44          # 조회 기간 최대 45일 제한
KEEP = 2000              # 대시보드 페이로드에 유지할 최근 리뷰 수


def _derive(pw, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITER)
    return kdf.derive(pw.encode('utf-8'))


def encrypt_json(obj, pw):
    salt = os.urandom(16)
    iv = os.urandom(12)
    ct = AESGCM(_derive(pw, salt)).encrypt(
        iv, json.dumps(obj, ensure_ascii=False).encode('utf-8'), None)
    return json.dumps({'v': 1, 'kdf': 'PBKDF2-SHA256', 'iter': KDF_ITER,
                       'salt': base64.b64encode(salt).decode(),
                       'iv': base64.b64encode(iv).decode(),
                       'ct': base64.b64encode(ct).decode()})


def decrypt_json(raw, pw):
    o = json.loads(raw)
    pt = AESGCM(_derive(pw, base64.b64decode(o['salt']))).decrypt(
        base64.b64decode(o['iv']), base64.b64decode(o['ct']), None)
    return json.loads(pt.decode('utf-8'))


def get_token(app_id, secret):
    r = requests.post(f'{API}/oauth/token',
                      data={'grant_type': 'client_credentials',
                            'client_id': app_id, 'client_secret': secret},
                      timeout=30)
    r.raise_for_status()
    return r.json()['access_token']


def fetch_range(token, start, end):
    """start~end (date) 구간 리뷰 전부 (페이지네이션)"""
    out = []
    page = 1
    while page <= 30:
        r = requests.get(f'{API}/v1/reviews', params={
            'access_token': token, 'limit': 100, 'page': page,
            'start_date': start.isoformat(), 'end_date': end.isoformat(),
            'date_order_desc': 1,
        }, timeout=60)
        if r.status_code == 401:
            raise RuntimeError('토큰 만료/무효 — 재실행 필요')
        r.raise_for_status()
        rows = r.json()
        if not isinstance(rows, list) or not rows:
            break
        out.extend(rows)
        if len(rows) < 100:
            break
        page += 1
        time.sleep(0.3)
    return out


def slim(r):
    """대시보드용 경량화"""
    thumbs = []
    full = ''
    for img in (r.get('images') or [])[:4]:
        t = img.get('thumbnail_url') or img.get('gallery_url') or img.get('url')
        if t:
            thumbs.append(t)
        if not full:
            full = img.get('gallery_url') or img.get('url') or ''
    return {
        'id': r.get('id'),
        'date': str(r.get('created_at') or '')[:10],
        'score': r.get('score'),
        'msg': str(r.get('message') or '')[:200],
        'prod': str(r.get('product_code') or ''),
        'type': r.get('review_type') or 'text',
        'thumbs': thumbs,
        'img': full,
        'user': str(r.get('user_name') or '')[:10],
        'cmts': r.get('comments_count') or 0,
        'disp': bool(r.get('display', True)),
    }


def main():
    app_id = os.environ.get('CREMA_APP_ID', '').strip()
    secret = os.environ.get('CREMA_SECRET', '').strip()
    pw = os.environ.get('IMWEB_DASH_PASSWORD', '').strip()
    if not app_id or not secret:
        print('크리마 미설정 (CREMA_APP_ID / CREMA_SECRET 없음) — 건너뜀')
        sys.exit(0)
    if not pw:
        print('IMWEB_DASH_PASSWORD 없음', file=sys.stderr)
        sys.exit(1)

    token = get_token(app_id, secret)
    today = datetime.date.today()

    # 기존 데이터 로드 (병합·영구 보존)
    prev = {}
    if os.path.exists(OUT):
        try:
            old = decrypt_json(open(OUT, encoding='utf-8').read(), pw)
            for x in old.get('reviews', []):
                prev[str(x['id'])] = x
            print(f'기존 리뷰 {len(prev)}건 로드')
        except Exception as e:
            print(f'기존 파일 로드 실패(신규 생성): {e}')

    # 수집 범위: 평시 최근 45일 / 최초엔 소급
    backfill = int(os.environ.get('CREMA_BACKFILL_DAYS') or 365) if not prev else CHUNK_DAYS
    fetched = 0
    end = today
    remaining = backfill
    while remaining > 0:
        span = min(CHUNK_DAYS, remaining)
        start = end - datetime.timedelta(days=span)
        rows = fetch_range(token, start, end)
        for r in rows:
            prev[str(r.get('id'))] = slim(r)
        fetched += len(rows)
        print(f'  {start} ~ {end}: {len(rows)}건')
        end = start - datetime.timedelta(days=1)
        remaining -= span + 1
        time.sleep(0.3)

    reviews = sorted(prev.values(), key=lambda x: (x.get('date') or '', x.get('id') or 0),
                     reverse=True)
    reviews = [r for r in reviews if r.get('disp', True)][:KEEP]

    out = {'updated': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'total': len(prev), 'reviews': reviews}
    os.makedirs('data', exist_ok=True)
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(encrypt_json(out, pw))
    print(f'저장 완료 — 이번 수집 {fetched}건 / 누적 {len(prev)}건 / 페이로드 {len(reviews)}건')


if __name__ == '__main__':
    main()
