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
        if not isinstance(img, dict):
            continue
        t = img.get('thumbnail_url') or img.get('gallery_url') or img.get('url')
        if t:
            thumbs.append(t)
        if not full:
            full = img.get('gallery_url') or img.get('url') or ''
    # 대체 필드: image_urls (문자열 배열)
    if not thumbs:
        for u in (r.get('image_urls') or [])[:4]:
            if isinstance(u, str) and u:
                thumbs.append(u)
                if not full:
                    full = u
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


WIDGET_API = 'https://review5.cre.ma/api/sunamfarmers.kr/reviews'
WIDGET_ID = 23   # 자사몰 메인 갤러리(포토 리뷰) 위젯
WIDGET_HDR = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
              'Referer': 'https://sunamfarmers.kr/'}


def fetch_widget_photos():
    """자사몰 크리마 위젯 공개 API — 포토 리뷰의 이미지 URL + 상품명 확보
    (공식 API가 이미지 필드를 제공하지 않는 문제의 우회로)"""
    photos, names = {}, {}
    page = 1
    while page <= 40:
        try:
            r = requests.get(WIDGET_API, params={'widget_id': WIDGET_ID, 'page': page},
                             headers=WIDGET_HDR, timeout=30)
            j = r.json() if r.ok else {}
        except Exception as e:
            print(f'위젯 조회 실패(p{page}): {e}')
            break
        rows = j.get('reviews') or []
        if not rows:
            break
        for x in rows:
            rid = str(x.get('id'))
            thumbs, full = [], ''
            for img in (x.get('images') or [])[:4]:
                if not isinstance(img, dict):
                    continue
                t = img.get('thumbnail_url') or img.get('gallery_url') or img.get('url')
                if t:
                    thumbs.append(t)
                if not full:
                    full = img.get('gallery_url') or img.get('url') or ''
            if thumbs:
                photos[rid] = {'thumbs': thumbs, 'img': full}
            pc = str(x.get('product_code') or '')
            pn = x.get('product_name') or ''
            if pc and pn:
                names[pc] = str(pn)[:40]
        pagy = j.get('pagy') or {}
        try:
            if pagy.get('page') and pagy.get('last') and int(pagy['page']) >= int(pagy['last']):
                break
        except Exception:
            pass
        page += 1
        time.sleep(0.4)
    return photos, names


def fetch_product_names(token):
    """크리마 Product API — product_code → 상품명 매핑"""
    names = {}
    page = 1
    while page <= 30:
        try:
            r = requests.get(f'{API}/v1/products',
                             params={'access_token': token, 'limit': 100, 'page': page},
                             timeout=60)
            rows = r.json() if r.ok else []
        except Exception:
            break
        if not isinstance(rows, list) or not rows:
            break
        for x in rows:
            code = str(x.get('code') or '')
            nm = x.get('name') or ''
            if code and nm:
                names[code] = str(nm)[:40]
        if len(rows) < 100:
            break
        page += 1
        time.sleep(0.3)
    return names


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

    # 진단: 포토 리뷰 직접 조회 (photo=1) — 크리마 문의용 증거 로그
    try:
        pr = requests.get(f'{API}/v1/reviews', params={
            'access_token': token, 'limit': 5, 'photo': 1,
            'start_date': (today - datetime.timedelta(days=44)).isoformat(),
            'end_date': today.isoformat(), 'date_order_desc': 1}, timeout=30)
        pj = pr.json() if pr.ok else None
        if isinstance(pj, list):
            print(f'[진단] photo=1 조회: {len(pj)}건')
            if pj:
                print(f'[진단] 목록 응답 전체 키: {sorted(pj[0].keys())}')
            for x in pj[:3]:
                print(f"[진단]  id={x.get('id')} date={str(x.get('created_at'))[:10]} "
                      f"type={x.get('review_type')} images_count={x.get('images_count')} "
                      f"images={len(x.get('images') or [])}")
        else:
            print(f'[진단] photo=1 조회 실패: HTTP {pr.status_code} {str(pr.text)[:200]}')
    except Exception as e:
        print(f'[진단] photo=1 조회 예외: {e}')

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

    # 포토 리뷰 표시: photo=1로 포토 id 마킹
    widget_names = {}
    try:
        photo_ids = []
        end2, rem2 = today, 365
        while rem2 > 0:
            span2 = min(CHUNK_DAYS, rem2)
            st2 = end2 - datetime.timedelta(days=span2)
            page = 1
            while page <= 30:
                r2 = requests.get(f'{API}/v1/reviews', params={
                    'access_token': token, 'limit': 100, 'page': page, 'photo': 1,
                    'start_date': st2.isoformat(), 'end_date': end2.isoformat()}, timeout=60)
                rows2 = r2.json() if r2.ok else []
                if not isinstance(rows2, list) or not rows2:
                    break
                photo_ids += [str(x.get('id')) for x in rows2 if x.get('id') is not None]
                if len(rows2) < 100:
                    break
                page += 1
                time.sleep(0.3)
            end2 = st2 - datetime.timedelta(days=1)
            rem2 -= span2 + 1
            time.sleep(0.2)
        for p in photo_ids:
            if p in prev and prev[p].get('type') == 'text':
                prev[p]['type'] = 'photo'
        print(f'포토 리뷰 {len(photo_ids)}건 마킹')

        # 자사몰 위젯 공개 API에서 이미지 URL + 상품명 병합
        widget_photos, widget_names = fetch_widget_photos()
        merged = 0
        for rid, ph in widget_photos.items():
            if rid in prev:
                prev[rid]['thumbs'] = ph['thumbs']
                prev[rid]['img'] = ph['img']
                if prev[rid].get('type') == 'text':
                    prev[rid]['type'] = 'photo'
                merged += 1
        print(f'위젯 이미지 병합: 포토 {len(widget_photos)}건 중 {merged}건 매칭 / 상품명 {len(widget_names)}건')
    except Exception as e:
        print(f'포토 보강 실패: {e}')

    reviews = sorted(prev.values(), key=lambda x: (x.get('date') or '', x.get('id') or 0),
                     reverse=True)
    reviews = [r for r in reviews if r.get('disp', True)][:KEEP]

    prod_names = dict(fetch_product_names(token))
    for k, v in widget_names.items():
        prod_names.setdefault(k, v)
    print(f'크리마 상품명 {len(prod_names)}건 (위젯 {len(widget_names)}건 포함)')

    out = {'updated': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'total': len(prev), 'reviews': reviews, 'prodNames': prod_names}
    os.makedirs('data', exist_ok=True)
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(encrypt_json(out, pw))
    print(f'저장 완료 — 이번 수집 {fetched}건 / 누적 {len(prev)}건 / 페이로드 {len(reviews)}건')


if __name__ == '__main__':
    main()
