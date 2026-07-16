# -*- coding: utf-8 -*-
"""
선암파머스 아임웹(자사몰·비즈몰) 데이터 수집 → 암호화 JSON 생성
- GitHub Actions에서 매일 실행 (fetch_naver_ads.py와 동일 패턴)
- 필요 환경변수(GitHub Secrets):
    IMWEB_JASA_KEY / IMWEB_JASA_SECRET   자사몰 API 키
    IMWEB_BIZ_KEY  / IMWEB_BIZ_SECRET    비즈몰 API 키
    IMWEB_DASH_PASSWORD                  대시보드 비밀번호 (복호화 키, 예: sunam2026!!)
- 출력:
    data/imweb_store.json.enc  누적 저장소 (증분 수집·회원 추이 히스토리)
    data/imweb_dash.json.enc   대시보드 페이로드
설치: pip install requests cryptography
"""
import os, json, time, base64, datetime, sys
import requests
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KST = datetime.timezone(datetime.timedelta(hours=9))
MAIN = '자사몰'
SITES = [
    {'name': '자사몰', 'key': os.environ.get('IMWEB_JASA_KEY', ''), 'secret': os.environ.get('IMWEB_JASA_SECRET', '')},
    {'name': '비즈몰', 'key': os.environ.get('IMWEB_BIZ_KEY', ''), 'secret': os.environ.get('IMWEB_BIZ_SECRET', '')},
]
PASSWORD = os.environ.get('IMWEB_DASH_PASSWORD', '')
STORE_PATH = 'data/imweb_store.json.enc'
DASH_PATH = 'data/imweb_dash.json.enc'
BACKFILL_DAYS_FIRST = 200   # 최초 실행 시 주문 소급 일수
BACKFILL_DAYS_DAILY = 7     # 평시 재수집 일수 (상태 변경 반영)
PROD_BUDGET = 1200          # 실행당 품목 수집 주문 수
FEES = {'card': 0.029, 'npay': 0.037, 'kakaopay': 0.032, 'toss': 0.03,
        'iche': 0.017, 'virtual': 0.005, 'cash': 0.0, 'etc': 0.03}
KDF_ITER = 150000

# ---------------- 암호화 ----------------
def _derive(pw: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITER)
    return kdf.derive(pw.encode('utf-8'))

def encrypt_json(obj, pw):
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = _derive(pw, salt)
    ct = AESGCM(key).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode('utf-8'), None)
    return json.dumps({'v': 1, 'kdf': 'PBKDF2-SHA256', 'iter': KDF_ITER,
                       'salt': base64.b64encode(salt).decode(),
                       'iv': base64.b64encode(iv).decode(),
                       'ct': base64.b64encode(ct).decode()})

def decrypt_json(raw, pw):
    o = json.loads(raw)
    key = _derive(pw, base64.b64decode(o['salt']))
    pt = AESGCM(key).decrypt(base64.b64decode(o['iv']), base64.b64decode(o['ct']), None)
    return json.loads(pt.decode('utf-8'))

# ---------------- 아임웹 API ----------------
def get_token(site):
    r = requests.get('https://api.imweb.me/v2/auth',
                     params={'key': site['key'], 'secret': site['secret']}, timeout=30).json()
    if not r.get('access_token'):
        raise RuntimeError(f"{site['name']} 토큰 발급 실패: {r}")
    return r['access_token']

def api_get(url, token, params=None):
    for _ in range(5):
        try:
            r = requests.get(url, params=params or {}, headers={'access-token': token}, timeout=30).json()
        except Exception:
            time.sleep(2); continue
        if isinstance(r, dict) and r.get('code') == -7:  # TOO MANY REQUEST
            time.sleep(2); continue
        return r
    return None

def paged(url, token, base_params=None, max_page=300):
    """offset 페이지네이션 공통 루프"""
    out, total_page, p = [], 1, 1
    while p <= total_page and p <= max_page:
        params = dict(base_params or {})
        params.update({'offset': p, 'limit': 100})
        res = api_get(url, token, params)
        data = (res or {}).get('data') or {}
        lst = data.get('list') or []
        pag = data.get('pagenation') or {}
        if pag:
            total_page = int(pag.get('total_page') or total_page)
            if int(pag.get('current_page') or p) != p:
                break
        if not lst:
            break
        out.extend(lst)
        p += 1
        time.sleep(1.1)
    return out

def dstr(ts):
    if not ts:
        return ''
    return datetime.datetime.fromtimestamp(int(ts), KST).strftime('%Y-%m-%d')

def fetch_orders(site, token, from_ts, to_ts):
    rows = {}
    chunk = 7 * 86400
    start = from_ts
    while start < to_ts:
        end = min(start + chunk, to_ts)
        lst = paged('https://api.imweb.me/v2/shop/orders', token,
                    {'order_date_from': start, 'order_date_to': end}, max_page=30)
        for o in lst:
            if not o or not o.get('order_no'):
                continue
            p = o.get('payment') or {}
            orderer = o.get('orderer') or {}
            rows[str(o['order_no'])] = {
                'no': str(o['order_no']), 'site': site['name'],
                'date': dstr(o.get('order_time')), 'status': o.get('status') or '',
                'pay': p.get('pay_type') or '', 'device': (o.get('device') or {}).get('type') or '',
                'total': float(p.get('total_price') or 0), 'amount': float(p.get('payment_amount') or 0),
                'deliv': float(p.get('deliv_price') or 0), 'coupon': float(p.get('coupon') or 0),
                'point': float(p.get('point') or 0), 'name': orderer.get('name') or '',
                'member': orderer.get('member_code') or ''}
        start += chunk
    return rows

def fetch_members(site, token):
    out = {}
    for m in paged('https://api.imweb.me/v2/member/members', token, {'orderBy': 'jointime'}):
        code = m.get('member_code')
        if not code:
            continue
        jt = m.get('join_time')
        if isinstance(jt, (int, float)) or (isinstance(jt, str) and jt.isdigit()):
            jd = dstr(int(jt))
        else:
            jd = str(jt or '')[:10].replace('.', '-')
        out[str(code)] = {'code': str(code), 'site': site['name'], 'join': jd,
                          'grade': m.get('member_grade') or ''}
    return out

def fetch_voc(site, token):
    reviews = []
    for r in paged('https://api.imweb.me/v2/shop/reviews', token, max_page=100):
        reviews.append({'idx': str(r.get('idx') or ''), 'site': site['name'],
                        'date': dstr(r.get('wtime')), 'rating': int(r.get('rating') or 0),
                        'prod': str(r.get('prod_no') or ''), 'nick': r.get('nick') or '',
                        'body': (r.get('body') or '')[:500], 'photo': 'Y' if r.get('is_photo') else 'N'})
    qnas = []
    for q in paged('https://api.imweb.me/v2/shop/inquirys', token, max_page=100):
        qnas.append({'idx': str(q.get('idx') or ''), 'site': site['name'],
                     'date': dstr(q.get('wtime')), 'status': q.get('status') or '',
                     'prod': str(q.get('prod_no') or ''), 'nick': q.get('nick') or '',
                     'subject': (q.get('subject') or '')[:200], 'body': (q.get('body') or '')[:500]})
    return reviews, qnas

def parse_prod_container(container, ono, site_name, date, rows):
    if not isinstance(container, dict):
        return
    for rec in container.values():
        items = (rec or {}).get('items') or []
        if not isinstance(items, list):
            continue
        for it in items:
            if not it:
                continue
            pay = it.get('payment') or {}
            rows.append({'no': str(ono), 'site': site_name, 'date': date,
                         'prod': str(it.get('prod_no') or ''), 'name': it.get('prod_name') or '',
                         'qty': int(pay.get('count') or 0), 'rev': float(pay.get('price') or 0)})

def fetch_prods(site, token, order_map, done_set, budget):
    """미수집 주문의 품목 내역 수집 (배치 25건, 실패 시 개별 폴백)"""
    pend = [no for no, o in order_map.items()
            if o['site'] == site['name'] and no not in done_set
            and o['status'] not in ('CANCEL', 'RETURN', 'PAY_WAIT')]
    pend = pend[:budget]
    rows, done = [], []
    for i in range(0, len(pend), 25):
        batch = pend[i:i + 25]
        params = [('order_no[]', n) for n in batch]
        res = None
        for _ in range(3):
            try:
                res = requests.get('https://api.imweb.me/v2/shop/prod-orders', params=params,
                                   headers={'access-token': token}, timeout=30).json()
            except Exception:
                time.sleep(2); continue
            if isinstance(res, dict) and res.get('code') == -7:
                time.sleep(2); continue
            break
        data = (res or {}).get('data')
        got = False
        if isinstance(data, dict) and 'list' not in data:
            for ono, container in data.items():
                got = True
                parse_prod_container(container, ono, site['name'], order_map.get(str(ono), {}).get('date', ''), rows)
                done.append(str(ono))
        if not got:
            for no in batch:
                r2 = api_get(f'https://api.imweb.me/v2/shop/orders/{no}/prod-orders', token)
                d2 = (r2 or {}).get('data')
                if isinstance(d2, dict) and isinstance(d2.get('list'), list):
                    tmp = {f'L{k}': rec for k, rec in enumerate(d2['list'])}
                    parse_prod_container(tmp, no, site['name'], order_map.get(no, {}).get('date', ''), rows)
                elif isinstance(d2, dict):
                    parse_prod_container(d2, no, site['name'], order_map.get(no, {}).get('date', ''), rows)
                done.append(no)
                time.sleep(1.1)
        time.sleep(1.1)
    return rows, done

# ---------------- 집계 (대시보드 페이로드) ----------------
def build_dash(store):
    today = datetime.datetime.now(KST).date()
    d130 = (today - datetime.timedelta(days=130)).isoformat()
    d180 = (today - datetime.timedelta(days=180)).isoformat()

    orders = store['orders']            # no -> order
    members = store['members']          # code -> member
    prods = store['prods']              # list
    reviews = store['reviews']
    qnas = store['qnas']

    # 회원별 구매 이력 (사이트별)
    pur = {}
    for o in orders.values():
        if o['status'] in ('CANCEL', 'RETURN', 'PAY_WAIT') or not o['member']:
            continue
        pur.setdefault(o['site'], {}).setdefault(o['member'], []).append(
            {'date': o['date'], 'amt': o['amount']})
    for site_map in pur.values():
        for lst in site_map.values():
            lst.sort(key=lambda x: x['date'])

    # 멤버십 온보딩 셋 (자사몰 180일 실결제 10만+)
    tier = set()
    for code, lst in pur.get(MAIN, {}).items():
        if sum(p['amt'] for p in lst if p['date'] >= d180) >= 100000:
            tier.add(code)

    # 일별 집계
    daily = {}
    def drec(dt):
        return daily.setdefault(dt, {'date': dt, 'jasa': 0, 'biz': 0, 'jasaOrd': 0, 'bizOrd': 0,
            'jasaMemOrd': 0, 'bizMemOrd': 0, 'jasaTierOrd': 0,
            'jasaCouponOrd': 0, 'bizCouponOrd': 0, 'jasaPoint': 0, 'bizPoint': 0,
            'jasaPointOrd': 0, 'bizPointOrd': 0, 'jasaCancel': 0, 'bizCancel': 0,
            'jasaCoupon': 0, 'bizCoupon': 0, 'jasaSettle': 0, 'bizSettle': 0})
    for o in orders.values():
        if not o['date']:
            continue
        r = drec(o['date'])
        is_j = o['site'] == MAIN
        if o['status'] in ('CANCEL', 'RETURN'):
            r['jasaCancel' if is_j else 'bizCancel'] += 1
            continue
        if o['status'] == 'PAY_WAIT':
            continue
        rate = FEES.get(o['pay'], FEES['etc'])
        pfx = 'jasa' if is_j else 'biz'
        r[pfx] += o['amount']
        r[pfx + 'Ord'] += 1
        if o['member']:
            r[pfx + 'MemOrd'] += 1
        if is_j and o['member'] in tier:
            r['jasaTierOrd'] += 1
        if o['coupon'] > 0:
            r[pfx + 'CouponOrd'] += 1
        if o['point'] > 0:
            r[pfx + 'PointOrd'] += 1
            r[pfx + 'Point'] += o['point']
        r[pfx + 'Coupon'] += o['coupon']
        r[pfx + 'Settle'] += o['amount'] * (1 - rate)
    daily_arr = [daily[k] for k in sorted(daily)][-130:]
    for r in daily_arr:
        r['jasaSettle'] = round(r['jasaSettle'])
        r['bizSettle'] = round(r['bizSettle'])

    # 회원 (신규 가입 일별 + 누적)
    mem_daily, totals = {}, {'jasa': 0, 'biz': 0}
    for m in members.values():
        pfx = 'jasa' if m['site'] == MAIN else 'biz'
        totals[pfx] += 1
        if m['join']:
            mem_daily.setdefault(m['join'], {'date': m['join'], 'jasaNew': 0, 'bizNew': 0})[pfx + 'New'] += 1
    mem_arr = [mem_daily[k] for k in sorted(mem_daily)][-130:]

    # 재구매율 (첫구매 후 90일)
    def rebuy(site_name):
        f = r_ = 0
        for lst in pur.get(site_name, {}).values():
            if not lst:
                continue
            f += 1
            first = lst[0]['date']
            fd = datetime.date.fromisoformat(first)
            for p in lst[1:]:
                if p['date'] > first and (datetime.date.fromisoformat(p['date']) - fd).days <= 90:
                    r_ += 1
                    break
        return (r_ / f) if f else 0

    # 구매횟수 분포
    def dist(site_name):
        o = {'once': 0, 'twice': 0, 'three': 0}
        for lst in pur.get(site_name, {}).values():
            n = len(lst)
            if n == 1: o['once'] += 1
            elif n == 2: o['twice'] += 1
            elif n >= 3: o['three'] += 1
        return o

    # 등급 분포 (자사몰)
    grades = {}
    for m in members.values():
        if m['site'] != MAIN:
            continue
        g = m['grade'] or '미지정'
        grades[g] = grades.get(g, 0) + 1
    grade_arr = sorted([{'name': k, 'count': v} for k, v in grades.items()],
                       key=lambda x: -x['count'])

    # 가입 코호트 (자사몰)
    coh = {}
    for code, m in members.items():
        if m['site'] != MAIN or not m['join']:
            continue
        ym = m['join'][:7]
        c = coh.setdefault(ym, {'ym': ym, 'joiners': 0, 'buyers': 0, 'rebuy': 0})
        c['joiners'] += 1
        lst = [p['date'] for p in pur.get(MAIN, {}).get(code, []) if p['date'] >= m['join']]
        if not lst:
            continue
        first = lst[0]
        jd = datetime.date.fromisoformat(m['join'])
        if (datetime.date.fromisoformat(first) - jd).days <= 30:
            c['buyers'] += 1
            fd = datetime.date.fromisoformat(first)
            for p in lst[1:]:
                if (datetime.date.fromisoformat(p) - fd).days <= 90:
                    c['rebuy'] += 1
                    break
    coh_arr = [coh[k] for k in sorted(coh, reverse=True)[:6]]

    # 거래처 TOP (비즈몰)
    b2b = {}
    for o in orders.values():
        if o['site'] != '비즈몰' or o['status'] in ('CANCEL', 'RETURN', 'PAY_WAIT'):
            continue
        nm = o['name'] or '(미상)'
        b = b2b.setdefault(nm, {'name': nm, 'orders': 0, 'rev': 0, 'last': ''})
        b['orders'] += 1
        b['rev'] += o['amount']
        if o['date'] > b['last']:
            b['last'] = o['date']
    b2b_top = sorted(b2b.values(), key=lambda x: -x['rev'])[:10]

    # 상품별 일 판매 (130일)
    p_agg = {}
    for p in prods:
        if not p['date'] or p['date'] < d130:
            continue
        key = (p['date'], p['site'], p['name'])
        a = p_agg.setdefault(key, {'date': p['date'], 'site': p['site'], 'name': p['name'], 'qty': 0, 'rev': 0})
        a['qty'] += p['qty']
        a['rev'] += p['rev']
    prod_arr = list(p_agg.values())

    # VOC 요약
    d30 = (today - datetime.timedelta(days=30)).isoformat()
    rd, s30, c30, low30, lows = {}, 0, 0, 0, []
    for r in reviews:
        if not r['date']:
            continue
        rec = rd.setdefault(r['date'], {'date': r['date'], 'count': 0, 'sum': 0})
        rec['count'] += 1
        rec['sum'] += r['rating']
        if r['date'] >= d30:
            c30 += 1
            s30 += r['rating']
            if r['rating'] <= 3:
                low30 += 1
        if r['rating'] <= 3:
            lows.append({'date': r['date'], 'rating': r['rating'], 'site': r['site'],
                         'prod': r['prod'], 'body': r['body'][:120]})
    lows.sort(key=lambda x: x['date'], reverse=True)
    qs = sorted([{'date': q['date'], 'status': q['status'], 'site': q['site'],
                  'prod': q['prod'], 'subject': q['subject'][:80]} for q in qnas],
                key=lambda x: x['date'], reverse=True)
    voc = {'ratingDaily': [rd[k] for k in sorted(rd)][-130:],
           'avg30': (s30 / c30) if c30 else None, 'reviews30': c30, 'low30': low30,
           'lowRecent': lows[:5],
           'waitCount': sum(1 for q in qnas if q['status'] == 'WAIT'),
           'recentQna': qs[:5]}

    # CSV용 원본 리스트
    csv = {
        'orders': [[o['no'], o['site'], o['date'], o['status'], o['pay'], o['amount'],
                    o['coupon'], o['point'], o['name'], '회원' if o['member'] else '비회원']
                   for o in sorted(orders.values(), key=lambda x: x['date'], reverse=True)],
        'ordersHead': ['주문번호', '사이트', '주문일', '상태', '결제수단', '실결제', '쿠폰할인', '적립금사용', '주문자', '회원여부'],
        'members': [[m['code'], m['site'], m['join'], m['grade']] for m in members.values()],
        'membersHead': ['회원코드', '사이트', '가입일', '쇼핑등급'],
        'reviews': [[r['date'], r['site'], r['rating'], r['prod'], r['nick'], r['body']] for r in reviews],
        'reviewsHead': ['작성일', '사이트', '별점', '상품번호', '작성자', '내용'],
        'qnas': [[q['date'], q['site'], q['status'], q['prod'], q['nick'], q['subject'], q['body']] for q in qnas],
        'qnasHead': ['작성일', '사이트', '상태', '상품번호', '작성자', '제목', '내용'],
    }

    return {'updated': datetime.datetime.now(KST).isoformat(),
            'daily': daily_arr, 'prods': prod_arr,
            'members': {'totals': totals, 'daily': mem_arr},
            'rebuy': {'jasa': rebuy(MAIN), 'biz': rebuy('비즈몰')},
            'grades': grade_arr, 'b2bTop': b2b_top, 'cohorts': coh_arr,
            'dist': {'jasa': dist(MAIN), 'biz': dist('비즈몰')},
            'voc': voc, 'csv': csv}

# ---------------- 메인 ----------------
def main():
    if not PASSWORD:
        sys.exit('IMWEB_DASH_PASSWORD 미설정')
    os.makedirs('data', exist_ok=True)

    # 저장소 로드
    store = {'orders': {}, 'members': {}, 'prods': [], 'prodDone': [],
             'reviews': [], 'qnas': [], 'snapshots': []}
    if os.path.exists(STORE_PATH):
        try:
            store = decrypt_json(open(STORE_PATH, encoding='utf-8').read(), PASSWORD)
        except Exception as e:
            print('저장소 복호화 실패 → 새로 시작:', e)

    now = int(time.time())
    first_run = not store['orders']
    back_days = BACKFILL_DAYS_FIRST if first_run else BACKFILL_DAYS_DAILY

    all_members = {}
    all_reviews, all_qnas = [], []
    done_set = set(store.get('prodDone', []))

    for site in SITES:
        token = get_token(site)
        print(site['name'], '주문 수집...')
        orders = fetch_orders(site, token, now - back_days * 86400, now)
        store['orders'].update(orders)
        print(site['name'], f'주문 {len(orders)}건 갱신')

        print(site['name'], '회원 수집...')
        all_members.update(fetch_members(site, token))

        print(site['name'], 'VOC 수집...')
        rv, qn = fetch_voc(site, token)
        all_reviews.extend(rv)
        all_qnas.extend(qn)

        print(site['name'], '품목 수집...')
        rows, done = fetch_prods(site, token, store['orders'], done_set, PROD_BUDGET)
        store['prods'].extend(rows)
        done_set.update(done)
        print(site['name'], f'품목 {len(rows)}행 추가')

    # 병합 보존: 아임웹에서 삭제(탈퇴·후기삭제)돼도 과거 기록 유지
    merged_members = dict(store.get('members', {}))
    merged_members.update(all_members)
    store['members'] = merged_members
    def _merge_by_idx(old_list, new_list):
        m = {(r.get('site',''), r.get('idx','')): r for r in (old_list or [])}
        for r in new_list:
            m[(r.get('site',''), r.get('idx',''))] = r
        return list(m.values())
    store['reviews'] = _merge_by_idx(store.get('reviews'), all_reviews)
    store['qnas'] = _merge_by_idx(store.get('qnas'), all_qnas)
    store['prodDone'] = sorted(done_set)

    # 회원 스냅샷 (일별 누적)
    today = datetime.datetime.now(KST).date().isoformat()
    snap = {'date': today,
            'jasa': sum(1 for m in all_members.values() if m['site'] == MAIN),
            'biz': sum(1 for m in all_members.values() if m['site'] == '비즈몰')}
    store['snapshots'] = [s for s in store.get('snapshots', []) if s['date'] != today] + [snap]

    dash = build_dash(store)
    dash['snapshots'] = store['snapshots'][-130:]

    open(STORE_PATH, 'w', encoding='utf-8').write(encrypt_json(store, PASSWORD))
    open(DASH_PATH, 'w', encoding='utf-8').write(encrypt_json(dash, PASSWORD))
    print('완료:', STORE_PATH, DASH_PATH,
          '| 주문', len(store['orders']), '| 회원', len(all_members),
          '| 품목행', len(store['prods']), '| 후기', len(all_reviews), '| 문의', len(all_qnas))

if __name__ == '__main__':
    main()
