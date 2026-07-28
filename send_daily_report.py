#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
선암파머스 · 광고 운영 일일 리포트 메일
=======================================
매일 아침 (수집 완료 후) 실행:
  data/meta.json (메타 성과·예산·변경이력)
  data/ga4_daily.json.enc (실측 매출 — IMWEB_DASH_PASSWORD로 복호화)
  data/imweb_dash.json.enc (자사몰 주문·VOC)
  data/crema_reviews.json.enc (저평점 후기)
를 읽어 §3 확정 규칙(기여이익 기반)으로 판정하고 투두가 담긴 리포트를 발송.

환경변수 (GitHub Secrets)
  MAIL_APP_PASSWORD    Gmail 앱 비밀번호 (16자리)
  IMWEB_DASH_PASSWORD  대시보드 비밀번호 (복호화 키)
  MAIL_USER            (선택) 발신 계정. 기본 official@sunamfarmers.kr
  REPORT_TO            (선택) 수신 주소. 기본 = MAIL_USER
"""
import base64
import datetime
import json
import os
import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KST = datetime.timezone(datetime.timedelta(hours=9))

# ── §3 마진 매핑 (index.html의 MARGIN_RULES와 동일하게 유지) ──
import re
MARGIN_RULES = [
    (re.compile(r'할인|B급|못난이|흠집', re.I), 0.07, '할인 생과 7%'),
    (re.compile(r'애사비|비니거|vinegar|식초', re.I), 0.698, '애사비 69.8%'),
    (re.compile(r'주스|착즙|사과즙|BIB|3L|20팩|50팩', re.I), 0.539, '착즙주스 53.9%'),
    (re.compile(r'애플티|애플\s?칩|잼', re.I), 0.52, '가공 52%'),
]
MARGIN_DEFAULT = (0.50, '기본 50%')
LEAD_RE = re.compile(r'사업자|트래픽|traffic|B2B|리드|lead|조회|인지|도달|reach|awareness', re.I)


def margin_of(name):
    for rx, m, label in MARGIN_RULES:
        if rx.search(name or ''):
            return m, label
    return MARGIN_DEFAULT


def decrypt_json(raw, pw):
    o = json.loads(raw)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=base64.b64decode(o['salt']), iterations=int(o['iter']))
    key = kdf.derive(pw.encode('utf-8'))
    pt = AESGCM(key).decrypt(base64.b64decode(o['iv']), base64.b64decode(o['ct']), None)
    return json.loads(pt.decode('utf-8'))


def load_enc(path, pw):
    try:
        return decrypt_json(open(path, encoding='utf-8').read(), pw)
    except Exception as e:
        print(f'! {path} 로드 실패: {e}')
        return None


def won(v):
    try:
        return '₩{:,}'.format(int(round(v)))
    except Exception:
        return '—'


def srange(rows, d1, d2, name=None, key='campaign'):
    o = {'cost': 0, 'rev': 0, 'imp': 0, 'clk': 0, 'conv': 0}
    for r in rows:
        d = r.get('date', '')
        if not (d1 <= d <= d2):
            continue
        if name is not None and (r.get(key) or '') != name:
            continue
        o['cost'] += r.get('cost', 0); o['rev'] += r.get('rev', 0)
        o['imp'] += r.get('imp', 0); o['clk'] += r.get('clk', 0); o['conv'] += r.get('conv', 0)
    o['ctr'] = o['clk'] / o['imp'] * 100 if o['imp'] else 0
    o['roas'] = o['rev'] / o['cost'] * 100 if o['cost'] else 0
    return o


def main():
    pw = os.environ.get('IMWEB_DASH_PASSWORD', '').strip()
    app_pw = os.environ.get('MAIL_APP_PASSWORD', '').strip()
    user = os.environ.get('MAIL_USER', 'official@sunamfarmers.kr').strip()
    to = os.environ.get('REPORT_TO', user).strip()
    if not app_pw:
        sys.exit('MAIL_APP_PASSWORD 미설정')

    # ── 데이터 로드 ──
    try:
        meta = json.load(open('data/meta.json', encoding='utf-8'))
    except Exception as e:
        sys.exit(f'data/meta.json 로드 실패: {e}')
    ga4 = load_enc('data/ga4_daily.json.enc', pw) if pw else None
    dash = load_enc('data/imweb_dash.json.enc', pw) if pw else None
    crema = load_enc('data/crema_reviews.json.enc', pw) if pw else None

    rows = meta.get('daily', [])
    if not rows:
        sys.exit('메타 일별 데이터 없음')
    anchor = max(r['date'] for r in rows if r.get('date'))          # 데이터 기준 최신일(보통 어제)
    A = datetime.date.fromisoformat(anchor)
    d7, d8, d13 = str(A - datetime.timedelta(days=6)), str(A - datetime.timedelta(days=7)), str(A - datetime.timedelta(days=13))
    d30 = str(A - datetime.timedelta(days=29))

    budgets = {b['campaign']: b for b in meta.get('budgets', [])}
    bhist = meta.get('budgetHistory', [])

    # GA4 일별 유료 매출 (실측)
    ga_day = {}
    if ga4 and ga4.get('daily'):
        for r in ga4['daily']:
            ga_day[r['date']] = max(0, (r.get('rev', 0) or 0) - (r.get('orgRev', 0) or 0))
    ga_camp7 = {}
    if ga4 and ga4.get('campaigns'):
        for x in (ga4['campaigns'].get('7') or []):
            ga_camp7[x['name']] = x

    def ga_sum(a, b):
        return sum(v for d, v in ga_day.items() if a <= d <= b) if ga_day else None

    # ── 캠페인 판정 (§3) ──
    camps = sorted({r.get('campaign') for r in rows if r.get('campaign')})
    verdicts = []
    for nm in camps:
        c7 = srange(rows, d7, anchor, nm)
        p7 = srange(rows, d13, d8, nm)
        if c7['cost'] == 0 and c7['imp'] == 0:
            continue                                          # 이번 주 미집행
        m, mlabel = margin_of(nm)
        contrib = round(c7['rev'] * m - c7['cost'])
        p_contrib = round(p7['rev'] * m - p7['cost'])
        be, tgt = 100 / m, 200 / m
        first = min((r['date'] for r in rows if r.get('campaign') == nm and r.get('date')), default=None)
        days = (A - datetime.date.fromisoformat(first)).days + 1 if first else None
        recent_bc = [h for h in bhist if h.get('campaign') == nm and h.get('date', '') >= d8]
        v = None
        if LEAD_RE.search(nm):
            v = ('리드', f'ROAS 판정 금지 — CPL·신청수로 평가 (7일 지출 {won(c7["cost"])})')
        elif days is not None and days <= 3:
            v = ('관찰', '게시 3일 이내 신규')
        elif c7['cost'] < 30000 and c7['imp'] < 3000:
            v = ('관찰', '최소 표본 미달')
        elif c7['cost'] >= 50000 and contrib < 0:
            v = ('끄기', f'확정 손실 — 7일 기여이익 {won(contrib)} ({mlabel})')
        elif c7['ctr'] >= 3 and c7['clk'] >= 100 and c7['conv'] == 0:
            v = ('랜딩점검', '클릭 좋은데 전환 0 — 랜딩·가격·재고 점검')
        elif recent_bc:
            h = recent_bc[-1]
            v = ('관찰', f'예산 변경({h["date"][5:]} {won(h["from"])}→{won(h["to"])}) 후 3일 보호')
        elif c7['roas'] >= tgt * 1.5 and (p7['cost'] == 0 or p7['roas'] >= tgt * 1.5):
            v = ('증액', f'목표×1.5 지속 — 기여이익 {won(contrib)} · +10~20%만')
        elif be <= c7['roas'] < tgt and contrib < p_contrib:
            v = ('감액', f'본전~목표 & 하락 (기여이익 {won(p_contrib)}→{won(contrib)})')
        elif contrib < 0:
            v = ('주의', f'기여이익 {won(contrib)} 마이너스 (지출 5만 미만 — 늘리지 말 것)')
        else:
            v = ('유지', f'기여이익 {won(contrib)}')
        g = ga_camp7.get(nm)
        verdicts.append({'name': nm, 'tag': v[0], 'why': v[1], 'c7': c7, 'contrib': contrib,
                         'margin_label': mlabel, 'be': be,
                         'ga_rev7': (g or {}).get('rev'), 'days': days})

    # 투두: 손실 차단 > 조정 > 증액, |기여이익| 큰 순, 최대 2건
    prio = {'끄기': 0, '랜딩점검': 1, '교체': 2, '감액': 3, '증액': 4}
    todos = sorted([v for v in verdicts if v['tag'] in prio],
                   key=lambda v: (prio[v['tag']], -abs(v['contrib'])))[:2]

    # ── 합계 ──
    t_y = srange(rows, anchor, anchor)
    t_7 = srange(rows, d7, anchor)
    t_p7 = srange(rows, d13, d8)
    t_30 = srange(rows, d30, anchor)

    def contrib_total(a, b):
        s = 0
        for nm in camps:
            c = srange(rows, a, b, nm)
            m, _ = margin_of(nm)
            s += c['rev'] * m - c['cost']
        return round(s)
    ct_y, ct_7, ct_p7, ct_30 = (contrib_total(anchor, anchor), contrib_total(d7, anchor),
                                contrib_total(d13, d8), contrib_total(d30, anchor))
    ga_y, ga_7, ga_30 = ga_sum(anchor, anchor), ga_sum(d7, anchor), ga_sum(d30, anchor)

    # 어제 자사몰 주문
    ord_y = None
    if dash and dash.get('daily'):
        for r in dash['daily']:
            if r.get('date') == anchor:
                ord_y = (r.get('jasaOrd') or 0) + (r.get('bizOrd') or 0)

    # 잘한 것 / 못한 것 / 괴리
    scored = [v for v in verdicts if v['tag'] not in ('리드',) and v['c7']['cost'] > 0]
    best = max(scored, key=lambda v: v['contrib'], default=None)
    worst = min(scored, key=lambda v: v['contrib'], default=None)
    gap = None
    for v in scored:
        if v['ga_rev7'] is not None and v['c7']['rev'] > 0 and v['ga_rev7'] > 0:
            ratio = v['c7']['rev'] / max(1, v['ga_rev7'])
            if ratio >= 3 and (gap is None or ratio > gap[1]):
                gap = (v, ratio)

    # 경보
    alerts = []
    if dash and dash.get('voc'):
        wc = dash['voc'].get('waitCount', 0)
        alerts.append(('미답변 문의 0건 OK' if not wc else f'미답변 문의 {wc}건 — 답변 필요', bool(wc)))
    if crema and crema.get('reviews'):
        low7 = sum(1 for r in crema['reviews']
                   if r.get('date', '') >= d7 and r.get('score') is not None and r['score'] <= 3)
        alerts.append((f'7일 저평점 후기 {low7}건' + ('' if low7 else ' OK'), low7 > 0))
    lead_names = [v['name'] for v in verdicts if v['tag'] == '리드']
    if lead_names:
        alerts.append(('리드 캠페인 신청수 미측정 — CPL 판정 불가 지속', True))

    # ── 리포트 조립 (HTML) ──
    def pct(v):
        return f'{v:.0f}%' if v is not None else '—'
    tag_color = {'끄기': '#b91c3c', '랜딩점검': '#7c3aed', '감액': '#92400e', '증액': '#027a38',
                 '교체': '#92400e', '관찰': '#5f5e5a', '유지': '#1d4ed8', '주의': '#92400e', '리드': '#1d4ed8'}

    def badge(tag):
        return (f'<span style="background:{tag_color.get(tag,"#555")};color:#fff;border-radius:8px;'
                f'padding:1px 8px;font-size:12px;font-weight:700">{tag}</span>')

    # ① 진행 중 광고
    rows1 = ''
    for v in sorted(verdicts, key=lambda x: -x['c7']['cost']):
        b = budgets.get(v['name'], {})
        bud = b.get('budget')
        y = srange(rows, anchor, anchor, v['name'])
        burn = f'{y["cost"]/bud*100:.0f}%' if bud else '—'
        bc = [h for h in bhist if h.get('campaign') == v['name']]
        bctxt = f'{bc[-1]["date"][5:]} {"↑" if bc[-1]["to"]>bc[-1]["from"] else "↓"}' if bc else '—'
        rows1 += (f'<tr><td style="text-align:left;padding:4px 8px">{v["name"][:26]}</td>'
                  f'<td>{won(bud) if bud else "—"}</td><td>{burn}</td><td>{bctxt}</td>'
                  f'<td>{badge(v["tag"])}</td></tr>')
    sec1 = (f'<h3 style="margin:18px 0 6px">① 진행 중인 광고 ({anchor} 기준)</h3>'
            f'<table style="border-collapse:collapse;font-size:13px;width:100%" border="0">'
            f'<tr style="color:#888"><td style="text-align:left;padding:4px 8px">캠페인</td>'
            f'<td>일예산</td><td>어제 소진율</td><td>최근 변경</td><td>판정</td></tr>{rows1}</table>')

    sec2 = (f'<h3 style="margin:18px 0 6px">② 어제 성과 ({anchor})</h3>'
            f'<div style="font-size:13.5px">지출 {won(t_y["cost"])} · 메타매출 {won(t_y["rev"])}'
            f' / 실측 {won(ga_y) if ga_y is not None else "—"}'
            f' · <b>기여이익 {"+" if ct_y>=0 else ""}{won(ct_y)}</b>'
            f'{f" · 주문 {ord_y}건" if ord_y is not None else ""}</div>')

    def hl(v, label, color):
        if not v:
            return ''
        g = f' / 실측 {won(v["ga_rev7"])}' if v['ga_rev7'] is not None else ''
        return (f'<div style="margin:3px 0"><b style="color:{color}">{label}</b> {v["name"][:28]} — '
                f'메타 ROAS {pct(v["c7"]["roas"])}{g} · 기여이익 {"+" if v["contrib"]>=0 else ""}{won(v["contrib"])} ({v["margin_label"]})</div>')
    gap_html = ''
    if gap:
        v, ratio = gap
        gap_html = (f'<div style="margin:3px 0"><b style="color:#92400e">괴리 주의</b> {v["name"][:28]} — '
                    f'메타매출 {won(v["c7"]["rev"])} vs 실측 {won(v["ga_rev7"])} ({ratio:.0f}배) · 메타만 보면 속는 구간</div>')
    d7_delta = f' (직전 7일 {"+" if ct_p7>=0 else ""}{won(ct_p7)})'
    sec3 = (f'<h3 style="margin:18px 0 6px">③ 최근 7일</h3>'
            f'<div style="font-size:13.5px">지출 {won(t_7["cost"])} · 메타매출 {won(t_7["rev"])}'
            f' / 실측 {won(ga_7) if ga_7 is not None else "—"}'
            f' · <b>기여이익 {"+" if ct_7>=0 else ""}{won(ct_7)}</b>{d7_delta}</div>'
            + hl(best, '잘한 것 🏆', '#027a38') + hl(worst, '못한 것 ⚠', '#b91c3c') + gap_html)

    ga_roas30 = (ga_30 / t_30['cost'] * 100) if (ga_30 is not None and t_30['cost']) else None
    sec4 = (f'<h3 style="margin:18px 0 6px">④ 최근 30일</h3>'
            f'<div style="font-size:13.5px">지출 {won(t_30["cost"])} · 메타매출 {won(t_30["rev"])}'
            f' / 실측 {won(ga_30) if ga_30 is not None else "—"}'
            f' · 기여이익 {"+" if ct_30>=0 else ""}{won(ct_30)}'
            f'{f" · 실측 ROAS {pct(ga_roas30)}" if ga_roas30 is not None else ""}</div>')

    obs = [v for v in verdicts if v['tag'] == '관찰']
    sec5 = ('<h3 style="margin:18px 0 6px">⑤ 관찰 중</h3><div style="font-size:13px;color:#555">'
            + ('<br>'.join(f'· {v["name"][:28]} — {v["why"]}' for v in obs) if obs else '없음') + '</div>')

    sec6 = ('<h3 style="margin:18px 0 6px">⑥ 경보</h3><div style="font-size:13px">'
            + ('<br>'.join(('<span style="color:#b91c3c">⚠ ' if bad else '<span style="color:#027a38">✓ ')
                           + txt + '</span>' for txt, bad in alerts) if alerts else '—') + '</div>')

    todo_html = ''
    for i, v in enumerate(todos, 1):
        todo_html += (f'<div style="border:1px solid #e5e5e5;border-left:4px solid {tag_color.get(v["tag"],"#555")};'
                      f'border-radius:8px;padding:10px 14px;margin:8px 0">'
                      f'<b>{i}. {badge(v["tag"])} {v["name"][:30]}</b>'
                      f'<div style="font-size:13px;margin-top:4px">팩트: 7일 지출 {won(v["c7"]["cost"])} · 메타매출 {won(v["c7"]["rev"])}'
                      + (f' / 실측 {won(v["ga_rev7"])}' if v.get('ga_rev7') is not None else '')
                      + f' · {v["margin_label"]} → 기여이익 <b>{"+" if v["contrib"]>=0 else ""}{won(v["contrib"])}</b></div>'
                      f'<div style="font-size:13px">권장: {v["why"]}</div></div>')
    sec7 = ('<h3 style="margin:18px 0 6px">⑦ 오늘의 투두 (가드레일: 최대 2건)</h3>'
            + (todo_html or '<div style="font-size:13px;color:#555">오늘은 조치 권고 없음 — 유지</div>'))

    today = datetime.datetime.now(KST).strftime('%-m/%-d')
    subject = f'[선암 광고] {today} 일일 리포트 — 7일 기여이익 {"+" if ct_7>=0 else ""}{won(ct_7)} · 투두 {len(todos)}건'
    html = (f'<div style="font-family:-apple-system,\'Apple SD Gothic Neo\',\'Malgun Gothic\',sans-serif;'
            f'max-width:680px;margin:0 auto;color:#222">'
            f'<h2 style="margin:6px 0">선암파머스 광고 일일 리포트 <span style="font-size:13px;color:#888;font-weight:400">{anchor} 데이터 기준</span></h2>'
            + sec1 + sec2 + sec3 + sec4 + sec5 + sec6
            + '<hr style="border:none;border-top:1px solid #ddd;margin:18px 0">'
            + sec7
            + '<div style="font-size:11.5px;color:#999;margin-top:16px">판정 규칙: 기여이익=매출×마진율−지출 · 본전 ROAS=100÷마진율 · '
              '실측=GA4 클릭 유입 결제(취소 미반영) · 대시보드: tennout.github.io/sunam-ad-dashboard</div></div>')

    # ── 발송 ──
    msg = MIMEMultipart('alternative')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = user
    msg['To'] = to
    msg.attach(MIMEText('HTML 메일을 지원하는 클라이언트에서 확인하세요.', 'plain', 'utf-8'))
    msg.attach(MIMEText(html, 'html', 'utf-8'))
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=30) as s:
        s.login(user, app_pw)
        s.sendmail(user, [to], msg.as_string())
    print(f'발송 완료 → {to} / {subject}')


if __name__ == '__main__':
    main()
