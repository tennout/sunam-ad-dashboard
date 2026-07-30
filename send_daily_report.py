#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
선암파머스 · 광고 운영 주간 리포트 메일
=======================================
매주 월요일 아침 실행. 구조:
  [로데이터부] 모든 수치에 출처 명기 (메타 귀속 / GA4 실측 / 아임웹)
  [의견부]    §3 규칙 기반 자동 판정 — 검토 제안일 뿐, 실행 판단은 운영자 몫

환경변수 (GitHub Secrets)
  MAIL_APP_PASSWORD    Gmail 앱 비밀번호
  IMWEB_DASH_PASSWORD  대시보드 비밀번호 (복호화 키)
  MAIL_USER / REPORT_TO
"""
import base64
import datetime
import json
import os
import re
import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KST = datetime.timezone(datetime.timedelta(hours=9))

# ── §3 마진 매핑 (index.html MARGIN_RULES와 동일 유지) ──
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
    anchor = max(r['date'] for r in rows if r.get('date'))
    A = datetime.date.fromisoformat(anchor)
    d7 = str(A - datetime.timedelta(days=6))
    d8 = str(A - datetime.timedelta(days=7))
    d13 = str(A - datetime.timedelta(days=13))
    d30 = str(A - datetime.timedelta(days=29))

    budgets = {b['campaign']: b for b in meta.get('budgets', [])}
    bhist = meta.get('budgetHistory', [])

    # GA4 실측
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

    # ── §3 판정 (의견부용 — 로데이터에는 섞지 않음) ──
    camps = sorted({r.get('campaign') for r in rows if r.get('campaign')})
    ad_names = sorted({r.get('adname') for r in rows if r.get('adname')})
    ad_ctrs = sorted(s['ctr'] for s in (srange(rows, d7, anchor, n, 'adname') for n in ad_names) if s['imp'] > 0)
    ctr_med = ad_ctrs[len(ad_ctrs) // 2] if ad_ctrs else 1.0
    verdicts = []
    for nm in camps:
        c7 = srange(rows, d7, anchor, nm)
        p7 = srange(rows, d13, d8, nm)
        if c7['cost'] == 0 and c7['imp'] == 0:
            continue
        m, mlabel = margin_of(nm)
        contrib = round(c7['rev'] * m - c7['cost'])
        p_contrib = round(p7['rev'] * m - p7['cost'])
        be, tgt = 100 / m, 200 / m
        first = min((r['date'] for r in rows if r.get('campaign') == nm and r.get('date')), default=None)
        days = (A - datetime.date.fromisoformat(first)).days + 1 if first else None
        recent_bc = [h for h in bhist if h.get('campaign') == nm and h.get('date', '') >= d8]
        if LEAD_RE.search(nm):
            v = ('리드', f'ROAS 판정 대상 아님 — CPL·신청수 기준 (신청수 측정 필요) · 7일 지출 {won(c7["cost"])} (메타)')
        elif days is not None and days <= 3:
            v = ('관찰', '게시 3일 이내 신규 — 판정 보류')
        elif c7['cost'] < 30000 and c7['imp'] < 3000:
            v = ('관찰', '최소 표본(7일 지출 3만/노출 3천) 미달 — 판정 보류')
        elif c7['cost'] >= 50000 and contrib < 0:
            v = ('끄기 검토', f'7일 지출 {won(c7["cost"])}(메타) & 기여이익 {won(contrib)}(메타 매출 × {mlabel} 기준) 마이너스')
        elif c7['ctr'] >= 3 and c7['clk'] >= 100 and c7['conv'] == 0:
            v = ('랜딩 점검', f'CTR {c7["ctr"]:.1f}%·클릭 {c7["clk"]}회인데 전환 0 (메타) — 소재보다 랜딩·가격·재고 쪽 확인 필요')
        elif recent_bc:
            h = recent_bc[-1]
            v = ('관찰', f'예산 변경({h["date"][5:]} {won(h["from"])}→{won(h["to"])}) 후 3일 — 재평가 보류')
        elif c7['cost'] >= 30000 and c7['ctr'] < ctr_med / 2:
            v = ('교체 검토', f'CTR {c7["ctr"]:.2f}%가 소재 중앙값({ctr_med:.2f}%)의 절반 미만 (메타)')
        elif c7['roas'] >= tgt * 1.5 and (p7['cost'] == 0 or p7['roas'] >= tgt * 1.5):
            v = ('증액 검토', f'메타 ROAS {c7["roas"]:.0f}%가 목표({tgt:.0f}%)×1.5 이상 2주 지속 · 기여이익 {"+" if contrib>=0 else ""}{won(contrib)}(메타 기준) — §3 가드레일: 하루 1개·+10~20%')
        elif be <= c7['roas'] < tgt and contrib < p_contrib:
            v = ('감액 검토', f'본전({be:.0f}%)~목표 구간 & 기여이익 하락 {won(p_contrib)}→{won(contrib)} (메타 기준)')
        elif contrib < 0:
            v = ('관찰', f'기여이익 {won(contrib)}(메타 기준) 마이너스이나 지출 5만 미만 — 확대 보류')
        else:
            v = None                       # 특이사항 없음
        g = ga_camp7.get(nm)
        verdicts.append({'name': nm, 'tag': v[0] if v else None, 'why': v[1] if v else None,
                         'c7': c7, 'contrib': contrib, 'margin_label': mlabel,
                         'ga_rev7': (g or {}).get('rev')})

    OP_ORDER = {'끄기 검토': 0, '랜딩 점검': 1, '교체 검토': 2, '감액 검토': 3, '증액 검토': 4, '관찰': 5, '리드': 6}
    opinions = sorted([v for v in verdicts if v['tag']],
                      key=lambda v: (OP_ORDER.get(v['tag'], 9), -abs(v['contrib'])))

    # ── 합계 ──
    t_7 = srange(rows, d7, anchor)
    t_p7 = srange(rows, d13, d8)
    t_30 = srange(rows, d30, anchor)

    def contrib_total(a, b):
        return round(sum(srange(rows, a, b, nm)['rev'] * margin_of(nm)[0] - srange(rows, a, b, nm)['cost']
                         for nm in camps))
    ct_7, ct_p7, ct_30 = contrib_total(d7, anchor), contrib_total(d13, d8), contrib_total(d30, anchor)
    ga_7, ga_30 = ga_sum(d7, anchor), ga_sum(d30, anchor)

    ord_7 = None
    if dash and dash.get('daily'):
        ord_7 = sum((r.get('jasaOrd') or 0) + (r.get('bizOrd') or 0)
                    for r in dash['daily'] if d7 <= r.get('date', '') <= anchor)

    refs = []
    if dash and dash.get('voc'):
        wc = dash['voc'].get('waitCount', 0)
        refs.append(f'미답변 1:1 문의 {wc}건 (아임웹)')
    if crema and crema.get('reviews'):
        low7 = sum(1 for r in crema['reviews']
                   if r.get('date', '') >= d7 and r.get('score') is not None and r['score'] <= 3)
        refs.append(f'7일 저평점(3점 이하) 후기 {low7}건 (크리마)')

    # ── 리포트 조립 ──
    tag_color = {'끄기 검토': '#b91c3c', '랜딩 점검': '#7c3aed', '감액 검토': '#92400e',
                 '증액 검토': '#027a38', '교체 검토': '#92400e', '관찰': '#5f5e5a', '리드': '#1d4ed8'}

    def pct(v):
        return f'{v:.0f}%' if v else '—'

    period = f'{d7[5:].replace("-", ".")} ~ {anchor[5:].replace("-", ".")}'
    ok = ct_7 >= 0
    # 요약 (출처 명기)
    ga7_html = (' / <b>' + won(ga_7) + '</b><span style="color:#888">(GA4 실측)</span>') if ga_7 is not None else ''
    sec0 = (f'<div style="background:{"#eefaf0" if ok else "#fdecec"};border:1px solid {"#bfe8cc" if ok else "#f5c2cb"};'
            f'border-radius:12px;padding:14px 18px;margin:6px 0 16px;font-size:14px">'
            f'최근 7일({period}) 광고비 <b>{won(t_7["cost"])}</b> → '
            f'매출 <b>{won(t_7["rev"])}</b><span style="color:#888">(메타 귀속)</span>'
            + ga7_html +
            f'<div style="margin-top:6px">메타 귀속 매출 × 마진율 − 광고비 = <b style="color:{"#027a38" if ok else "#b91c3c"};font-size:17px">{"+" if ok else ""}{won(ct_7)}</b>'
            f' <span style="font-size:12px;color:#888">(직전 7일 {"+" if ct_p7>=0 else ""}{won(ct_p7)})</span></div>'
            f'<div style="font-size:11.5px;color:#999;margin-top:6px">※ 메타 귀속 = 메타가 자기 광고 기여로 집계한 매출(과대 경향) · GA4 실측 = 광고 클릭 후 실제 결제(과소 경향) — 진실은 그 사이</div></div>')

    # [로데이터부] ① 진행 중인 광고 (팩트만)
    rows1 = ''
    for v in sorted(verdicts, key=lambda x: -x['c7']['cost']):
        b = budgets.get(v['name'], {})
        bud = b.get('budget')
        st = b.get('status', '')
        st_txt = ('<span style="color:#027a38">●게재중</span>' if st == 'ACTIVE'
                  else f'<span style="color:#999">○{("중지" if st else "—")}</span>')
        bc = [h for h in bhist if h.get('campaign') == v['name']]
        bctxt = f'{bc[-1]["date"][5:]} {"↑" if bc[-1]["to"]>bc[-1]["from"] else "↓"}' if bc else '—'
        rows1 += (f'<tr><td style="text-align:left;padding:4px 8px">{v["name"][:26]}</td>'
                  f'<td>{st_txt}</td><td>{won(bud) if bud else "—"}</td><td>{bctxt}</td></tr>')
    sec1 = (f'<h3 style="margin:18px 0 6px">① 진행 중인 광고 <span style="font-size:11.5px;color:#888;font-weight:400">출처: 메타 캠페인 설정</span></h3>'
            f'<table style="border-collapse:collapse;font-size:13px;width:100%">'
            f'<tr style="color:#888"><td style="text-align:left;padding:4px 8px">캠페인</td>'
            f'<td>상태</td><td>일예산</td><td>최근 예산 변경</td></tr>{rows1}</table>')

    # ② 최근 7일 캠페인별 (로데이터 표 — 메타/실측 병기)
    rows2 = ''
    for v in sorted(verdicts, key=lambda x: -x['c7']['cost']):
        c = v['c7']
        ga_r = v['ga_rev7']
        ga_roas = (ga_r / c['cost'] * 100) if (ga_r is not None and c['cost']) else None
        rows2 += (f'<tr><td style="text-align:left;padding:4px 8px">{v["name"][:24]}</td>'
                  f'<td>{won(c["cost"])}</td><td>{won(c["rev"])}</td><td>{pct(c["roas"])}</td>'
                  f'<td>{won(ga_r) if ga_r is not None else "—"}</td><td>{pct(ga_roas) if ga_roas is not None else "—"}</td>'
                  f'<td style="color:{"#027a38" if v["contrib"]>=0 else "#b91c3c"};font-weight:700">{"+" if v["contrib"]>=0 else ""}{won(v["contrib"])}</td></tr>')
    sec2 = (f'<h3 style="margin:18px 0 6px">② 최근 7일 캠페인별 ({period})</h3>'
            f'<table style="border-collapse:collapse;font-size:12.5px;width:100%">'
            f'<tr style="color:#888"><td style="text-align:left;padding:4px 8px">캠페인</td>'
            f'<td>지출<br>(메타)</td><td>매출<br>(메타 귀속)</td><td>ROAS<br>(메타)</td>'
            f'<td>매출<br>(GA4 실측)</td><td>ROAS<br>(실측)</td><td>기여이익<br>(메타 기준)</td></tr>{rows2}</table>'
            f'<div style="font-size:11px;color:#999;margin-top:4px">기여이익 = 메타 귀속 매출 × 마진율 − 지출 · 마진율은 캠페인명 키워드로 자동 매핑</div>')

    # ③ 기간 합계
    sec3 = (f'<h3 style="margin:18px 0 6px">③ 기간 합계</h3>'
            f'<div style="font-size:13px;line-height:1.9">'
            f'<b>최근 7일</b> — 지출 {won(t_7["cost"])}(메타) · 매출 {won(t_7["rev"])}(메타 귀속)'
            f'{f" / {won(ga_7)}(GA4 실측)" if ga_7 is not None else ""}'
            f' · 기여이익 {"+" if ct_7>=0 else ""}{won(ct_7)}(메타 기준)'
            f'{f" · 자사몰+비즈몰 주문 {ord_7}건(아임웹)" if ord_7 is not None else ""}<br>'
            f'<b>최근 30일</b> — 지출 {won(t_30["cost"])}(메타) · 매출 {won(t_30["rev"])}(메타 귀속)'
            f'{f" / {won(ga_30)}(GA4 실측)" if ga_30 is not None else ""}'
            f' · 기여이익 {"+" if ct_30>=0 else ""}{won(ct_30)}(메타 기준)</div>')

    # ④ 참고 지표
    sec4 = ('<h3 style="margin:18px 0 6px">④ 참고 지표</h3><div style="font-size:13px">'
            + ('<br>'.join('· ' + t for t in refs) if refs else '—') + '</div>')

    # [의견부] — 규칙 기반 제안, 실행 판단은 운영자
    op_html = ''
    for v in opinions:
        col = tag_color.get(v['tag'], '#555')
        op_html += (f'<div style="border:1px solid #e5e5e5;border-left:4px solid {col};border-radius:8px;'
                    f'padding:9px 13px;margin:7px 0;font-size:13px">'
                    f'<b><span style="background:{col};color:#fff;border-radius:8px;padding:1px 8px;font-size:11.5px">{v["tag"]}</span>'
                    f' {v["name"][:30]}</b><div style="margin-top:3px;color:#444">{v["why"]}</div></div>')
    secB = ('<h3 style="margin:18px 0 6px">의견 <span style="font-size:11.5px;color:#888;font-weight:400">§3 확정 규칙 기반 자동 판정 · 검토 제안일 뿐 실행 판단은 운영자 몫</span></h3>'
            + (op_html or '<div style="font-size:13px;color:#555">이번 주 특이사항 없음</div>'))

    today = datetime.datetime.now(KST).strftime('%-m/%-d')
    subject = f'[선암 광고] 주간 리포트 ({period}) — 기여이익 {"+" if ct_7>=0 else ""}{won(ct_7)} (메타 기준) · 의견 {len(opinions)}건'
    html = (f'<div style="font-family:-apple-system,\'Apple SD Gothic Neo\',\'Malgun Gothic\',sans-serif;'
            f'max-width:680px;margin:0 auto;color:#222">'
            f'<h2 style="margin:6px 0">선암파머스 광고 주간 리포트 <span style="font-size:13px;color:#888;font-weight:400">{anchor} 데이터 기준</span></h2>'
            + sec0
            + '<div style="font-size:12px;color:#888;border-bottom:2px solid #222;padding-bottom:4px;margin-top:20px"><b style="color:#222">로데이터</b> — 수치와 출처만</div>'
            + sec1 + sec2 + sec3 + sec4
            + '<div style="font-size:12px;color:#888;border-bottom:2px solid #222;padding-bottom:4px;margin-top:26px"><b style="color:#222">의견</b> — 규칙 기반 제안</div>'
            + secB
            + '<div style="font-size:11.5px;color:#999;margin-top:16px">판정 규칙(§3): 기여이익=메타 귀속 매출×마진율−지출 · 본전 ROAS=100÷마진율 · 목표=본전×2 · '
              '대시보드: tennout.github.io/sunam-ad-dashboard</div></div>')

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
