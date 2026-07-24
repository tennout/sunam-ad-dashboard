#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
선암파머스 · 메타(페이스북·인스타그램) 광고 성과 수집 스크립트
================================================================
이 스크립트가 하는 일
  1) 메타 마케팅 API(Insights)로 광고 성과를 수집하고
  2) 대시보드가 읽는 data/meta_bundle.js 파일로 저장합니다.

수집 항목 (대시보드 3대 기능용)
  · 완전 퍼널   : 노출→클릭→랜딩조회(LPV)→장바구니(ATC)→구매(purchase)
  · 지면별 성과 : 피드/릴스/스토리/탐색 등 (publisher_platform + platform_position)
  · 소재 피로도 : frequency(1인당 평균 노출 횟수) + 소재별 성과

환경변수 (GitHub Secrets 권장 — 코드/repo에 넣지 말 것)
  META_TOKEN         (필수)  액세스 토큰 (장기토큰 권장)
  META_AD_ACCOUNT    (필수)  광고계정 ID (예: act_1234567890 또는 1234567890)
  META_APP_ID        (선택)  단기토큰 자동 교환용
  META_APP_SECRET    (선택)  단기토큰 자동 교환용
  META_ACCOUNT_NAME  (선택)  표시용 계정명 (기본: 선암파머스)

사용법
  $ META_TOKEN=... META_AD_ACCOUNT=act_... python fetch_meta_ads.py --days 90

API 문서
  https://developers.facebook.com/docs/marketing-api/insights
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib import error, parse, request

GRAPH = "https://graph.facebook.com/v21.0"
USER_AGENT = "sunamfarmers-dashboard-meta/1.0"

# 액션 타입 매핑 — 메타는 픽셀/앱 이벤트 종류가 다양해 후보를 순서대로 탐색
ACTION_KEYS = {
    "lpv": ["landing_page_view", "omni_landing_page_view"],
    "atc": [
        "offsite_conversion.fb_pixel_add_to_cart",
        "add_to_cart",
        "omni_add_to_cart",
    ],
    "purchase": [
        "offsite_conversion.fb_pixel_purchase",
        "purchase",
        "omni_purchase",
    ],
    "linkclick": ["link_click"],
}


# ────────────────────────────────────────────────
# HTTP
# ────────────────────────────────────────────────
def _get(url: str, params: dict, retries: int = 3):
    q = parse.urlencode(params, doseq=True)
    full = f"{url}?{q}" if q else url   # next URL은 이미 쿼리 포함 → ? 덧붙이면 커서 깨짐
    last = None
    for attempt in range(retries):
        try:
            req = request.Request(full, method="GET", headers={"User-Agent": USER_AGENT})
            with request.urlopen(req, timeout=60) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else None
        except error.HTTPError as e:
            detail = e.read().decode("utf-8", "ignore")[:300]
            last = f"HTTP {e.code}: {detail}"
            # 400 = 대개 토큰/권한/필드 오류 → 재시도 무의미
            if e.code in (500, 502, 503, 504, 429):
                time.sleep(2 * (attempt + 1))
                continue
            raise RuntimeError(last)
        except error.URLError as e:
            last = f"URL error: {e.reason}"
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(last or "unknown error")


def _get_paged(url: str, params: dict, max_pages: int = 50) -> list:
    """페이징(next)을 따라가며 data를 전부 모음."""
    out = []
    res = _get(url, params)
    pages = 0
    while res:
        out.extend(res.get("data") or [])
        nxt = ((res.get("paging") or {}).get("next"))
        pages += 1
        if not nxt or pages >= max_pages:
            break
        # next는 완성된 URL — 그대로 호출
        res = _get(nxt, {})
    return out


# ────────────────────────────────────────────────
# 토큰 교환 (단기 → 장기)
# ────────────────────────────────────────────────
def exchange_long_lived(token: str, app_id: str, app_secret: str) -> tuple:
    """장기토큰으로 교환. 반환: (token, expires_in초 or None)."""
    try:
        res = _get(
            f"{GRAPH}/oauth/access_token",
            {
                "grant_type": "fb_exchange_token",
                "client_id": app_id,
                "client_secret": app_secret,
                "fb_exchange_token": token,
            },
        )
        return res.get("access_token", token), res.get("expires_in")
    except Exception as e:
        print(f"  ! 장기토큰 교환 실패(단기토큰 그대로 사용): {e}")
        return token, None


def token_expiry(token: str, app_id: str, app_secret: str) -> str:
    """토큰 만료 시각(디버그). 실패 시 빈 문자열."""
    if not (app_id and app_secret):
        return ""
    try:
        res = _get(
            f"{GRAPH}/debug_token",
            {"input_token": token, "access_token": f"{app_id}|{app_secret}"},
        )
        ts = ((res or {}).get("data") or {}).get("data_access_expires_at") or \
             ((res or {}).get("data") or {}).get("expires_at")
        if ts:
            return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return ""


# ────────────────────────────────────────────────
# 파서 헬퍼
# ────────────────────────────────────────────────
def _actions_to_map(actions) -> dict:
    m = {}
    for a in actions or []:
        t = a.get("action_type")
        v = a.get("value")
        if t is None:
            continue
        try:
            m[t] = float(v or 0)
        except Exception:
            m[t] = 0.0
    return m


def _actions_to_map_win(actions, win: str) -> dict:
    """어트리뷰션 윈도우별 값 (예: 7d_click = 클릭 기여만, 뷰스루 제외)"""
    m = {}
    for a in actions or []:
        t = a.get("action_type")
        if t is None:
            continue
        try:
            m[t] = float(a.get(win) or 0)
        except Exception:
            m[t] = 0.0
    return m


def _pick(m: dict, keys: list) -> float:
    for k in keys:
        if k in m:
            return m[k]
    return 0.0


def _num(v, cast=float):
    try:
        return cast(float(v))
    except Exception:
        return cast(0)


def _row_metrics(r: dict) -> dict:
    am = _actions_to_map(r.get("actions"))
    vm = _actions_to_map(r.get("action_values"))
    am_clk = _actions_to_map_win(r.get("actions"), "7d_click")
    vm_clk = _actions_to_map_win(r.get("action_values"), "7d_click")
    imp = _num(r.get("impressions"), int)
    clk = _num(r.get("clicks"), int)
    cost = round(_num(r.get("spend")))
    return {
        "imp": imp,
        "clk": clk,
        "cost": cost,
        "reach": _num(r.get("reach"), int),
        "freq": round(_num(r.get("frequency")), 2),
        "lpv": int(_pick(am, ACTION_KEYS["lpv"])),
        "atc": int(_pick(am, ACTION_KEYS["atc"])),
        "conv": int(_pick(am, ACTION_KEYS["purchase"])),
        "rev": round(_pick(vm, ACTION_KEYS["purchase"])),
        "convClk": int(_pick(am_clk, ACTION_KEYS["purchase"])),
        "revClk": round(_pick(vm_clk, ACTION_KEYS["purchase"])),
        "linkclk": int(_pick(am, ACTION_KEYS["linkclick"])),
    }


BASE_FIELDS = (
    "campaign_name,ad_name,impressions,clicks,spend,reach,frequency,"
    "actions,action_values"
)


# ────────────────────────────────────────────────
# 수집
# ────────────────────────────────────────────────
def fetch_insights(acct: str, token: str, since: str, until: str,
                   level: str, breakdowns: str = "", time_increment: str = "") -> list:
    params = {
        "access_token": token,
        "level": level,
        "fields": BASE_FIELDS,
        "time_range": json.dumps({"since": since, "until": until}),
        # 클릭/뷰스루 분리 — 액션마다 "7d_click", "1d_view" 값이 따로 옴
        "action_attribution_windows": json.dumps(["7d_click", "1d_view"]),
        "limit": 500,
    }
    if breakdowns:
        params["breakdowns"] = breakdowns
    if time_increment:
        params["time_increment"] = time_increment
    return _get_paged(f"{GRAPH}/{acct}/insights", params)


def fetch_creative_previews(acct: str, token: str) -> dict:
    """소재 썸네일·원본링크 수집. 반환: {ad_name: {thumb, link}}."""
    out = {}
    # 메타가 "Please reduce the amount of data" (HTTP 500, code 1)로 거부하면
    # 페이지 크기를 줄여가며 재시도 (200 → 50 → 25 → 10)
    rows = None
    last_err = None
    for _limit in (50, 25, 10):
        try:
            rows = _get_paged(f"{GRAPH}/{acct}/ads", {
                "access_token": token,
                # effective_status = 실제 게재 상태(ACTIVE/PAUSED/…), 나머지는 썸네일/링크용
                # object_story_spec의 picture(고화질), image_url(원본), thumbnail_url(저화질) 순으로 확보
                "fields": ("name,effective_status,creative{thumbnail_url,image_url,instagram_permalink_url,"
                           "effective_object_story_id,object_story_spec{link_data{picture},"
                           "video_data{image_url}}}"),
                # 썸네일 요청 크기 확대 (기본 64px → 600px)
                "thumbnail_width": 600,
                "thumbnail_height": 600,
                "limit": _limit,
            })
            break
        except Exception as e:
            last_err = e
            print(f"    ! limit={_limit} 실패 — 더 작게 재시도: {str(e)[:120]}")
    if rows is None:
        # 최후 폴백: 무거운 고화질 필드 빼고 저화질 썸네일만
        try:
            rows = _get_paged(f"{GRAPH}/{acct}/ads", {
                "access_token": token,
                "fields": "name,effective_status,creative{thumbnail_url,instagram_permalink_url,effective_object_story_id}",
                "thumbnail_width": 600, "thumbnail_height": 600, "limit": 25,
            })
            print("    (폴백: 저화질 썸네일만 수집)")
        except Exception as e:
            print(f"    ! 소재 미리보기 수집 실패: {last_err or e}")
            return out
    for a in rows:
        name = a.get("name", "")
        cr = a.get("creative") or {}
        oss = cr.get("object_story_spec") or {}
        hi = ((oss.get("link_data") or {}).get("picture")
              or (oss.get("video_data") or {}).get("image_url"))
        # 고화질(원본) 우선, 없으면 확대 요청한 thumbnail_url
        thumb = hi or cr.get("image_url") or cr.get("thumbnail_url") or ""
        link = cr.get("instagram_permalink_url") or ""
        if not link and cr.get("effective_object_story_id"):
            link = f"https://www.facebook.com/{cr['effective_object_story_id']}"
        if name:
            out[name] = {"thumb": thumb, "link": link,
                         "status": a.get("effective_status", "")}
    return out


def collect(acct: str, token: str, days: int) -> dict:
    end = date.today()
    start = end - timedelta(days=days - 1)
    since, until = str(start), str(end)
    print(f"▶ 메타 수집 {since} ~ {until} (계정 {acct})")

    # 1) 일자×소재 (퍼널·피로도·추이의 기반) — ad 레벨 + 일별
    print("  · 일자×소재 성과 수집...")
    daily = []
    for r in fetch_insights(acct, token, since, until, level="ad", time_increment="1"):
        m = _row_metrics(r)
        daily.append(dict(
            m,
            date=r.get("date_start", ""),
            campaign=r.get("campaign_name", ""),
            ad=r.get("ad_name", ""),
        ))
    print(f"    {len(daily)}행")

    # 2) 소재 합계 (기간 전체, 피로도=frequency 포함)
    print("  · 소재별 합계 수집...")
    creatives = []
    for r in fetch_insights(acct, token, since, until, level="ad"):
        m = _row_metrics(r)
        creatives.append(dict(m, campaign=r.get("campaign_name", ""), ad=r.get("ad_name", "")))
    print(f"    소재 {len(creatives)}개")

    # 2-1) 소재 미리보기(썸네일·원본링크) 결합
    print("  · 소재 미리보기(썸네일) 수집...")
    prev = fetch_creative_previews(acct, token)
    hit = 0
    for c in creatives:
        p = prev.get(c.get("ad", ""))
        if p:
            c["thumb"] = p.get("thumb", "")
            c["link"] = p.get("link", "")
            c["status"] = p.get("status", "")
            hit += 1
    print(f"    썸네일 매칭 {hit}개")

    # 3) 캠페인 합계
    print("  · 캠페인별 합계 수집...")
    campaigns = []
    for r in fetch_insights(acct, token, since, until, level="campaign"):
        m = _row_metrics(r)
        campaigns.append(dict(m, campaign=r.get("campaign_name", "")))
    print(f"    캠페인 {len(campaigns)}개")

    # 4) 지면별 성과 (publisher_platform + platform_position)
    print("  · 지면별 성과 수집...")
    placements = []
    try:
        for r in fetch_insights(acct, token, since, until, level="account",
                                breakdowns="publisher_platform,platform_position"):
            m = _row_metrics(r)
            pp = r.get("publisher_platform", "")
            pos = r.get("platform_position", "")
            placements.append(dict(m, platform=pp, position=pos))
    except Exception as e:
        print(f"    ! 지면 수집 실패: {e}")
    print(f"    지면 {len(placements)}개")

    # 퍼널 합계 (기간 전체)
    funnel = {"imp": 0, "clk": 0, "linkclk": 0, "lpv": 0, "atc": 0, "conv": 0, "rev": 0,
              "convClk": 0, "revClk": 0}
    for c in creatives:
        for k in funnel:
            funnel[k] += c.get(k, 0)

    return {
        "daily": daily,
        "creatives": creatives,
        "campaigns": campaigns,
        "placements": placements,
        "funnel": funnel,
        "rangeStart": since,
        "rangeEnd": until,
    }


# ────────────────────────────────────────────────
# 메인
# ────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="메타 광고 성과 수집")
    ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--out", default="data")
    args = ap.parse_args()

    token = os.environ.get("META_TOKEN", "").strip()
    acct = os.environ.get("META_AD_ACCOUNT", "").strip()
    app_id = os.environ.get("META_APP_ID", "").strip()
    app_secret = os.environ.get("META_APP_SECRET", "").strip()
    acct_name = os.environ.get("META_ACCOUNT_NAME", "선암파머스").strip()

    if not token or not acct:
        print("❌ META_TOKEN, META_AD_ACCOUNT 환경변수가 필요합니다.")
        sys.exit(1)
    if not acct.startswith("act_"):
        acct = "act_" + acct

    # 장기토큰 교환 (앱ID/시크릿 있을 때)
    if app_id and app_secret:
        print("· 장기토큰 교환 시도...")
        token, exp = exchange_long_lived(token, app_id, app_secret)
        if exp:
            print(f"  교환 완료 — 약 {int(exp)//86400}일 유효")
    expires_at = token_expiry(token, app_id, app_secret)
    if expires_at:
        print(f"· 토큰 만료 예정: {expires_at}")

    try:
        data = collect(acct, token, args.days)
    except Exception as e:
        print(f"❌ 수집 실패: {e}")
        sys.exit(1)

    out_dir = Path(args.out)
    out_dir.mkdir(exist_ok=True)

    bundle = {
        "generatedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tokenExpiresAt": expires_at,
        "account": {"name": acct_name, "adAccountId": acct},
        **data,
    }
    (out_dir / "meta.json").write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out_dir / "meta_bundle.js").write_text(
        "window.META_ADS_BUNDLE = " + json.dumps(bundle, ensure_ascii=False) + ";\n",
        encoding="utf-8",
    )
    print(f"\n▶ 완료 — 일자 {len(data['daily'])} · 소재 {len(data['creatives'])} · "
          f"캠페인 {len(data['campaigns'])} · 지면 {len(data['placements'])}")
    print("   대시보드 새로고침 시 메타 탭에 자동 반영됩니다.")


if __name__ == "__main__":
    main()
