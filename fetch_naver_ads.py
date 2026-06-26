#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
선암파머스 · 네이버 검색광고 API 데이터 수집 스크립트
================================================================
이 스크립트가 하는 일
  1) accounts.json에 적힌 여러 광고 계정을 순회하며
  2) 네이버 검색광고 API로부터 캠페인·광고그룹·소재·키워드·일자별 성과를 수집하고
  3) 대시보드(HTML)가 읽을 수 있는 형태의 JSON 파일로 저장합니다.

사용법
  $ python fetch_naver_ads.py             # 최근 90일치
  $ python fetch_naver_ads.py --days 30   # 최근 30일치

자동 갱신
  - Cowork 예약 작업(scheduled task)
  - macOS/Linux crontab  (예: 매일 04:00)
      0 4 * * * cd /path/to/dashboard && /usr/bin/python3 fetch_naver_ads.py >> fetch.log 2>&1
  - Windows 작업 스케줄러

API 공식 문서
  https://naver.github.io/searchad-apidoc/
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib import error, parse, request

API_BASE = "https://api.searchad.naver.com"
USER_AGENT = "sunamfarmers-dashboard/1.0"

# ────────────────────────────────────────────────
# 1. 인증 헤더 (HMAC-SHA256 서명)
# ────────────────────────────────────────────────
def _sign(method: str, uri: str, ts: str, secret_key: str) -> str:
    message = f"{ts}.{method}.{uri}".encode("utf-8")
    digest = hmac.new(secret_key.encode("utf-8"), message, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


def _headers(method: str, uri: str, acct: dict) -> dict:
    ts = str(int(time.time() * 1000))
    return {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": USER_AGENT,
        "X-Timestamp": ts,
        "X-API-KEY": acct["apiKey"],
        "X-Customer": str(acct["customerId"]),
        "X-Signature": _sign(method, uri, ts, acct["secretKey"]),
    }


# ────────────────────────────────────────────────
# 2. HTTP 래퍼 (재시도 포함)
# ────────────────────────────────────────────────
def _get(uri: str, acct: dict, params: dict | None = None, retries: int = 3):
    query = ("?" + parse.urlencode(params, doseq=True)) if params else ""
    url = API_BASE + uri + query
    last_err = None
    for attempt in range(retries):
        try:
            req = request.Request(url, method="GET", headers=_headers("GET", uri, acct))
            with request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else None
        except error.HTTPError as e:
            last_err = f"HTTP {e.code}: {e.read().decode('utf-8', 'ignore')[:200]}"
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(1.5 * (attempt + 1))
                continue
            raise RuntimeError(last_err)
        except error.URLError as e:
            last_err = f"URL error: {e.reason}"
            time.sleep(1.0 * (attempt + 1))
    raise RuntimeError(last_err or "unknown error")


# ────────────────────────────────────────────────
# 3. 광고 유형 매핑 (네이버 campaignTp → 대시보드 코드)
# ────────────────────────────────────────────────
AD_TYPE_MAP = {
    "WEB_SITE": "powerlink",      # 파워링크 (사이트검색광고)
    "SHOPPING": "shop",           # 쇼핑검색광고
    "POWER_CONTENTS": "powerlink",
    "BRAND_SEARCH": "brand",      # 브랜드검색
    "PLACE": "place",
    "CATALOG": "shop",
}


def _map_ad_type(campaign_tp: str) -> str:
    return AD_TYPE_MAP.get((campaign_tp or "").upper(), "powerlink")


# ────────────────────────────────────────────────
#  키워드도구(keywordstool): 월검색량 · 경쟁정도 · 연관키워드
# ────────────────────────────────────────────────
_COMP_KOR = {
    "낮음": "낮음", "중간": "중간", "높음": "높음",
    "LOW": "낮음", "MID": "중간", "MIDDLE": "중간", "HIGH": "높음",
}


def _kw_int(v):
    """keywordstool은 검색량이 적으면 '< 10' 같은 문자열을 준다."""
    try:
        t = str(v).replace(",", "").strip()
        if t.startswith("<"):
            return 5
        return int(float(t))
    except Exception:
        return 0


def _nospace(s: str) -> str:
    return "".join((s or "").split()).lower()


def fetch_keyword_tool(acct: dict, kw_strings: list) -> tuple:
    """등록 키워드 문자열들로 keywordstool 조회.
    반환: (vol_map, opportunities)
      vol_map[nospace(키워드)] = {pc, mobile, total, comp, depth}
      opportunities = [{keyword, pc, mobile, total, comp, depth}, ...]  (미등록 연관키워드)
    """
    vol_map, opp_map = {}, {}
    registered = {_nospace(s) for s in kw_strings if s and s.strip()}
    uniq = [s.strip() for s in dict.fromkeys(kw_strings) if s and s.strip()]
    for i in range(0, len(uniq), 5):  # hintKeywords는 최대 5개
        batch = uniq[i:i + 5]
        hint = ",".join(k.replace(" ", "") for k in batch)
        try:
            res = _get("/keywordstool", acct, {"hintKeywords": hint, "showDetail": 1})
        except Exception as e:
            print(f"    ! 키워드도구 조회 실패({hint}): {e}")
            continue
        for r in (res or {}).get("keywordList") or []:
            kw = (r.get("relKeyword") or "").strip()
            if not kw:
                continue
            pc = _kw_int(r.get("monthlyPcQcCnt"))
            mo = _kw_int(r.get("monthlyMobileQcCnt"))
            comp = _COMP_KOR.get(str(r.get("compIdx") or "").upper(), str(r.get("compIdx") or ""))
            try:
                depth = round(float(r.get("plAvgDepth") or 0), 1)
            except Exception:
                depth = 0
            rec = {"pc": pc, "mobile": mo, "total": pc + mo, "comp": comp, "depth": depth}
            key = _nospace(kw)
            if key in registered:
                vol_map[key] = rec
            elif key not in opp_map:
                opp_map[key] = dict(rec, keyword=kw)
        time.sleep(0.2)  # rate-limit 완화
    opportunities = sorted(opp_map.values(), key=lambda x: x["total"], reverse=True)[:40]
    return vol_map, opportunities


# ────────────────────────────────────────────────
#  /stats 응답 파서: Naver API의 다양한 응답 형식을 모두 흡수
#   - {"data": [{"date":"YYYYMMDD","impCnt":..}]}   (가장 흔함)
#   - [{"id":..,"fields":[..],"datasets":[{"date":..,"values":[..]}]}]
#   - {"id":..,"fields":[..],"datasets":[{"date":..,"values":[..]}]}
# ────────────────────────────────────────────────
_FIELD_NAMES = ["impCnt", "clkCnt", "salesAmt", "ccnt", "convAmt", "ctr", "cpc"]


def _daterange_chunks(start, end, max_days: int = 90):
    """Naver /stats는 92일 이내 구간만 허용. 안전하게 90일로 나눔."""
    chunks = []
    cs = start
    while cs <= end:
        ce = min(cs + timedelta(days=max_days - 1), end)
        chunks.append((cs, ce))
        cs = ce + timedelta(days=1)
    return chunks


def _normalize_date(raw) -> str:
    """YYYYMMDD → YYYY-MM-DD 정규화"""
    if not raw:
        return ""
    s = str(raw)[:10]
    if len(s) == 8 and s.isdigit():
        return f"{s[:4]}-{s[4:6]}-{s[6:8]}"
    return s


def _parse_stats(stat) -> list:
    """어떤 형태가 와도 [{date, impCnt, clkCnt, ...}] 리스트로 변환."""
    if not stat:
        return []

    # 외곽: list or dict
    if isinstance(stat, list):
        buckets = stat
    elif isinstance(stat, dict):
        if isinstance(stat.get("data"), list):
            buckets = stat["data"]
        elif isinstance(stat.get("datasets"), list):
            buckets = [stat]  # 단일 id 응답
        else:
            buckets = [stat]
    else:
        return []

    out = []
    for b in buckets:
        if not isinstance(b, dict):
            continue
        # Case 1: 버킷이 그 자체로 일자별 한 줄인 경우 (flat)
        # 날짜 필드는 API 버전에 따라 date / dateStart / statDt 등으로 다양함
        date_key = next((k for k in ("date", "dateStart", "statDt", "index") if k in b), None)
        if date_key and any(f in b for f in _FIELD_NAMES):
            row = dict(b)
            row["date"] = _normalize_date(b[date_key])
            out.append(row)
            continue
        # Case 2: 버킷이 id+datasets 구조인 경우
        fields = b.get("fields") or _FIELD_NAMES
        for ds in (b.get("datasets") or []):
            if not isinstance(ds, dict):
                continue
            date = _normalize_date(ds.get("date") or ds.get("index") or ds.get("statDt"))
            vals = ds.get("values") or ds.get("data") or []
            row = {"date": date}
            if isinstance(vals, list):
                for i, fn in enumerate(fields):
                    if i < len(vals):
                        row[fn] = vals[i]
            else:
                # 드물게 ds 자체가 flat dict일 수도
                for fn in _FIELD_NAMES:
                    if fn in ds:
                        row[fn] = ds[fn]
            out.append(row)
    return out


# ────────────────────────────────────────────────
# 4. 개별 계정 수집
# ────────────────────────────────────────────────
def fetch_account(acct: dict, days: int = 365) -> dict:
    name = acct.get("name", acct.get("customerId"))
    print(f"  · [{name}] 메타 수집...")
    end = date.today()
    start = end - timedelta(days=days - 1)

    # 네이버 API는 /ncc/adgroups, /ncc/ads, /ncc/keywords 조회 시
    # 상위 ID(nccCampaignId / nccAdgroupId)를 쿼리 파라미터로 꼭 넘겨야 함.
    # 캠페인만 커스터머 단위로 바로 조회 가능.
    campaigns = _get("/ncc/campaigns", acct) or []
    print(f"    캠페인 {len(campaigns)}개")

    # 광고그룹은 캠페인별로 조회
    adgroups = []
    for c in campaigns:
        cid = c.get("nccCampaignId")
        if not cid:
            continue
        try:
            ag_list = _get("/ncc/adgroups", acct, {"nccCampaignId": cid}) or []
            adgroups.extend(ag_list)
        except Exception as e:
            print(f"    ! 캠페인 {cid} 광고그룹 조회 실패: {e}")
    print(f"    광고그룹 {len(adgroups)}개")

    # 소재·키워드는 광고그룹별로 조회
    ads, keywords = [], []
    for ag in adgroups:
        agid = ag.get("nccAdgroupId")
        if not agid:
            continue
        try:
            ad_list = _get("/ncc/ads", acct, {"nccAdgroupId": agid}) or []
            ads.extend(ad_list)
        except Exception as e:
            print(f"    ! 광고그룹 {agid} 소재 조회 실패: {e}")
        try:
            kw_list = _get("/ncc/keywords", acct, {"nccAdgroupId": agid}) or []
            keywords.extend(kw_list)
        except Exception as e:
            print(f"    ! 광고그룹 {agid} 키워드 조회 실패: {e}")
    print(f"    소재 {len(ads)}개 · 키워드 {len(keywords)}개")

    cmp_lookup = {c["nccCampaignId"]: c for c in campaigns}

    # 4-1) 캠페인별 일자별 성과 — 92일 제한 우회를 위해 90일 청크로 나눔
    chunks = _daterange_chunks(start, end, max_days=90)
    print(f"  · [{name}] 일자별 성과 {start} ~ {end} 수집 ({len(chunks)}개 구간)...")
    daily = []
    fields = json.dumps(
        ["impCnt", "clkCnt", "salesAmt", "ccnt", "convAmt", "ctr", "cpc"],
        ensure_ascii=False,
    )
    _debug_shown = False
    nonzero = 0
    for c in campaigns:
        cid = c["nccCampaignId"]
        ad_type = _map_ad_type(c.get("campaignTp"))
        for ci, (cs, ce) in enumerate(chunks, start=1):
            tr = json.dumps({"since": str(cs), "until": str(ce)}, ensure_ascii=False)
            try:
                stat = _get(
                    "/stats",
                    acct,
                    {
                        "id": cid,
                        "fields": fields,
                        "timeRange": tr,
                        "breakdown": "day",
                    },
                )
                if not _debug_shown and stat:
                    preview = json.dumps(stat, ensure_ascii=False)[:400]
                    print(f"    [진단] 첫 stats 원본 구조: {preview}...")
                    _debug_shown = True
                rows = _parse_stats(stat)
                for r in rows:
                    imp = int(float(r.get("impCnt", 0) or 0))
                    clk = int(float(r.get("clkCnt", 0) or 0))
                    cost = int(float(r.get("salesAmt", 0) or 0))
                    conv = int(float(r.get("ccnt", 0) or 0))
                    rev  = int(float(r.get("convAmt", 0) or 0))
                    if (imp + clk + cost) > 0:
                        nonzero += 1
                    daily.append(
                        {
                            "date": r.get("date", ""),
                            "ad": ad_type,
                            "campaign": cid,
                            "imp":  imp,
                            "clk":  clk,
                            "cost": cost,
                            "conv": conv,
                            "rev":  rev,
                        }
                    )
            except Exception as e:
                print(f"    ! 캠페인 {cid} 구간 {ci}/{len(chunks)} stats 실패: {e}")
    print(f"    일자×캠페인 {len(daily)}건 (실데이터가 있는 행 {nonzero}건)")

    # 4-2) 키워드 최근 30일 성과 (대시보드의 TOP/BOTTOM 테이블용)
    print(f"  · [{name}] 키워드 성과 수집...")
    kw_daily = []
    kw_since = (end - timedelta(days=29)).isoformat()
    kw_time_range = json.dumps({"since": kw_since, "until": str(end)}, ensure_ascii=False)
    kw_fields = json.dumps(
        ["impCnt", "clkCnt", "salesAmt", "ccnt", "convAmt", "ctr", "cpc", "avgRnk"],
        ensure_ascii=False,
    )
    rank_acc = {}  # kwid -> [sum(avgRnk*imp), sum(imp)]
    # 키워드는 광고그룹별로 묶어서 조회 (/stats?ids=[...])
    ag_to_ad = {a["nccAdgroupId"]: _map_ad_type(cmp_lookup.get(a.get("nccCampaignId"), {}).get("campaignTp")) for a in adgroups}
    # 키워드 id → (keyword string, ad type)
    kw_lookup = {
        k["nccKeywordId"]: (k.get("keyword", ""), ag_to_ad.get(k.get("nccAdgroupId"), "powerlink"))
        for k in keywords
    }
    # /stats는 keyword ID의 ids 배열 조회를 제한적으로만 지원하므로
    # 한 개씩 단일 id로 순회(안정적). 79~수백 개까지는 체감 무리 없음.
    ids_all = list(kw_lookup.keys())
    total = len(ids_all)
    for i, kwid in enumerate(ids_all, start=1):
        if i % 20 == 0 or i == total:
            print(f"    키워드 stats 진행 {i}/{total}")
        try:
            stat = _get(
                "/stats",
                acct,
                {
                    "id": kwid,
                    "fields": kw_fields,
                    "timeRange": kw_time_range,
                    "breakdown": "day",
                },
            )
            for r in _parse_stats(stat):
                kw_str, ad_type = kw_lookup[kwid]
                _imp = int(float(r.get("impCnt", 0) or 0))
                _rnk = float(r.get("avgRnk", 0) or 0)
                if _imp > 0 and _rnk > 0:
                    acc = rank_acc.setdefault(kwid, [0.0, 0])
                    acc[0] += _rnk * _imp
                    acc[1] += _imp
                kw_daily.append(
                    {
                        "date": r.get("date", ""),
                        "kw": kw_str,
                        "ad": ad_type,
                        "imp":  int(float(r.get("impCnt", 0) or 0)),
                        "clk":  int(float(r.get("clkCnt", 0) or 0)),
                        "cost": int(float(r.get("salesAmt", 0) or 0)),
                        "conv": int(float(r.get("ccnt", 0) or 0)),
                        "rev":  int(float(r.get("convAmt", 0) or 0)),
                    }
                )
        except Exception as e:
            # 개별 키워드 실패는 조용히 스킵 (대부분 일시중지/삭제된 키워드)
            pass

    # 4-3) 이벤트 로그 (소재 교체 = editTm)
    events = []
    cutoff = (end - timedelta(days=days - 1)).isoformat()
    for a in ads:
        edit_tm = (a.get("editTm") or "")[:10]
        reg_tm  = (a.get("regTm")  or "")[:10]
        ad_obj = a.get("ad") or {}
        headline = (ad_obj.get("headline") or ad_obj.get("subject") or "").strip()
        campaign_id = a.get("nccCampaignId")
        ad_type = _map_ad_type(cmp_lookup.get(campaign_id, {}).get("campaignTp"))
        if edit_tm and edit_tm >= cutoff and edit_tm != reg_tm:
            events.append(
                {
                    "date": edit_tm,
                    "type": "creative",
                    "ad": ad_type,
                    "title": f"{ad_type} 소재 수정",
                    "detail": (headline[:60] + ("…" if len(headline) > 60 else "")) or "소재 수정",
                }
            )
        elif reg_tm and reg_tm >= cutoff:
            events.append(
                {
                    "date": reg_tm,
                    "type": "creative",
                    "ad": ad_type,
                    "title": f"{ad_type} 소재 신규 등록",
                    "detail": (headline[:60] + ("…" if len(headline) > 60 else "")) or "소재 등록",
                }
            )
    # 일자 내림차순 정렬
    events.sort(key=lambda x: x["date"])

    # 4-4) 소재·키워드 원본 목록 (대시보드의 전체 목록 뷰용)
    ag_name = {ag["nccAdgroupId"]: ag.get("name", "") for ag in adgroups}
    ads_list = []
    for a in ads:
        ad_obj = a.get("ad") or {}
        head = (ad_obj.get("headline") or ad_obj.get("subject") or "").strip()
        desc = (
            ad_obj.get("description")
            or " / ".join(
                x for x in [ad_obj.get("description1"), ad_obj.get("description2")] if x
            )
            or ""
        ).strip()
        agid = a.get("nccAdgroupId")
        ads_list.append(
            {
                "id": a.get("nccAdId"),
                "adgroup": agid,
                "adgroupName": ag_name.get(agid, ""),
                "ad": _map_ad_type(cmp_lookup.get(a.get("nccCampaignId"), {}).get("campaignTp")),
                "status": a.get("status") or a.get("inspectStatus") or "",
                "headline": head,
                "description": desc,
                "regTm": (a.get("regTm") or "")[:19],
                "editTm": (a.get("editTm") or "")[:19],
            }
        )

    kw_list = []
    for k in keywords:
        agid = k.get("nccAdgroupId")
        kw_list.append(
            {
                "id": k.get("nccKeywordId"),
                "keyword": k.get("keyword", ""),
                "adgroup": agid,
                "adgroupName": ag_name.get(agid, ""),
                "ad": ag_to_ad.get(agid, "powerlink"),
                "bidAmt": k.get("bidAmt"),
                "useCustomBid": bool(k.get("useGroupBidAmt") is False),
                "status": k.get("status") or k.get("inspectStatus") or "",
            }
        )

    # 4-5) 키워드도구(검색량·경쟁도·연관키워드) + 평균노출순위 결합
    print(f"  · [{name}] 키워드도구(검색량·경쟁도) 수집...")
    try:
        vol_map, kw_opps = fetch_keyword_tool(acct, [k.get("keyword", "") for k in keywords])
    except Exception as e:
        print(f"    ! 키워드도구 전체 실패: {e}")
        vol_map, kw_opps = {}, []
    print(f"    검색량 매칭 {len(vol_map)}개 · 연관키워드 후보 {len(kw_opps)}개")

    # 키워드별 평균노출순위(노출가중)
    kw_rank = {}
    for kwid, (rsum, isum) in rank_acc.items():
        if isum > 0:
            kw_rank[kwid] = round(rsum / isum, 1)

    for item in kw_list:
        v = vol_map.get(_nospace(item.get("keyword", "")))
        if v:
            item["monthlyPc"] = v["pc"]
            item["monthlyMobile"] = v["mobile"]
            item["monthlyTotal"] = v["total"]
            item["compIdx"] = v["comp"]
            item["plAvgDepth"] = v["depth"]
        r = kw_rank.get(item.get("id"))
        if r:
            item["avgRnk"] = r

    return {
        "meta": {
            "account": name,
            "customerId": str(acct["customerId"]),
            "fetchedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "rangeStart": str(start),
            "rangeEnd":   str(end),
            "campaignCount": len(campaigns),
            "keywordCount":  len(keywords),
            "creativeCount": len(ads),
            "hasKeywordTool": bool(vol_map or kw_opps),
        },
        "daily": daily,
        "kwDaily": kw_daily,
        "events": events,
        "adsList": ads_list,
        "keywordsList": kw_list,
        "kwOpportunities": kw_opps,
    }


# ────────────────────────────────────────────────
# 5. 메인 (전체 계정 루프)
# ────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="네이버 검색광고 API 데이터 수집")
    parser.add_argument("--days", type=int, default=365, help="최근 N일치 수집 (기본 365일 = 1년)")
    parser.add_argument("--config", default="accounts.json", help="계정 설정 파일 경로")
    parser.add_argument("--out", default="data", help="출력 디렉토리")
    args = parser.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"❌ {cfg_path}가 없습니다. accounts.sample.json을 복사해서 채워 주세요.")
        sys.exit(1)

    try:
        accounts = json.loads(cfg_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"❌ {cfg_path} JSON 형식 오류: {e}")
        sys.exit(1)

    if not isinstance(accounts, list) or not accounts:
        print("❌ accounts.json은 계정 객체의 배열이어야 합니다.")
        sys.exit(1)

    out_dir = Path(args.out)
    out_dir.mkdir(exist_ok=True)

    print(f"▶ {len(accounts)}개 계정, 최근 {args.days}일치 수집 시작")
    account_list = []
    for acct in accounts:
        # 필수 필드 체크
        missing = [k for k in ("name", "customerId", "apiKey", "secretKey") if not acct.get(k)]
        if missing:
            print(f"  ✗ 계정 설정 누락 필드: {missing} — 건너뜀")
            continue

        try:
            data = fetch_account(acct, days=args.days)
            out_file = out_dir / f"{acct['customerId']}.json"
            out_file.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            account_list.append(
                {
                    "id": str(acct["customerId"]),
                    "name": acct["name"],
                    "customerId": str(acct["customerId"]),
                    "status": "ok",
                    "updatedAt": data["meta"]["fetchedAt"],
                }
            )
            print(
                f"  ✓ [{acct['name']}] 완료 — 일자×캠페인 {len(data['daily'])}건, "
                f"키워드 {len(data['kwDaily'])}건, 이벤트 {len(data['events'])}건"
            )
        except Exception as e:
            print(f"  ✗ [{acct.get('name')}] 실패: {e}")
            account_list.append(
                {
                    "id": str(acct.get("customerId", "?")),
                    "name": acct.get("name", "unknown"),
                    "customerId": str(acct.get("customerId", "?")),
                    "status": "err",
                    "error": str(e)[:200],
                }
            )

    (out_dir / "accounts.json").write_text(
        json.dumps(account_list, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # bundle.js — 대시보드가 file:// 에서 열려도 로드 가능하도록
    # 모든 계정 데이터를 하나의 JS 파일로 묶어 전역 변수에 주입한다.
    bundle = {
        "generatedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "accounts": account_list,
        "data": {},
    }
    for a in account_list:
        if a["status"] != "ok":
            continue
        json_path = out_dir / f"{a['customerId']}.json"
        if json_path.exists():
            try:
                bundle["data"][a["customerId"]] = json.loads(
                    json_path.read_text(encoding="utf-8")
                )
            except Exception as e:
                print(f"    ! bundle 합치기 중 {a['customerId']} 건너뜀: {e}")

    (out_dir / "bundle.js").write_text(
        "window.NAVER_ADS_BUNDLE = "
        + json.dumps(bundle, ensure_ascii=False)
        + ";\n",
        encoding="utf-8",
    )

    ok = sum(1 for a in account_list if a["status"] == "ok")
    err = sum(1 for a in account_list if a["status"] == "err")
    print(f"\n▶ 전체 종료 — 성공 {ok} · 실패 {err}")
    print(f"   대시보드 HTML을 새로고침하면 상단 스위처에 반영됩니다.")


if __name__ == "__main__":
    main()
