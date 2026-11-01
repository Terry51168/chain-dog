# -*- coding: utf-8 -*-
"""链上甄选 · 金狗雷达（付费模块）

叠加在「链上警犬」之上：警犬负责排雷（防御），本模块负责找金狗（进攻）。
两者共用同一套取数与会话，不重复造轮子。

分层与主程序一致：
    配置 → 取数 → 门槛/打分 → 渲染 → 会员 → 扫描/推送 → 路由/指令

接入方式（二选一）：
    A. 并入单文件：把本文件整段贴到 app.py 的「九、HTTP 层」之前，
       然后在 handle_message 里加一行 handle_selection_command(...)，
       在 app 上调用 selection_routes(app)。
    B. 独立模块：bot/selection.py，启动时 selection.bind(app_module)。

设计约束（与主程序一致，改代码前先读）：
  1. 门槛（gate）与打分（score）分离：gate 只做"一票否决"，score 只做"排序"。
  2. 取数失败一律返回空值，绝不因为上游抖动把一枚好币判死。
  3. "查不到"不等于"安全"也不等于"危险"：未知只扣分，不拦截新币。
  4. 所有推送必须带失效条件 —— 卖的是情报，不是财富密码。
"""

import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import requests

try:  # 并入 app.py 时已经导入过，独立运行时自己补上
    from flask import jsonify, request
except Exception:  # pragma: no cover
    jsonify = request = None


# ======================================================================
# 〇、绑定主程序（单文件并入时无需 bind；独立模块时启动调一次）
# ======================================================================
BOT = None


def bind(mod):
    """复用主程序的连接池 / 线程池 / 发消息函数。

    独立部署时：import selection; selection.bind(app_module)
    并入单文件时：selection.bind(sys.modules[__name__])
    """
    global BOT
    BOT = mod
    return True


_SELF_SESSION = None


def _session():
    if BOT is not None and getattr(BOT, "SESSION", None) is not None:
        return BOT.SESSION
    global _SELF_SESSION
    if _SELF_SESSION is None:
        _SELF_SESSION = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=16)
        _SELF_SESSION.mount("https://", adapter)
        _SELF_SESSION.mount("http://", adapter)
    return _SELF_SESSION


def _executor(name, fallback_workers):
    """借用主程序线程池；独立运行时自建一个。"""
    if BOT is not None:
        ex = getattr(BOT, name, None)
        if ex is not None:
            return ex
    global _POOL
    if "_POOL" not in globals() or _POOL is None:
        from concurrent.futures import ThreadPoolExecutor
        _POOL = ThreadPoolExecutor(max_workers=fallback_workers,
                                   thread_name_prefix="pick")
    return _POOL


_POOL = None


def _now_bj():
    return datetime.now(timezone(timedelta(hours=8)))


def _to_float(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


# ======================================================================
# 一、配置：全部可调参数集中在此
# ======================================================================
# 熔断/门槛：这些是"不满足就别推"的硬条件，不是分数
# 全部走环境变量：调参不该要求重新上传代码 —— 测试期一天要试三组数，
# 每次改代码 + git push + pull + 重启，光流程就能把人耗死。
GATE_MIN_LIQ_USD = int(os.getenv("SELECTION_MIN_LIQ", "15000"))   # 池子太小，进得去出不来
GATE_MIN_AGE_MIN = int(os.getenv("SELECTION_MIN_AGE_MIN", "10"))  # 池龄 <10 分钟还在狙击期，数据全是噪音
GATE_MAX_AGE_DAYS = float(os.getenv("SELECTION_MAX_AGE_DAYS", "30"))   # 老币不叫金狗，叫蓝筹
GATE_MAX_MCAP_USD = float(os.getenv("SELECTION_MAX_MCAP", "150000000"))  # 市值过大已过成长期
GATE_MAX_TAX_PCT = 10.0       # 买卖任一超过 10% 直接淘汰
GATE_MIN_TXNS_24H = int(os.getenv("SELECTION_MIN_TXNS", "50"))    # 24h 交易笔数太少 = 死盘

# 评分权重（合计 100）
W_SAFETY, W_CHIP, W_MOMENTUM, W_FRESH, W_NARRATIVE = 30, 25, 25, 10, 10

# 分级：S 需要"全维度可验证"，数据缺失最多到 A —— 看不见筹码结构就不该给最高分
GRADE_S = int(os.getenv("SELECTION_GRADE_S", "85"))
GRADE_A = int(os.getenv("SELECTION_GRADE_A", "75"))
GRADE_B = int(os.getenv("SELECTION_GRADE_B", "70"))
SELECTION_MIN_SCORE = int(os.getenv("SELECTION_MIN_SCORE", str(GRADE_B)))   # 低于此分不进榜单

# 推送节流
PUSH_INTERVAL_SEC = int(os.getenv("SELECTION_PUSH_INTERVAL", "1800"))  # 30 分钟扫一次
MAX_PUSH_PER_DAY = int(os.getenv("SELECTION_MAX_PUSH_PER_DAY", "6"))
# 影子模式：只记录、不推送。上线头一两周建议开着 —— 先攒样本再调阈值，
# 别拿第一批付费用户当小白鼠。
SHADOW_MODE = os.getenv("SELECTION_SHADOW", "0").strip().lower() in ("1", "true", "yes")
# 同一个币多久内不重复评估。推送期该长（避免重复骚扰），影子期该短（要样本）。
# 所以做成可配：测试期设 2，正式期改回 6。
SEEN_TTL = int(os.getenv("SELECTION_SEEN_TTL_H", "6")) * 3600
# 影子记录落盘路径：没配 Redis 时用它，单机测试期比外部服务更可靠
SHADOW_FILE = os.getenv("SELECTION_SHADOW_FILE", "/opt/chain-dog/shadow.jsonl")

FREE_DELAY_SEC = 2 * 3600     # 免费群延迟 2 小时、只给 3 个 B 级以上
FREE_MAX_PICKS = 3

# GeckoTerminal 网络名 → GoPlus chain_id（None = Solana 走独立接口）
GECKO_CHAIN = {
    "solana": None, "eth": "1", "bsc": "56", "base": "8453",
    "arbitrum": "42161", "polygon_pos": "137", "avax": "43114",
    "optimism": "10",
}
DEFAULT_NETWORKS = [n.strip() for n in
                    os.getenv("SELECTION_NETWORKS", "solana,bsc,base,eth").split(",") if n.strip()]
CHAIN_LABEL = {"1": "ETH", "56": "BSC", "137": "POL", "42161": "ARB",
               "8453": "BASE", "43114": "AVAX", "10": "OP", None: "SOL"}

# 推送目标（逗号分隔的群 ID）；没配就只响应指令、不主动推
PAID_GROUPS = [g.strip() for g in os.getenv("SELECTION_PAID_GROUPS", "").split(",") if g.strip()]
FREE_GROUPS = [g.strip() for g in os.getenv("SELECTION_FREE_GROUPS", "").split(",") if g.strip()]

# 卡密签名密钥（务必改；改了这个之前发的码就全废）
CARD_SECRET = os.getenv("SELECTION_CARD_SECRET", "change-me-please-9f3a")

# 套餐：days=有效天数，price=展示价（仅供文案，不参与计算）
PLANS = {
    "TRIAL": {"label": "7 天体验", "days": 7, "price": "$9.9", "code": "T"},
    "MONTH": {"label": "月卡", "days": 30, "price": "$29", "code": "M"},
    "QUARTER": {"label": "季卡", "days": 90, "price": "$69", "code": "Q"},
    "YEAR": {"label": "年卡", "days": 365, "price": "$199", "code": "Y"},
    "VIP": {"label": "狙击室（月）", "days": 30, "price": "$199", "code": "V"},
}
PLAN_ALIAS = {"T": "TRIAL", "M": "MONTH", "Q": "QUARTER", "Y": "YEAR", "V": "VIP"}


# ======================================================================
# 二、取数：GeckoTerminal（发现）+ DexScreener（补全）+ GoPlus（安全）
# ======================================================================
GECKO_BASE = "https://api.geckoterminal.com/api/v2"


def gecko_pools(network, kind="new_pools", page=1):
    """GeckoTerminal 新池 / 热门池。失败返回 []。

    kind: new_pools | trending_pools | trending_pools?duration=...
    免费额度 30 次/分钟，扫描一轮控制在 8 次以内。
    """
    url = f"{GECKO_BASE}/networks/{network}/{kind}?page={page}"
    try:
        res = _session().get(url, timeout=8,
                             headers={"Accept": "application/json;version=20230302"})
        res.raise_for_status()
        return res.json().get("data") or []
    except Exception as e:
        print(f"[pick] GeckoTerminal {network}/{kind} 异常: {e}")
        return []


def _norm_pool(network, pool):
    """把 GeckoTerminal 的 pool 拍平成候选结构；字段缺失一律给安全默认值。"""
    a = pool.get("attributes") or {}
    rel = pool.get("relationships") or {}

    def _rel_id(key):
        data = (rel.get(key) or {}).get("data") or {}
        return data.get("id") or ""

    base_id = _rel_id("base_token")            # "solana_<mint>"
    addr = base_id.split("_", 1)[-1] if "_" in base_id else base_id
    if not addr:
        return None

    name = a.get("name") or ""                 # "WIF / SOL"
    symbol = name.split("/")[0].strip() or "?"
    created = a.get("pool_created_at") or ""
    age_min = None
    if created:
        try:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age_min = max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 60)
        except Exception:
            age_min = None

    txns = a.get("transactions") or {}
    vol = a.get("volume_usd") or {}
    pc = a.get("price_change_percentage") or {}

    def _tx(bucket):
        d = txns.get(bucket) or {}
        return int(_to_float(d.get("buys"))), int(_to_float(d.get("sells"))), \
            int(_to_float(d.get("buyers"))), int(_to_float(d.get("sellers")))

    b24, s24, buyers24, sellers24 = _tx("h24")
    return {
        "network": network,
        "chain_id": GECKO_CHAIN.get(network),
        "addr": addr,
        "pool_addr": a.get("address") or "",
        "symbol": symbol[:18],
        "name": name,
        "price": _to_float(a.get("base_token_price_usd")),
        "liq": _to_float(a.get("reserve_in_usd")),
        "fdv": _to_float(a.get("fdv_usd")),
        "mcap": _to_float(a.get("market_cap_usd")),
        "age_min": age_min,
        "vol24": _to_float(vol.get("h24")),
        "vol1h": _to_float(vol.get("h1")),
        "pc5m": _to_float(pc.get("m5")),
        "pc1h": _to_float(pc.get("h1")),
        "pc6h": _to_float(pc.get("h6")),
        "pc24h": _to_float(pc.get("h24")),
        "buys24": b24, "sells24": s24,
        "buyers24": buyers24, "sellers24": sellers24,
        "dex": ((pool.get("relationships") or {}).get("dex") or {}).get("data", {}).get("id", ""),
        "pair_url": f"https://www.geckoterminal.com/{network}/pools/{a.get('address', '')}",
        "source": "gecko",
    }


def dexscreener_enrich(cand):
    """用 DexScreener 的 pair 补全社交信息 / boost / 更准的链上标签。

    取数失败不影响主流程：这些只影响「叙事分」，不参与门槛。
    """
    addr = cand["addr"]
    fn = None
    if BOT is not None:
        fn = getattr(BOT, "dexscreener_pairs", None)
    pairs = []
    if fn:
        try:
            pairs = fn(addr, "SOL" if cand.get("chain_id") is None else "EVM")
        except TypeError:                      # 主程序签名没有 tag 参数时退回单参调用
            pairs = fn(addr)
    if not pairs:
        try:
            res = _session().get(
                f"https://api.dexscreener.com/latest/dex/tokens/{addr}", timeout=5)
            res.raise_for_status()
            pairs = res.json().get("pairs") or []
        except Exception:
            pairs = []
    if not pairs:
        return cand
    own = [p for p in pairs
           if (p.get("baseToken") or {}).get("address", "").lower() == addr.lower()] or pairs
    best = max(own, key=lambda p: _to_float((p.get("liquidity") or {}).get("usd")))
    info = best.get("info") or {}
    cand["websites"] = [w.get("url") for w in (info.get("websites") or []) if w.get("url")]
    cand["socials"] = [s.get("type") for s in (info.get("socials") or []) if s.get("type")]
    cand["has_desc"] = bool((info.get("description") or "").strip())
    cand["boost"] = bool((best.get("boosts") or {}).get("active"))
    cand["pair_url"] = best.get("url") or cand.get("pair_url")
    if best.get("fdv"):
        cand["fdv"] = _to_float(best.get("fdv"))
    if best.get("marketCap"):
        cand["mcap"] = _to_float(best.get("marketCap"))
    if best.get("pairCreatedAt") and cand.get("age_min") is None:
        cand["age_min"] = max(0.0, (time.time() * 1000 - _to_float(best["pairCreatedAt"])) / 60000)
    return cand


def goplus_security(cand):
    """复用主程序的 GoPlus 取数；独立运行时自己发一次。失败返回 {}。"""
    cid, addr = cand["chain_id"], cand["addr"]
    try:
        if BOT is not None:
            if cid is None:
                fn = getattr(BOT, "goplus_solana", None)
                return (fn(addr) if fn else {}) or {}
            fn = getattr(BOT, "goplus_evm", None)
            return (fn(cid, addr) if fn else {}) or {}
        if cid is None:
            url = f"https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses={addr}"
            data = _session().get(url, timeout=6).json()
            return ((data.get("result") or {}).get(addr) or {}) if data.get("code") == 1 else {}
        url = f"https://api.gopluslabs.io/api/v1/token_security/{cid}?contract_addresses={addr}"
        data = _session().get(url, timeout=6).json()
        if data.get("code") == 1:
            return ((data.get("result") or {}).get(addr.lower()) or {})
    except Exception as e:
        print(f"[pick] GoPlus 异常 {addr[:10]}: {e}")
    return {}


# ======================================================================
# 三、判定：门槛（一票否决）→ 打分（排序）
# ======================================================================
BURN_ADDRS = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}

# 独立运行（未 bind 主程序）时的锚定币兜底：这些增发是 1:1 储备机制，不算后门。
# bind 之后一律以主程序的 KNOWN_PEGGED 为准，这张表只是防止单测/离线时误杀稳定币。
_PEGGED_FALLBACK = {
    "56": {"0x55d398326f99059ff775485246999027b3197955",   # USDT
           "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",   # USDC
           "0xe9e7cea3dedca5984780bafc599bd69add087d56"},  # BUSD
    "1": {"0xdac17f958d2ee523a2206206994597c13d831ec7",    # USDT
          "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",    # USDC
          "0x6b175474e89094c44da98b954eedeac495271d0f"},   # DAI
    "8453": {"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"},  # USDC
    "42161": {"0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"},  # USDT
}


def _pegged(chain_id):
    if BOT is not None:
        return getattr(BOT, "KNOWN_PEGGED", {}).get(chain_id, set())
    return _PEGGED_FALLBACK.get(chain_id, set())


def _own_lp_lock(info):
    """返回 (锁仓比例 或 None, 是否已销毁)。0% 锁仓不等于可撤池，统一按"无法判定"。"""
    holders = info.get("lp_holders") or []
    if not holders:
        return None, False
    locked = 0.0
    burned = False
    for h in holders:
        pct = _to_float(h.get("percent")) * 100
        if (h.get("address") or "").lower() in BURN_ADDRS:
            burned = True
            locked += pct
        elif str(h.get("is_locked")) == "1":
            locked += pct
    if locked <= 0:
        return None, burned
    return min(locked, 100.0), burned


def hard_gate(cand, info):
    """一票否决。返回 (通过?, 原因)。只拦"明确有害"，不拦"未知"。"""
    liq = cand.get("liq") or 0
    if liq < GATE_MIN_LIQ_USD:
        return False, f"池子仅 ${liq:,.0f}"
    age = cand.get("age_min")
    if age is not None and age < GATE_MIN_AGE_MIN:
        return False, f"池龄 {age:.0f} 分钟，尚在狙击期"
    if age is not None and age > GATE_MAX_AGE_DAYS * 1440:
        return False, f"池龄超过 {GATE_MAX_AGE_DAYS:.0f} 天，已过成长期"
    mcap = cand.get("mcap") or cand.get("fdv") or 0
    if mcap > GATE_MAX_MCAP_USD:
        return False, f"市值 {mcap/1e6:.0f}M，已非早期标的"
    if (cand.get("buys24", 0) + cand.get("sells24", 0)) < GATE_MIN_TXNS_24H:
        return False, "24h 交易过少"

    if cand["chain_id"] is None:                     # ---------- Solana ----------
        if (info.get("mintable") or {}).get("status") == "1":
            return False, "Mint 权限未放弃"
        if (info.get("freezable") or {}).get("status") == "1":
            return False, "Freeze 权限未放弃"
        return True, ""

    # ---------- EVM ----------
    if str(info.get("is_honeypot") or "") == "1":
        return False, "貔貅盘"
    if str(info.get("is_open_source") or "") == "0":
        return False, "合约未开源，无法评估"
    if _to_float(info.get("buy_tax")) * 100 > GATE_MAX_TAX_PCT or \
            _to_float(info.get("sell_tax")) * 100 > GATE_MAX_TAX_PCT:
        return False, "税率超过 10%"
    for key, label in (("owner_change_balance", "可改余额"),
                       ("hidden_owner", "隐藏 Owner"),
                       ("can_take_back_ownership", "可收回权限"),
                       ("is_blacklisted", "带黑名单功能")):
        if str(info.get(key) or "") == "1":
            return False, label
    if str(info.get("is_mintable") or "") == "1":
        if cand["addr"].lower() not in _pegged(cand["chain_id"]):
            return False, "可无限增发"
    if _creator_is_bad(info, cand["chain_id"]):
        return False, "创建者有前科"
    return True, ""


_MALICIOUS_FLAGS = ["phishing_activities", "stealing_attack", "cybercrime",
                    "money_laundering", "blackmail_activities"]


_FLAG_CACHE = {}
_FLAG_LOCK = threading.Lock()
_FLAG_TTL = 6 * 3600


def _addr_has_bad_flags(addr, chain_id):
    """创建者/Owner 是否有前科。带 6 小时缓存 —— 一个部署者往往发几十个盘，
    不缓存的话一轮扫描要多打几十次 GoPlus。查不到按"无前科"处理，不误杀。"""
    now = time.time()
    with _FLAG_LOCK:
        hit = _FLAG_CACHE.get(addr)
        if hit and now - hit[0] < _FLAG_TTL:
            return hit[1]
    bad = False
    try:
        fn = getattr(BOT, "goplus_address_security", None) if BOT is not None else None
        if fn:
            r = fn(addr, chain_id) or {}
            if r.get("data_source"):        # 有真实索引才采信，默认值不算数
                flags = getattr(BOT, "MALICIOUS_FLAGS", None) or _MALICIOUS_FLAGS
                bad = any(str(r.get(f)) == "1" for f in flags)
    except Exception:
        bad = False
    with _FLAG_LOCK:
        if len(_FLAG_CACHE) > 20000:
            _FLAG_CACHE.clear()
        _FLAG_CACHE[addr] = (now, bad)
    return bad


def _creator_is_bad(info, chain_id):
    """创建者/Owner 涉黑一票否决。"""
    if BOT is None:
        return False
    seen = set()
    for role in ("creator_address", "owner_address"):
        a = (info.get(role) or "").lower()
        if not a.startswith("0x") or a in seen:
            continue
        seen.add(a)
        if _addr_has_bad_flags(a, chain_id):
            return True
    return False


def _holders_split(info, chain_id, exclude=None):
    """拆前 10 持仓里的 个人(EOA) / 合约 占比。合约多为池子/金库，不算砸盘风险。

    exclude：本项目主池地址。Solana 的头号持仓通常就是池子本身，
    不排掉会把每个 Solana 币都算成"个人巨鲸控盘"。

    优先用 GoPlus 返回里自带的 is_contract："0"/"1"，实测普通代币都带这个字段。
    只有缺失时才回落到 classify_holder —— 那是一次额外网络请求，能省则省。
    """
    skip = set(BURN_ADDRS) | ({exclude.lower()} if exclude else set())
    holders = [(h.get("address", "").lower(), _to_float(h.get("percent")) * 100,
                str(h.get("is_contract")))
               for h in (info.get("holders") or [])[:10]]
    holders = [h for h in holders if h[0] not in skip]
    top10 = sum(p for _, p, _ in holders)

    contract_pct = 0.0
    unknown = []
    for a, p, ic in holders:
        if ic == "1":
            contract_pct += p
        elif ic == "0":
            continue
        else:
            unknown.append((a, p))
    classify = getattr(BOT, "classify_holder", None) if BOT is not None else None
    if classify and chain_id and unknown:
        try:
            for a, p in unknown[:3]:          # 字段缺失时最多补判 3 个，控制耗时
                if classify(a, chain_id).get("is_contract"):
                    contract_pct += p
        except Exception:
            pass
    return top10, max(0.0, top10 - contract_pct), contract_pct


def score(cand, info):
    """五维打分，返回 (总分, 维度字典, 标签)。维度满分合计 100。"""
    reasons, warns, unknowns = [], [], []

    # ---------- 1. 安全 30 ----------
    safety = W_SAFETY
    if cand["chain_id"] is None:
        fatal = {"mintable": "Mint", "freezable": "Freeze"}
        for k in fatal:
            if (info.get(k) or {}).get("status") == "":
                safety -= 2
                unknowns.append(fatal[k])
        if (info.get("closable") or {}).get("status") == "1":
            safety -= 3
            warns.append("Close 未弃")
    else:
        tax = _to_float(info.get("buy_tax")) * 100 + _to_float(info.get("sell_tax")) * 100
        if tax > 8:
            safety -= 7
            warns.append(f"税率 {tax:.1f}%")
        elif tax > 5:
            safety -= 4
            warns.append(f"税率 {tax:.1f}%")
        for key, label in (("transfer_pausable", "可暂停交易"),
                           ("is_whitelisted", "白名单限制"),
                           ("is_proxy", "代理合约")):
            if str(info.get(key) or "") == "1":
                safety -= 3
                warns.append(label)
        if str(info.get("self_destruct") or "") == "1":
            safety -= 3
            warns.append("可自毁")
        if str(info.get("is_open_source") or "") == "":
            safety -= 2
            unknowns.append("开源")
    safety = max(0, safety)

    # ---------- 2. 筹码 25 ----------
    # 关键原则：看不见筹码结构 ≠ 筹码健康。数据缺失一律压到中位以下，
    # 且不再叠加 LP/持有人加分 —— 否则"没数据"反而比"数据一般"得分高。
    top10, eoa_pct, contract_pct = _holders_split(info, cand["chain_id"],
                                                 cand.get("pool_addr") or cand.get("addr"))
    lock, burned = _own_lp_lock(info)
    if top10 <= 0:
        chip = 8
        unknowns.append("筹码分布")
    else:
        if eoa_pct <= 15:
            chip = 10
        elif eoa_pct <= 25:
            chip = 8
        elif eoa_pct <= 35:
            chip = 6
        elif eoa_pct <= 45:
            chip = 4
        elif eoa_pct <= 55:
            chip = 2
        else:
            chip = 0
        if eoa_pct > 50:
            warns.append(f"个人持仓 {eoa_pct:.0f}%")
        if burned:
            chip += 8
            reasons.append("LP 已销毁")
        elif lock is None:
            chip += 5
        elif lock >= 90:
            chip += 8
            reasons.append(f"LP 锁 {lock:.0f}%")
        elif lock >= 50:
            chip += 6
            reasons.append(f"LP 锁 {lock:.0f}%")
        elif lock >= 20:
            chip += 4
        else:
            chip += 2
            warns.append("LP 锁定率低")
        hc = int(_to_float(info.get("holder_count")))
        if hc >= 2000:
            chip += 7
        elif hc >= 800:
            chip += 6
        elif hc >= 300:
            chip += 5
        elif hc >= 100:
            chip += 3
        elif hc > 0:
            chip += 1
        else:
            chip += 4
    chip = min(W_CHIP, chip)

    # ---------- 3. 动量 25 ----------
    liq = max(cand.get("liq") or 0, 1.0)
    turnover = (cand.get("vol24") or 0) / liq
    if turnover < 0.3:
        mom = 1
    elif turnover < 0.8:
        mom = 4
    elif turnover < 1.5:
        mom = 7
    elif turnover <= 3:
        mom = 10
        reasons.append(f"换手 {turnover:.1f}x")
    elif turnover <= 8:
        mom = 9
        reasons.append(f"换手 {turnover:.1f}x")
    else:
        mom = 6
        warns.append("换手异常（疑似刷量）")
    # 换手 20 倍以上基本只有一种解释：机器人对倒刷量。
    # 这种池子的成交量是假的，用它判断"有人接盘"会得出完全相反的结论。
    if turnover > 30:
        mom = max(0, mom - 6)
        warns.append(f"换手 {turnover:.0f}x，疑似机器人对倒")
    elif turnover > 20:
        mom = max(0, mom - 3)
        warns.append(f"换手 {turnover:.0f}x，成交异常")

    buys, sells = cand.get("buys24") or 0, cand.get("sells24") or 0
    ratio = buys / max(sells, 1)
    if ratio >= 1.5:
        mom += 6
        reasons.append(f"买盘 {ratio:.1f}:1")
    elif ratio >= 1.1:
        mom += 5
    elif ratio >= 0.9:
        mom += 3
    else:
        mom += 1
        warns.append("卖盘占优")

    buyers = cand.get("buyers24") or 0
    if buyers >= 800:
        mom += 5
        reasons.append(f"24h 独立买家 {buyers:,}")
    elif buyers >= 300:
        mom += 4
    elif buyers >= 100:
        mom += 2

    # 过热惩罚：追高是散户亏钱的第一原因，涨太快反而降分
    pc1h = cand.get("pc1h") or 0
    if pc1h > 200:
        mom += 0
        warns.append("1h 已涨超 200%，追高风险")
    elif pc1h > 80:
        mom += 2
        warns.append(f"1h +{pc1h:.0f}%，已启动")
    elif pc1h >= -10:
        mom += 4
    elif pc1h >= -30:
        mom += 2
    else:
        mom += 0
        warns.append(f"1h {pc1h:.0f}%，可能破位")

    # 24h 涨幅单独扣分：只看 1h 会漏掉"横盘一天翻十倍"的币。
    # 这类币的 1h 可能只涨 20%，但整体已经垂直，进场就是接最后一棒。
    pc24h = cand.get("pc24h") or 0
    if pc24h > 1000:
        mom -= 9
        warns.append(f"24h +{pc24h:.0f}%，垂直拉升")
    elif pc24h > 500:
        mom -= 6
        warns.append(f"24h +{pc24h:.0f}%，涨幅过大")
    elif pc24h > 300:
        mom -= 3
        warns.append(f"24h +{pc24h:.0f}%，短线过热")

    # 跌也要扣：24 小时阴跌说明进场资金已经在撤，这时候推出去是让人接货
    if pc24h < -50:
        mom -= 6
        warns.append(f"24h {pc24h:.0f}%，下跌趋势")
    elif pc24h < -25:
        mom -= 3
        warns.append(f"24h {pc24h:.0f}%，已走弱")
    momentum = max(0, min(W_MOMENTUM, mom))

    # ---------- 4. 新鲜度 10 ----------
    age = cand.get("age_min")
    if age is None:
        fresh = 5
    elif age < 60:
        fresh = 4
        warns.append("池龄不足 1 小时")
    elif age < 360:
        fresh = 9
    elif age < 1440:
        fresh = 10
        reasons.append(f"池龄 {age/60:.1f}h")
    elif age < 4320:
        fresh = 7
    elif age < 10080:
        fresh = 4
    else:
        fresh = 2

    # ---------- 5. 叙事 10 ----------
    narr = 0.0
    if cand.get("websites"):
        narr += 3
    if cand.get("socials"):
        narr += 3
        if "twitter" in [str(s).lower() for s in cand["socials"]]:
            reasons.append("有官方推特")
    if cand.get("has_desc"):
        narr += 2
    if cand.get("boost"):
        narr += 1.5
    sym = (cand.get("symbol") or "").lower()
    if 2 <= len(sym) <= 10 and not re.search(r"token|finance|swap|coin|dao", sym):
        narr += 1.5
    narrative = min(W_NARRATIVE, round(narr))

    total = int(round(safety + chip + momentum + fresh + narrative))
    dims = {"safety": safety, "chip": chip, "momentum": momentum,
            "fresh": fresh, "narrative": narrative}
    return total, dims, {"reasons": reasons, "warns": warns, "unknowns": unknowns,
                         "top10": top10, "eoa_pct": eoa_pct,
                         "contract_pct": contract_pct, "lp_lock": lock, "burned": burned}


def grade_of(total):
    if total >= GRADE_S:
        return "S"
    if total >= GRADE_A:
        return "A"
    if total >= GRADE_B:
        return "B"
    return "C"


GRADE_RANK = {"C": 0, "B": 1, "A": 2, "S": 3}


def at_least(c, grade="A"):
    """按**等级**过滤，不是按分数。

    等级上限（grade_cap）就是为了压住那些分数很高但结构有缺陷的币。
    如果推送时又拿 score 筛，上限就白设了 —— 被压成 B 的币照样会被推出去。
    """
    return GRADE_RANK.get(c.get("grade", "C"), 0) >= GRADE_RANK[grade]


def grade_cap(ctx, cand):
    """评级上限：分数是排序，等级是承诺强度。

    把所有触发条件都算一遍，取最严的一条 —— 不用 early-return。
    早期版本命中第一条就 return，于是"24h 涨 197% → A"会先返回，
    把后面"池子只有 $31K → B"整条规则盖掉：一个更严重的缺陷被一个较轻的掩盖了。
    """
    bad, warn = [], []

    def lim(bucket, why):
        bucket.append(why)

    if ctx.get("eoa_pct", 0) > 50:
        lim(bad, "个人持仓>50%")
    if (cand.get("pc1h") or 0) > 150:
        lim(bad, "1h 涨超 150%")

    # 池子太薄：几万美元就能把盘砸穿，这种深度不配"推荐"两个字
    liq = cand.get("liq") or 0
    if liq < 50000:
        lim(bad, f"池子 ${liq/1000:.0f}K")
    elif liq < 100000:
        lim(warn, f"池子 ${liq/1000:.0f}K")

    # 看不见筹码 = 判断不了砸盘风险。分数可以高，但等级不能是强承诺
    if "持仓" in (ctx.get("unknowns") or []):
        lim(bad, "筹码数据缺失")

    pc24 = cand.get("pc24h") or 0
    if pc24 > 300 or pc24 < -20:
        lim(bad, f"24h {pc24:+.0f}%")
    elif pc24 > 150 or pc24 < -10:
        lim(warn, f"24h {pc24:+.0f}%")

    turn = (cand.get("vol24") or 0) / max(liq or 1.0, 1.0)
    if turn > 30:
        lim(bad, f"换手 {turn:.0f}x")
    elif turn > 20:
        lim(warn, f"换手 {turn:.0f}x")

    if ctx.get("top10", 0) > 0 and ctx.get("lp_lock") is None \
            and not ctx.get("burned") and ctx.get("eoa_pct", 0) > 40:
        lim(bad, "LP 未锁且筹码集中")

    # 把触发原因记在 ctx 上：用户看到"89 分却是 B"必须能当场知道为什么，
    # 否则只会觉得评分乱来。这也是客服解释"为什么这个币没进推送"的依据。
    ctx["cap"] = bad or warn
    return "B" if bad else ("A" if warn else "S")


def capped_grade(total, ctx, cand):
    g = grade_of(total)
    cap = grade_cap(ctx, cand)
    return cap if GRADE_RANK[g] > GRADE_RANK[cap] else g


def invalidations(cand, ctx):
    """失效条件：告诉用户"什么时候该走"。这是和喊单号最大的区别。"""
    out = []
    if ctx.get("burned"):
        out.append("开发方从 LP 地址撤出流动性")
    elif ctx.get("lp_lock"):
        out.append(f"LP 锁仓跌破 {max(0, ctx['lp_lock'] * 0.6):.0f}% 或解锁")
    else:
        out.append("LP 出现大额撤池")
    if ctx.get("eoa_pct", 0) > 30:
        out.append(f"前 10 个人地址持仓升破 {min(95, ctx['eoa_pct'] + 10):.0f}%")
    out.append("24h 买入笔数连续 2 小时低于卖出笔数")
    out.append("价格较本期参考价回落 35%｜流动性腰斩")
    return out


# ======================================================================
# 四、渲染
# ======================================================================
GRADE_ICON = {"S": "🏆", "A": "🥈", "B": "🥉", "C": "·"}


def _fmt_money(n):
    n = _to_float(n)
    if n >= 1_000_000:
        return f"${n/1_000_000:.2f}M"
    if n >= 1000:
        return f"${n/1000:.1f}K"
    return f"${n:.0f}"


def _fmt_age(m):
    if m is None:
        return "未知"
    if m < 60:
        return f"{m:.0f}分钟"
    if m < 1440:
        return f"{m/60:.1f}小时"
    return f"{m/1440:.1f}天"


def _pct(v):
    v = _to_float(v)
    return f"+{v:.0f}%" if v >= 0 else f"{v:.0f}%"


def render_pick(c, idx=None, detail=True):
    """单币甄选卡。detail=False 时给免费版用（去掉具体理由，留钩子）。"""
    head = f"{GRADE_ICON.get(c['grade'], '·')} {c['grade']} {c['score']}分"
    no = f"{idx}️⃣ " if idx else ""
    top10 = c["ctx"].get("top10", 0)
    if top10 <= 0:
        hold_str = "👥 前10 数据缺失"
    else:
        hold_str = (f"👥 前10 {top10:.0f}%（个人 {c['ctx'].get('eoa_pct', 0):.0f}%）")
    lines = [
        f"{no}${c['symbol']} · {CHAIN_LABEL.get(c['chain_id'], c['network'])} · {head}",
        # 一行最多放 2 个指标：手机宽度下 3 个必然折行，折行后最难读
        f"💰 池子 {_fmt_money(c.get('liq'))}　📊 24h {_pct(c.get('pc24h'))}",
        f"🔄 换手 {(c.get('vol24') or 0)/max(c.get('liq') or 1,1):.1f}x　🕐 池龄 {_fmt_age(c.get('age_min'))}",
        hold_str,
    ]
    if detail:
        rs = c["ctx"].get("reasons") or []
        if rs:
            lines.append(f"⚡ 亮点　{' / '.join(rs[:3])}")
        ws = c["ctx"].get("warns") or []
        if ws:
            lines.append(f"⚠️ 留意　{' / '.join(ws[:3])}")
        cap = c["ctx"].get("cap") or []
        if cap:
            lines.append(f"⛔ 上限　{' / '.join(cap[:2])}")
        lines.append(f"🛑 失效　{'｜'.join(c['invalidations'][:2])}")
        lines.append(f"🔗 {c.get('pair_url', '')}")
    return "\n".join(lines)


def render_digest(picks, title=None, free=False, scanned=0, when=None, delayed=False):
    """一期榜单。免费版只给 3 个且不带理由 —— 让人看见、但看不全。"""
    when = when or _now_bj()
    title = title or f"🏆 链上甄选 · {when.strftime('%m/%d %H:%M')}"
    shown = picks[:FREE_MAX_PICKS] if free else picks
    lines = [title]
    if scanned:
        lines.append(f"本期从 {scanned} 个新池中筛出 {len(picks)} 个"
                     f"（S/A 级优先，全部过安全门槛）")
    lines.append("▱▱▱▱▱▱▱▱▱▱")
    if not shown:
        lines.append("本期无符合标准的标的。宁缺毋滥，等下一个。")
        return "\n".join(lines)
    for i, c in enumerate(shown, 1):
        lines.append(render_pick(c, i, detail=not free))
        if i != len(shown):
            lines.append("")
    lines.append("▱▱▱▱▱▱▱▱▱▱")
    if free:
        # 只有真的用了延迟数据才敢说"延迟 2 小时"。
        # 兜底时给的是实时榜单，文案必须跟着改，否则就是虚假宣传 —— 用户一旦发现，
        # "付费才能拿到最新"这个卖点当场失效。
        tag = "且延迟 2 小时" if delayed else ""
        # 只筛出 2 个时说"仅显示 3 个"，用户会以为被吞了一个 —— 明明是自己筛得严。
        if len(shown) < FREE_MAX_PICKS:
            lines.append(f"🔒 本期免费可见 {len(shown)} 个{tag}，不含失效条件与建仓逻辑。")
        else:
            lines.append(f"🔒 免费版仅显示 {FREE_MAX_PICKS} 个{tag}，不含失效条件与建仓逻辑。")
        lines.append("👉 发送 /订阅 查看完整榜单（实时推送 + 失效提醒 + 战绩回溯）")
    else:
        lines.append("📌 以上为数据筛选结果，非投资建议；仓位自控，严格按失效条件离场。")
    return "\n".join(lines)


# ======================================================================
# 五、会员：卡密 + 到期时间 + 每日额度（Upstash）
# ======================================================================
def _upstash(path, method="POST"):
    url = os.getenv("UPSTASH_REDIS_REST_URL", "") or (getattr(BOT, "UPSTASH_URL", "") if BOT else "")
    token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "") or \
        (getattr(BOT, "UPSTASH_TOKEN", "") if BOT else "")
    if not url or not token:
        return None
    try:
        r = _session().request(method, f"{url}/{path}",
                               headers={"Authorization": f"Bearer {token}"}, timeout=4)
        if r.status_code != 200:
            return None
        return r.json().get("result")
    except Exception as e:
        print(f"[pick] upstash 异常 {path[:40]}: {e}")
        return None


def _redis_ready():
    """Redis 是否配置好。没配的话影子记录、去重、会员校验全部静默失效，
    但服务本身照跑 —— 这种"半残"状态必须能被一眼看见，所以放进 ping。"""
    if BOT is None:
        url = os.getenv("UPSTASH_REDIS_REST_URL", "")
        token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
    else:
        url = os.getenv("UPSTASH_REDIS_REST_URL", "") or getattr(BOT, "UPSTASH_URL", "")
        token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "") or getattr(BOT, "UPSTASH_TOKEN", "")
    return bool(url and token)


def _b32(b):
    return base64.b32encode(b).decode().rstrip("=")


def _unb32(s):
    s = s.upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def issue_code(plan="MONTH", count=1):
    """离线生成卡密：不需要连 Redis，发给代理/客服即可。

    结构：XX + base32(套餐码 1B | 天数 2B | 随机 3B | HMAC 4B)
    """
    plan = PLAN_ALIAS.get(plan, plan)
    spec = PLANS[plan]
    out = []
    for _ in range(count):
        payload = (spec["code"].encode() + int(spec["days"]).to_bytes(2, "big")
                   + os.urandom(3))
        sig = hmac.new(CARD_SECRET.encode(), payload, hashlib.sha256).digest()[:4]
        raw = _b32(payload + sig)
        out.append("XX" + "-".join(raw[i:i + 4] for i in range(0, len(raw), 4)))
    return out


def parse_code(code):
    """校验卡密签名，返回 (plan, days, nonce, 规范码)；非法返回 None。"""
    s = re.sub(r"[^A-Z0-9]", "", (code or "").upper())
    if not s.startswith("XX") or len(s) < 14:
        return None
    try:
        raw = _unb32(s[2:])
    except Exception:
        return None
    if len(raw) != 10:
        return None
    payload, sig = raw[:6], raw[6:]
    if not hmac.compare_digest(sig, hmac.new(CARD_SECRET.encode(), payload, hashlib.sha256).digest()[:4]):
        return None
    code_ch = chr(payload[0])
    days = int.from_bytes(payload[1:3], "big")
    plan = next((k for k, v in PLANS.items() if v["code"] == code_ch), None)
    if not plan or days <= 0 or days > 400:
        return None
    return plan, days, payload[3:].hex(), "XX" + s[2:]


def redeem_code(code, uid):
    """核销：验签 → 查重 → 叠加到期时间。返回 (成功?, 文案)。"""
    parsed = parse_code(code)
    if not parsed:
        return False, "❌ 卡密无效，请检查是否输错（区分大小写请整段复制）"
    plan, days, nonce, canon = parsed
    # 用 INCR 原子抢锁：并发提交同一张卡，只有一个能拿到 1
    claim_key = f"xx:claim:{canon}"
    n = _upstash(f"incr/{claim_key}")
    if n is None:
        return False, "⚠️ 系统繁忙，请稍后重试"
    if int(_to_float(n)) > 1:
        return False, "❌ 这张卡密已经被使用过了"
    _upstash(f"expire/{claim_key}/{60*60*24*400}", "GET")
    _upstash(f"set/xx:owner:{canon}/{uid}")
    now = int(time.time())
    cur = int(_to_float(_upstash(f"get/xx:sub:{uid}", "GET") or 0))
    until = max(now, cur) + days * 86400
    _upstash(f"set/xx:sub:{uid}/{until}/ex/{60*60*24*420}")
    _upstash(f"set/xx:plan:{uid}/{plan}", "GET")
    return True, (f"✅ 激活成功：{PLANS[plan]['label']}（{days} 天）\n"
                  f"📅 有效期至 {datetime.fromtimestamp(until, timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M')}\n"
                  f"发送 /金狗 查看最新甄选榜单")


def sub_until(uid):
    return int(_to_float(_upstash(f"get/xx:sub:{uid}", "GET") or 0))


def is_member(uid):
    if not uid:
        return False
    return sub_until(uid) > time.time()


def quota_used(uid, date_str=None):
    d = date_str or _now_bj().strftime("%Y%m%d")
    return int(_to_float(_upstash(f"get/xx:q:{uid}:{d}", "GET") or 0))


def quota_take(uid, limit=30):
    """按次计费/防刷：返回 True 表示本次可用。"""
    d = _now_bj().strftime("%Y%m%d")
    n = _upstash(f"incr/xx:q:{uid}:{d}")
    if n is None:
        return True                      # 统计不可用时不卡用户
    if int(_to_float(n)) > limit:
        return False
    _upstash(f"expire/xx:q:{uid}:{d}/{86400}", "GET")
    return True


# ======================================================================
# 六、扫描：取数 → 门槛 → 打分 → 排序
# ======================================================================
_SEEN = {}
_SEEN_LOCK = threading.Lock()
_LAST_PICKS = []            # 内存里保留最近一期，供免费版延迟取用
_LAST_PICKS_TS = 0.0
_PUSH_COUNT = {"date": "", "n": 0}
_FREE_LAST = 0.0


def _seen_before(addr, write=True):
    """最近扫过没有。write=False 时只读不写 —— 这一条是必须的。

    手动 /金狗 如果也写标记，用户每查一次就把当场那批币锁死一整个 SEEN_TTL，
    随后的定时任务全部撞"已看过"，推送直接归零。表现出来就是：
    刚 /金狗 推出 2 个，过一会儿 /甄选记录 却显示"本期 0 个"。
    查得越勤，自动推送越哑火 —— 这是最反直觉、也最难自己看出来的一种 bug。
    """
    now = time.time()
    with _SEEN_LOCK:
        ts = _SEEN.get(addr)
        if ts and now - ts < SEEN_TTL:
            return True
        if not write:
            return False
        _SEEN[addr] = now
        if len(_SEEN) > 5000:
            for k, v in list(_SEEN.items()):
                if now - v >= SEEN_TTL:
                    del _SEEN[k]
        return False


def _candidates(networks=None):
    """并发拉取每个网络的新池 + 热门池，去重后返回归一化候选。"""
    nets = networks or DEFAULT_NETWORKS
    jobs = [(n, k) for n in nets for k in ("new_pools", "trending_pools")]
    ex = _executor("SUB_EXECUTOR", 8)
    results = list(ex.map(lambda nk: (nk[0], nk[1], gecko_pools(nk[0], nk[1])), jobs))
    seen, out = set(), []
    for net, _kind, pools in results:
        for p in pools:
            c = _norm_pool(net, p)
            if not c:
                continue
            key = (c["network"], c["addr"].lower())
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
    return out


def evaluate(cand):
    """单币完整评估：安全 → 门槛 → 打分。返回候选（不合格返回 None）。"""
    info = goplus_security(cand)
    cand["info"] = info
    ok, why = hard_gate(cand, info)
    if not ok:
        cand["rejected"] = why
        return None
    if not info:
        # 完全查不到安全数据：新币常见，不判死但压制评分，避免把"未知"当"安全"
        cand["rejected"] = "安全数据缺失"
        return None
    total, dims, ctx = score(cand, info)
    cand.update({"score": total, "dims": dims, "ctx": ctx,
                 "grade": capped_grade(total, ctx, cand),
                 "invalidations": invalidations(cand, ctx)})
    return cand


_LAST_DIAG = {}


def scan_once(networks=None, limit=12, enrich=True, mark=True):
    """扫一轮，返回按分数降序的合格标的。耗时约 5~15 秒（并发）。

    同时把"每个候选卡在哪一层"记进 _LAST_DIAG。甄选最容易出的问题不是打分不准，
    而是某个门槛把所有标的筛光了，外部却只看得到"本期 0 个"。没有这层统计，
    调阈值就是盲改，改完也不知道是变好了还是变差了。
    """
    global _LAST_DIAG
    raw = _candidates(networks)
    scanned = len(raw)
    rejects = {}

    def _drop(reason):
        rejects[reason] = rejects.get(reason, 0) + 1

    # 先做便宜的门槛（流动性/池龄/交易数），把 80% 垃圾挡在 GoPlus 之前，省配额
    pre = []
    for c in raw:
        if (c.get("liq") or 0) < GATE_MIN_LIQ_USD:
            _drop("池子过小")
        elif c.get("age_min") is not None and c["age_min"] < GATE_MIN_AGE_MIN:
            _drop("池龄过短")
        elif (c.get("buys24", 0) + c.get("sells24", 0)) < GATE_MIN_TXNS_24H:
            _drop("交易过少")
        else:
            pre.append(c)
    pre.sort(key=lambda c: -((c.get("vol24") or 0) / max(c.get("liq") or 1, 1)))
    # 先排序再截断，最后才打"已看过"标记 —— 否则被截掉的那批会被误标已推，
    # 6 小时内再也进不了候选（等于白丢）。
    head = pre[:limit * 4]
    pre = [c for c in head
           if not _seen_before(f"{c['network']}:{c['addr'].lower()}", write=mark)]
    if len(head) > len(pre):
        # 去重掉的数量必须显式记下来，否则 scanned 和 rejects 永远对不上账，
        # 看起来像"数据丢了"，其实是被去重挡掉了。小时数从常量取，
        # 不要写死成 6 —— 调到 2 小时之后文案还写 6，排查时会跟着走错路。
        rejects[f"已看过({SEEN_TTL // 3600}小时内)"] = len(head) - len(pre)

    ex = _executor("QUERY_EXECUTOR", 8)
    if enrich:
        list(ex.map(dexscreener_enrich, pre))
    results = list(ex.map(evaluate, pre))
    evaled, weak = [], []
    for org, c in zip(pre, results):
        if not c:
            _drop((org or {}).get("rejected") or "未通过")
            continue
        evaled.append(c)
        if c["score"] < SELECTION_MIN_SCORE:
            weak.append({"symbol": c["symbol"], "score": c["score"], "grade": c["grade"]})
    evaled.sort(key=lambda c: -c["score"])
    weak.sort(key=lambda x: -x["score"])
    hits = [c for c in evaled if c["score"] >= SELECTION_MIN_SCORE][:limit]
    _LAST_DIAG = {"ts": int(time.time()), "scanned": scanned, "pre": len(pre),
                  "rejects": dict(sorted(rejects.items(), key=lambda kv: -kv[1])[:12]),
                  "weak": weak[:5], "hits": len(hits)}
    return hits, scanned


_LAST_SCAN_TS = 0.0
_SCAN_LOCK = threading.Lock()

# 免费用户的个人冷却：每次 /金狗 可能触发一次全链扫描，不限制会被刷爆额度
_CD = {}
_CD_LOCK = threading.Lock()


def _cooldown_ok(uid, sec=60):
    if not uid:
        return True
    now = time.time()
    with _CD_LOCK:
        if now - _CD.get(uid, 0) < sec:
            return False
        _CD[uid] = now
        if len(_CD) > 10000:
            _CD.clear()
        return True


def ensure_picks(limit=8, mark=True):
    """取本期榜单，没有就现扫一次。

    返回 (picks, scanned, 是否真的扫过)。加锁 + 30 秒节流：
    群里 20 个人同时发 /金狗，不能触发 20 次全链扫描把额度打光。
    mark=False 用于手动查询：不写去重标记，免得把手动查的那批币锁死。
    """
    global _LAST_SCAN_TS
    if _LAST_PICKS:
        return _LAST_PICKS, 0, True
    if not _SCAN_LOCK.acquire(blocking=False):
        return [], 0, False
    try:
        if _LAST_PICKS:
            return _LAST_PICKS, 0, True
        picks, scanned = scan_once(limit=limit, mark=mark)
        _LAST_SCAN_TS = time.time()
        return picks, scanned, True
    finally:
        _SCAN_LOCK.release()


def picks_for_free(picks=None, ts=None):
    """免费版：用**上一期**（已冷却 2 小时）的榜单，只取 A 级以上前 3。

    注意必须传上一期：tick 里刚扫完就把 _LAST_PICKS 换成了新结果，
    直接读模块变量永远拿到"刚生成、还没冷却"的那一期，免费推送会永远为空。
    """
    picks = _LAST_PICKS if picks is None else picks
    ts = _LAST_PICKS_TS if ts is None else ts
    if not picks or time.time() - ts < FREE_DELAY_SEC:
        return []
    return [c for c in picks if at_least(c, "A")][:FREE_MAX_PICKS]


def _send_raw(chat_type, chat_id, text):
    fn = getattr(BOT, "send_message", None) if BOT is not None else None
    if fn:
        fn(chat_type, chat_id, text)
        return
    key = os.getenv("DEBOX_APP_KEY", "") or (getattr(BOT, "APP_KEY", "") if BOT else "")
    try:
        _session().post("https://open.debox.pro/openapi/bot/sendMessage",
                        json={"chat_type": chat_type, "chat_id": chat_id,
                              "content": text, "parse_mode": "text"},
                        headers={"Content-Type": "application/json", "X-API-KEY": key},
                        timeout=10)
    except Exception as e:
        print(f"[pick] 推送失败 {chat_id}: {e}")


def _send_group(gid, text):
    _send_raw("group", gid, text)


# ---------- 影子记录：只写库，不推送 ----------
def _shadow_record(picks, scanned=0, manual=False):
    """把本期结果写进 Redis（base64 过的 JSON），供事后复盘。

    为什么不用明文 JSON 拼路径：Upstash REST 的命令参数在 URL path 里，
    币名带 "/" 或 "?" 会把路径截断，base64 之后不会有任何特殊字符。
    """
    day = _now_bj().strftime("%Y%m%d")
    rows = []
    for c in picks:
        rows.append({"ts": int(time.time()), "symbol": c["symbol"], "addr": c["addr"],
                     "network": c["network"], "score": c["score"], "grade": c["grade"],
                     "price": c.get("price"), "liq": c.get("liq"), "vol24": c.get("vol24"),
                     "dims": c.get("dims"), "warns": (c.get("ctx") or {}).get("warns")})
    if not rows:
        # 空结果同样要留档。连续几天 0 个，是门槛太严、还是数据源压根没给数据，
        # 只有把"为什么 0 个"记下来才分得清；只记命中数，复盘就退化成猜。
        rows.append({"ts": int(time.time()), "empty": True, "scanned": scanned,
                     "pre": _LAST_DIAG.get("pre"), "rejects": _LAST_DIAG.get("rejects"),
                     "weak": _LAST_DIAG.get("weak")})
    if manual:
        # 手动 /金狗 也留档：不然"我明明推了 2 个，记录却是 0"这种对不上账的情况
        # 会一直出现。但标记来源，统计时和定时任务分开算，别把手动查询算成"期"。
        for r in rows:
            r["manual"] = 1
    if _redis_ready():
        for payload in rows:
            raw = base64.urlsafe_b64encode(
                json.dumps(payload, ensure_ascii=False).encode()).decode().rstrip("=")
            _upstash(f"rpush/xx:shadow:{day}/{raw}")
        _upstash(f"ltrim/xx:shadow:{day}/0/499", "GET")
        _upstash(f"expire/xx:shadow:{day}/{86400 * 120}", "GET")
        return
    # 没配 Redis：直接落盘。测试期只有一台机器，一个文件比外部服务更少出错，
    # 也不用为了看记录先去注册数据库 —— 否则"先跑三天看看"就卡在配置上了。
    try:
        d = os.path.dirname(SHADOW_FILE)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(SHADOW_FILE, "a", encoding="utf-8") as f:
            for payload in rows:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[pick] 影子落盘失败: {e}")


def load_shadow(days=3):
    out = []
    if _redis_ready():
        for i in range(days):
            day = (_now_bj() - timedelta(days=i)).strftime("%Y%m%d")
            for r in (_upstash(f"lrange/xx:shadow:{day}/0/-1", "GET") or []):
                try:
                    out.append(json.loads(base64.urlsafe_b64decode(
                        r + "=" * (-len(r) % 4)).decode()))
                except Exception:
                    continue
    else:
        cutoff = time.time() - days * 86400
        try:
            with open(SHADOW_FILE, encoding="utf-8") as f:
                for line in f:
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    if row.get("ts", 0) >= cutoff:
                        out.append(row)
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[pick] 影子读取失败: {e}")
    out.sort(key=lambda x: -x.get("ts", 0))
    return out


def render_shadow(days=3, recent=12):
    """把影子记录整理成人能读的几行。

    原始 JSON 适合机器，不适合在手机上看 —— 而影子期唯一要回答的问题只有三个：
    每期入了几个、等级分布对不对、被筛掉的主因是什么。所以只保留这三件事。
    """
    rows = load_shadow(days)
    if not rows:
        return (f"📊 甄选影子记录 · 近 {days} 天\n"
                "还没有数据。\n"
                "定时任务每 30 分钟记一次；也可以发一次 /金狗 立刻产生一条。")

    picks, empties, man_picks = [], [], []
    auto, man = {}, {}
    for r in rows:
        ts = r.get("ts", 0)
        book = man if r.get("manual") else auto
        book.setdefault(ts, 0)
        if r.get("empty"):
            empties.append(r)
        else:
            book[ts] += 1
            picks.append(r)
            if r.get("manual"):
                man_picks.append(r)
    auto_seq = [auto[k] for k in sorted(auto)]          # 旧 → 新
    man_seq = [man[k] for k in sorted(man)]
    zero = sum(1 for n in auto_seq if n == 0)
    man_strong = sum(1 for r in man_picks if r.get("grade") in ("S", "A"))
    by_grade = {g: sum(1 for r in picks if r.get("grade") == g) for g in ("S", "A", "B")}

    # 自动和手动必须分开算："我刚推了 2 个"和"这 2 个小时的定时任务没出货"
    # 是两件事，混在一起数就永远对不上，也看不出定时任务到底有没有在干活。
    # 手动那行还要报 A 级以上几个：免费版只给 A 级以上，群里看到 2 个而这里写 8 个，
    # 差出来的 6 个全是 B 级 —— 不点明，用户只会以为记录在瞎报。
    lines = [f"📊 甄选影子记录 · 近 {days} 天",
             f"自动扫描 {len(auto_seq)} 期：入选 {sum(auto_seq)} 个，零入选 {zero} 期",
             f"手动查询 {len(man_seq)} 次：入选 {len(man_picks)} 个"
             f"（A 级以上 {man_strong}）",
             f"S {by_grade['S']} / A {by_grade['A']} / B {by_grade['B']}"]
    if auto_seq:
        lines.append("▱▱▱▱▱▱▱▱▱▱")
        lines.append(f"每期入选数（最近 {min(recent, len(auto_seq))} 期，旧→新）")
        lines.append(" ".join(str(n) for n in auto_seq[-recent:]))
    if picks:
        lines.append("▱▱▱▱▱▱▱▱▱▱")
        lines.append("最近入选")
        # 同一轮的币 ts 完全相同，只按时间排会按写入顺序出，77 分的 B 可能压在
        # 77 分的 A 上面。同轮再按分数、再按等级排，否则看起来像等级判错了。
        for r in sorted(picks, key=lambda x: (-x.get("ts", 0), -x.get("score", 0),
                                              -GRADE_RANK.get(x.get("grade", "C"), 0)))[:5]:
            t = datetime.fromtimestamp(r.get("ts", 0), tz=timezone(timedelta(hours=8)))
            lines.append(f"{GRADE_ICON.get(r.get('grade'), '·')} {r.get('grade')} "
                         f"{r.get('score')}分 ${r.get('symbol')} "
                         f"{t.strftime('%m/%d %H:%M')}")
    if empties:
        last = max(empties, key=lambda x: x.get("ts", 0))
        rej = last.get("rejects") or {}
        if rej:
            lines.append("▱▱▱▱▱▱▱▱▱▱")
            lines.append("最近一次零入选的淘汰主因")
            top = sorted(rej.items(), key=lambda kv: -kv[1])[:4]
            lines.append("　".join(f"{k} {v}" for k, v in top))
        weak = last.get("weak") or []
        if weak:
            lines.append("最接近门槛的：" + "、".join(
                f"${w['symbol']} {w['score']}分" for w in weak[:3]))
    return "\n".join(lines)


# ---------- 单币诊断：回答"这个币为什么没上榜" ----------
DS_TO_GECKO = {"ethereum": "eth", "bsc": "bsc", "polygon": "polygon_pos",
               "arbitrum": "arbitrum", "base": "base", "solana": "solana",
               "avalanche": "avax", "optimism": "optimism"}


def explain(addr, network=None):
    """单币诊断。给客服和运营用：用户问"为什么不推我这个币"，一查就知道卡在哪。"""
    addr = (addr or "").strip()
    if not addr:
        return {"error": "缺少 addr 参数"}
    try:
        r = _session().get(f"https://api.dexscreener.com/latest/dex/tokens/{addr}", timeout=6)
        pairs = (r.json().get("pairs") or []) if r.ok else []
    except Exception as e:
        return {"addr": addr, "error": f"DexScreener 请求失败: {e}"}
    if not pairs:
        return {"addr": addr, "error": "查不到该代币的池子（未上池 / 已下架 / 地址错误）"}

    best = max(pairs, key=lambda p: _to_float((p.get("liquidity") or {}).get("usd")))
    base = best.get("baseToken") or {}
    ds_chain = best.get("chainId") or ""
    net = network or DS_TO_GECKO.get(ds_chain, ds_chain)
    t24 = (best.get("txns") or {}).get("h24") or {}
    created = best.get("pairCreatedAt")
    info_block = best.get("info") or {}

    cand = {
        "network": net, "chain_id": GECKO_CHAIN.get(net),
        "addr": (base.get("address") or addr), "pool_addr": best.get("pairAddress") or "",
        "symbol": (base.get("symbol") or "?")[:18], "name": base.get("name") or "",
        "price": _to_float(best.get("priceUsd")),
        "liq": _to_float((best.get("liquidity") or {}).get("usd")),
        "vol24": _to_float((best.get("volume") or {}).get("h24")),
        "age_min": ((time.time() * 1000 - _to_float(created)) / 60000) if created else None,
        "pc24h": _to_float((best.get("priceChange") or {}).get("h24")),
        "pc1h": _to_float((best.get("priceChange") or {}).get("h1")),
        "buys24": int(_to_float(t24.get("buys"))), "sells24": int(_to_float(t24.get("sells"))),
        "buyers24": 0, "sellers24": 0,          # DexScreener 不提供，动量分会少算 5 分
        "fdv": _to_float(best.get("fdv")), "mcap": _to_float(best.get("marketCap")),
        "pair_url": best.get("url") or "",
        "websites": [w.get("url") for w in (info_block.get("websites") or []) if w.get("url")],
        "socials": [s.get("type") for s in (info_block.get("socials") or []) if s.get("type")],
        "has_desc": bool((info_block.get("description") or "").strip()),
        "boost": bool((best.get("boosts") or {}).get("active")),
    }
    info = goplus_security(cand)
    ok, why = hard_gate(cand, info)
    result = {"addr": cand["addr"], "symbol": cand["symbol"], "network": net,
              "pool": cand["pair_url"], "safety_fields": len(info),
              "gate_pass": ok, "gate_reason": why or None,
              "note": "DexScreener 不提供独立买家数，动量分按 0 计，实际得分可能更高 5 分"}
    if not ok:
        return result
    if not info:
        result.update({"gate_reason": "GoPlus 查不到安全数据", "gate_pass": False})
        return result
    total, dims, ctx = score(cand, info)
    result.update({"score": total, "grade": capped_grade(total, ctx, cand), "dims": dims,
                   "top10": round(ctx["top10"], 1), "eoa_pct": round(ctx["eoa_pct"], 1),
                   "lp_lock": ctx["lp_lock"], "reasons": ctx["reasons"],
                   "warns": ctx["warns"], "unknowns": ctx["unknowns"],
                   "in_list": total >= SELECTION_MIN_SCORE,
                   "invalidations": invalidations(cand, ctx)})
    return result


def tick(force=False):
    """一次定时任务：扫描 → 存最近一期 → 推付费群（≤每日上限）→ 推免费群（延迟）。"""
    global _LAST_PICKS, _LAST_PICKS_TS, _FREE_LAST
    today = _now_bj().strftime("%Y%m%d")
    if _PUSH_COUNT["date"] != today:
        _PUSH_COUNT.update({"date": today, "n": 0})
    if not force and _PUSH_COUNT["n"] >= MAX_PUSH_PER_DAY:
        return 0

    picks, scanned = scan_once()
    prev_picks, prev_ts = _LAST_PICKS, _LAST_PICKS_TS
    _LAST_PICKS, _LAST_PICKS_TS = picks, time.time()

    if SHADOW_MODE:
        # 影子期：全部记下来，一条不发。/金狗 仍可查，方便自己先看质量。
        # 必须放在 "not picks" 之前 —— 否则空扫描不留痕，而空扫描恰恰是最该看的那种。
        _shadow_record(picks, scanned)
        return 0

    if not picks:
        return 0

    # 免费群：用上一期（冷却 2 小时）的榜单，晚 2 小时、只给 3 个、不给理由
    free = picks_for_free(prev_picks, prev_ts)
    if free and FREE_GROUPS and time.time() - _FREE_LAST >= FREE_DELAY_SEC:
        txt = render_digest(free, free=True, delayed=True)
        for gid in FREE_GROUPS:
            _send_group(gid, txt)
        _FREE_LAST = time.time()

    # 付费群：只推 A 级以上，B 级留在线查询 —— 推得越克制，打开率越高
    push = [c for c in picks if at_least(c, "A")]
    if not push:
        return 0
    text = render_digest(push, scanned=scanned)
    for gid in PAID_GROUPS:
        _send_group(gid, text)
    if PAID_GROUPS:
        _PUSH_COUNT["n"] += 1
    # 战绩：记下当期入选价，供 /甄选战绩 回溯
    for c in push:
        _upstash(f"set/xx:entry:{c['addr'].lower()}/{c.get('price', 0)}")
        _upstash(f"sadd/xx:picks:{today}/{c['addr'].lower()}")
    return len(push)


def _loop():
    """常驻进程的推送循环。Serverless 上不要用：实例冻结后线程不跑，改用 /cron/selection。"""
    time.sleep(60)      # 首次延迟：刚冷启动时先让用户的查询用满线程池
    while True:
        try:
            # 没配任何群、也没开影子模式 → 不扫。省下额度留给 /金狗 的按需查询
            if PAID_GROUPS or FREE_GROUPS or SHADOW_MODE:
                tick()
        except Exception as e:
            print(f"[pick] 推送循环异常: {e}")
        time.sleep(PUSH_INTERVAL_SEC)


_SCHED_STARTED = False
_SCHED_LOCK = threading.Lock()


def ensure_scheduler():
    """进程内只启动一次推送线程。

    为什么不在模块里直接 start_scheduler()：gunicorn 先导入再 fork，
    fork 只复制主线程，导入期启动的线程在 worker 里并不存在；
    多 worker 时又会每个 worker 各推一次。所以挂到首个请求上，每个进程各启一个，
    并用 -w 1 保证只有一个进程。
    """
    global _SCHED_STARTED
    with _SCHED_LOCK:
        if _SCHED_STARTED:
            return False
        _SCHED_STARTED = True
    return start_scheduler()


_SCHED_THREAD = None


def start_scheduler():
    global _SCHED_THREAD
    serverless = ("VERCEL", "AWS_LAMBDA_FUNCTION_NAME", "FC_FUNCTION_NAME", "SCF_FUNCTIONNAME")
    if any(os.getenv(m) for m in serverless):
        print("[pick] Serverless 环境：跳过后台推送线程，请用 /cron/selection")
        return False
    t = threading.Thread(target=_loop, daemon=True, name="xx-scheduler")
    t.start()
    _SCHED_THREAD = t
    return True


# ======================================================================
# 七、指令与路由
# ======================================================================
SUB_TEXT = (
    "🏆 链上甄选 · 会员\n\n"
    "警犬帮你排雷，甄选帮你找狗。\n\n"
    "【你会得到】\n"
    "① 每 30 分钟全链扫描，S/A 级实时推送\n"
    "② 五维评分：安全 / 筹码 / 动量 / 新鲜度 / 叙事\n"
    "③ 每个标的附「失效条件」，告诉你什么时候走\n"
    "④ 历史战绩回溯，赚了亏了都公开\n\n"
    "【价格】\n"
    "🎟 7 天体验 $9.9\n"
    "📅 月卡 $29\n"
    "📦 季卡 $69（推荐，约 $23/月）\n"
    "🗓 年卡 $199\n\n"
    "【开通】向管理员购买卡密后，私聊发送：\n"
    "/激活 你的卡密\n\n"
    "⚠️ 本服务提供数据筛选与风险提示，不构成投资建议，不承诺收益。"
)


def _reply(data, text):
    gid, uid = data.get("group_id"), data.get("from_user_id")
    if gid:
        _send_raw("group", gid, text)
    elif uid:
        _send_raw("private", uid, text)


def handle_selection_command(data, message=None):
    """在 handle_message 里调用：命中甄选指令返回 True，未命中返回 False。

    放在帮助/管理后台之后、查 CA 之前 —— 它的指令都以 / 开头，
    不会被误当成合约地址，也不会干扰钓鱼检测。
    """
    message = message if message is not None else (data.get("message_raw") or data.get("message") or "")
    if not isinstance(message, str):
        return False
    cmd = re.sub(r"^(?:@[^\s]+\s*)+", "", message.strip()).strip()
    # DeBox 群里 @机器人 时指令可能长成 "/金狗@1234"，把尾部 @xxx 也剥掉
    cmd = re.sub(r"@\S+$", "", cmd).strip()
    low = cmd.lower()
    uid = str(data.get("from_user_id") or "")

    if low.split(" ")[0] in ("/订阅", "/subscribe", "/会员"):
        _reply(data, SUB_TEXT)
        return True

    if low.split(" ")[0] in ("/激活", "/redeem"):
        code = cmd.split(" ", 1)[1].strip() if " " in cmd else ""
        if not code:
            _reply(data, "用法：/激活 XX-XXXX-XXXX-XXXX")
            return True
        ok, msg = redeem_code(code, uid)
        _reply(data, msg)
        return True

    if low.split(" ")[0] in ("/金狗", "/甄选", "/pick", "/picks"):
        member = is_member(uid)
        if member and not quota_take(uid, 60):
            _reply(data, "⚠️ 今日查询次数已达上限（60 次），明天再来。")
            return True
        if not member and not _cooldown_ok(uid, 60):
            _reply(data, "🐕 慢一点，60 秒后才能再查一次。订阅后不限频 → /订阅")
            return True
        picks, scanned, did_scan = ensure_picks(limit=8, mark=False)
        if not did_scan:
            # 另一个请求正在扫，或刚扫过还没出结果：让对方等 10 秒，别触发第二次全链扫描
            _reply(data, "🐕 正在扫描全链，约 10 秒后重发 /金狗 即可")
            return True
        if not picks and scanned == 0:
            # 一个池子都没拉到 = 数据源挂了，不能谎报"本期无标的"
            _reply(data, "🐕 行情源暂时不可用，稍后再试（不影响安全查询）")
            return True
        if scanned > 0:
            # 真扫了一轮才留档；scanned=0 是命中内存缓存，记了只会把同一期重复算几遍
            _shadow_record(picks, scanned, manual=True)
        if member:
            _reply(data, render_digest(picks[:8], scanned=scanned))
        else:
            free = picks_for_free() or [c for c in picks if at_least(c, "A")][:FREE_MAX_PICKS]
            if not free:
                _reply(data, "🐕 本期暂无符合标准的标的。\n"
                             "订阅后可查看完整榜单与实时推送 → 发送 /订阅")
            else:
                _reply(data, render_digest(free, free=True, scanned=scanned))
        return True

    if low.split(" ")[0] in ("/甄选战绩", "/战绩", "/track"):
        # 支持 /战绩 30 看一个月；默认 7 天。战绩是给用户看的，不做管理员限制。
        parts = cmd.split()
        days = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 7
        _reply(data, render_track(max(1, min(30, days))))
        return True

    if low.split(" ")[0] in ("/甄选记录", "/影子", "/shadow"):
        # 管理员专用：影子期每天要看的就是这几行，比 curl 方便得多
        admin = str(getattr(BOT, "ADMIN_USER_ID", "") if BOT else "")
        if not admin or uid.lstrip("@") != admin.lstrip("@"):
            _reply(data, "⚠️ 仅管理员可用")
            return True
        parts = cmd.split()
        days = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 3
        _reply(data, render_shadow(max(1, min(30, days))))
        return True
    return False


# ---------- 战绩回溯：入选价 → 现价 ----------
_TRACK_CACHE = {}          # (addr, network) -> (ts, price)
_TRACK_TTL = 300

# Gecko 网络名 → DexScreener chainId。同一串 0x 地址在不同链上是两个毫不相干的币，
# 不过滤链就会出现"BSC 的币拿 ETH 同地址的币报价"，涨幅动辄几亿倍。
DS_CHAIN_OF = {v: k for k, v in DS_TO_GECKO.items()}
ODD_ROI_PCT = 1000.0       # 涨幅超过 10 倍先当数据异常，人工核对前不进统计


def _pair_liq(p):
    liq = p.get("liquidity")
    return _to_float(liq.get("usd")) if isinstance(liq, dict) else _to_float(liq)


def _now_price(item):
    """当前价。三种结果必须分开：真实价格 / 已下架(0.0) / 取价失败(None)。

    下架不能和网络抖动混为一谈：下架的币按 -100% 计，网络失败要跳过。
    两者都当"查不到"悄悄跳过，胜率会凭空变好看 —— 这正是战绩最不该犯的错。

    两处口径必须固定，否则战绩页会出现天文数字（曾把 B 级平均拉到 +5061113%）：
    1. 按链过滤。DexScreener 的 /tokens/{addr} 返回该地址在所有链上的交易对，
       跨链同地址是两个不同的币，价格差几个数量级。
    2. 按流动性取主盘，而不是取最高价。同一链上真盘旁边常挂着无人交易的假盘/测试盘，
       取 max 等于把一个没人买的盘口当成"这个币现在的价格"。
    """
    addr, net = item if isinstance(item, tuple) else (item, "")
    addr, net = (addr or "").lower(), (net or "").lower()
    key = (addr, net)
    now = time.time()
    hit = _TRACK_CACHE.get(key)
    if hit and now - hit[0] < _TRACK_TTL:
        return hit[1], "ok"
    try:
        r = _session().get(f"https://api.dexscreener.com/latest/dex/tokens/{addr}",
                           timeout=4)
        if not r.ok:
            return None, "net"
        pairs = list(r.json().get("pairs") or [])
        want = DS_CHAIN_OF.get(net)
        if want:
            same = [p for p in pairs if (p.get("chainId") or "").lower() == want]
            # 指定了链却一个交易对都没有 = 这条链上已经没得买了，按下架处理。
            # 退回全部交易对会让"已归零"被算成涨跌，方向完全相反。
            pairs = same
        if not pairs:
            return 0.0, "gone"
        cur = _to_float(max(pairs, key=_pair_liq).get("priceUsd"))
        if cur <= 0:
            return 0.0, "gone"
        _TRACK_CACHE[key] = (now, cur)
        if len(_TRACK_CACHE) > 2000:
            _TRACK_CACHE.clear()
        return cur, "ok"
    except Exception:
        return None, "net"


def _track_items(days):
    """近 N 天记录过的标的：[(日期, 地址, 代号, 入选价, 等级, 链), ...]

    同一个币只算第一次：战绩的分子分母都是"一次推荐"，重复计入同一笔会虚增样本
    数，也会让同一个币的涨跌被算好几遍。
    有 Redis 用推送时写的 entry 集合（只含真正推出去的）；没 Redis 用影子文件
    —— 影子期不推送，所以"入选"即视为推荐。
    """
    items, seen = [], set()
    if _redis_ready():
        for i in range(days):
            d = (_now_bj() - timedelta(days=i)).strftime("%Y%m%d")
            for a in (_upstash(f"smembers/xx:picks:{d}", "GET") or [])[:20]:
                a = (a or "").lower()
                entry = _to_float(_upstash(f"get/xx:entry:{a}", "GET") or 0)
                if entry > 0 and a not in seen:
                    seen.add(a)
                    items.append((d, a, a[:6], entry, "", ""))
        return items

    rows = sorted(load_shadow(days), key=lambda x: x.get("ts", 0))   # 旧 → 新
    for r in rows:
        a = (r.get("addr") or "").lower()
        p = _to_float(r.get("price") or 0)
        if not a or p <= 0 or a in seen:
            continue
        seen.add(a)
        t = datetime.fromtimestamp(r.get("ts", 0), tz=timezone(timedelta(hours=8)))
        items.append((t.strftime("%Y%m%d"), a, r.get("symbol") or a[:6],
                      p, r.get("grade") or "", r.get("network") or ""))
    return items


def render_track(days=7):
    """战绩回溯：把过去 N 天推过的币按当前价对一遍，赚的亏的都列。

    这是唯一能回答"模型到底准不准"的东西。只报胜率不够：中位数才说明大部分标的
    是否真赚钱，平均数会被一两个十倍币拉飞。等级分组则是验证"S 比 B 强"的唯一证据
    —— 如果 S 和 B 的表现没差别，那分级就是摆设，卖点也就没了。
    """
    items = _track_items(days)
    if not items:
        return (f"📊 甄选战绩 · 近 {days} 天\n"
                "还没有记录。\n"
                "先发一次 /金狗 产生一条，过几小时再回来对价。")

    targets = [(it[1], it[5]) for it in items]
    try:
        prices = list(_executor("TRACK_EXECUTOR", 6).map(_now_price, targets))
    except Exception:
        prices = [_now_price(t) for t in targets]

    rows, skipped = [], 0
    for (d, a, sym, entry, grade, _net), (cur, st) in zip(items, prices):
        if st == "net" or cur is None:
            skipped += 1
            continue
        gone = st == "gone"
        roi = (cur - entry) / entry * 100
        # 十几倍的币在链上确实存在，但几亿倍的只可能是数据错了（跨链同名盘、入选价
        # 被截断）。这类样本必须从均值里剔掉：一条就能把 B 级平均拉到千万级，
        # 整个战绩页当场变成笑话。
        rows.append({"d": d, "sym": sym, "grade": grade, "roi": roi,
                     "gone": gone, "odd": (not gone) and roi > ODD_ROI_PCT})
    if not rows:
        return "📊 战绩取价失败（行情源没响应），过几分钟再试。"

    normal = sorted((r for r in rows if not r["odd"]), key=lambda r: -r["roi"])
    odd = sorted((r for r in rows if r["odd"]), key=lambda r: -r["roi"])
    if not normal:
        return (f"📊 甄选战绩 · 近 {days} 天（{len(odd)} 个标的）\n"
                f"全部涨幅异常（>{ODD_ROI_PCT:.0f}%），疑似跨链同名盘或入选价记录有误，\n"
                "已暂不计入统计。把记录发我，我核对数据源。")
    rows = normal
    n = len(rows)
    win = sum(1 for r in rows if r["roi"] > 0)
    roi_sorted = sorted(r["roi"] for r in rows)
    med = roi_sorted[n // 2]
    avg = sum(roi_sorted) / n

    lines = [f"📊 甄选战绩 · 近 {days} 天（{n} 个标的）",
             f"胜率 {win / n * 100:.0f}%　中位 {med:+.0f}%　平均 {avg:+.0f}%",
             f"最好 ${rows[0]['sym']} {rows[0]['roi']:+.0f}%　"
             f"最差 ${rows[-1]['sym']} {rows[-1]['roi']:+.0f}%"]

    graded = [(g, [r for r in rows if r["grade"] == g]) for g in ("S", "A", "B")]
    if any(grp for _, grp in graded):
        lines.append("▱▱▱▱▱▱▱▱▱▱")
        for g, grp in graded:
            if not grp:
                continue
            gavg = sum(r["roi"] for r in grp) / len(grp)
            gwin = sum(1 for r in grp if r["roi"] > 0) / len(grp) * 100
            lines.append(f"{GRADE_ICON.get(g, '·')} {g} {len(grp)} 个："
                         f"平均 {gavg:+.0f}%　胜率 {gwin:.0f}%")

    lines.append("▱▱▱▱▱▱▱▱▱▱")
    for r in rows[:10]:
        icon = (GRADE_ICON.get(r["grade"], "·") + " ") if r["grade"] else ""
        tag = "　已下架" if r["gone"] else ""
        lines.append(f"{'🟢' if r['roi'] > 0 else '🔴'} {icon}"
                     f"${r['sym']} {r['roi']:+.0f}%{tag}　"
                     f"{r['d'][4:6]}/{r['d'][6:]}")
    if odd:
        lines.append("▱▱▱▱▱▱▱▱▱▱")
        lines.append(f"⚠️ {len(odd)} 个涨幅异常（>{ODD_ROI_PCT:.0f}%），疑跨链同名盘，未计入")
        for r in odd[:3]:
            lines.append(f"⚠️ ${r['sym']} ×{r['roi'] / 100:.0f} 倍　"
                         f"{r['d'][4:6]}/{r['d'][6:]}")
    if skipped:
        lines.append(f"（另有 {skipped} 个取价失败，未计入）")
    lines.append("按入选价对现价，未计滑点与税费；下架按 -100% 计。")
    return "\n".join(lines)


def selection_routes(app):
    """管理接口：手动扫描、定时任务、生成卡密、单币诊断、影子记录回看。

    统一用 X-API-KEY 鉴权，和主程序 /webhook、/refresh-blocklist 保持一致。
    """

    def _auth():
        expected = os.getenv("DEBOX_WEBHOOK_KEY", "") or \
            (getattr(BOT, "WEBHOOK_KEY", "") if BOT else "")
        got = request.headers.get("X-API-KEY", "")
        if not expected or not got:
            return False
        try:   # 常量时间比对，见主程序 auth_ok 的注释
            return hmac.compare_digest(got.encode("utf-8"), expected.encode("utf-8"))
        except Exception:
            return False

    @app.route("/selection/scan", methods=["POST"])
    def _xx_scan():
        if not _auth():
            return jsonify({"error": "unauthorized"}), 401
        picks, scanned = scan_once()
        return jsonify({"scanned": scanned, "hit": len(picks),
                        "picks": [{"symbol": c["symbol"], "score": c["score"],
                                   "grade": c["grade"], "addr": c["addr"],
                                   "dims": c["dims"]} for c in picks]})

    @app.route("/cron/selection", methods=["GET", "POST"])
    def _xx_cron():
        if not _auth():
            return jsonify({"error": "unauthorized"}), 401
        n = tick(force=True)
        return jsonify({"pushed": n, "shadow": SHADOW_MODE})

    @app.route("/selection/ping", methods=["GET"])
    def _xx_ping():
        """存活探针：不需要密钥，托管平台的 health check 直接打这里。"""
        return jsonify({"ok": True, "shadow": SHADOW_MODE,
                        "networks": DEFAULT_NETWORKS,
                        "pushed_today": _PUSH_COUNT["n"],
                        "redis": _redis_ready(),
                        "sched": bool(_SCHED_THREAD and _SCHED_THREAD.is_alive())})

    @app.route("/selection/score", methods=["GET"])
    def _xx_score():
        """单币诊断：curl '/selection/score?addr=0x...' 看它卡在哪一步。"""
        if not _auth():
            return jsonify({"error": "unauthorized"}), 401
        return jsonify(explain(request.args.get("addr", ""), request.args.get("network")))

    @app.route("/selection/shadow", methods=["GET"])
    def _xx_shadow():
        """影子期样本：默认回看最近 3 天，看看到底推了些什么、分数分布如何。"""
        if not _auth():
            return jsonify({"error": "unauthorized"}), 401
        try:
            days = max(1, min(30, int(request.args.get("days", 3))))
        except (TypeError, ValueError):
            days = 3
        if request.args.get("format") == "text":
            return app.response_class(render_shadow(days), mimetype="text/plain; charset=utf-8")
        rows = load_shadow(days)
        return jsonify({"count": len(rows),
                        "by_grade": {g: sum(1 for r in rows if r.get("grade") == g)
                                     for g in ("S", "A", "B")},
                        "rows": rows})

    @app.route("/selection/diag", methods=["GET", "POST"])
    def _xx_diag():
        """"为什么 0 个"：回看最近一次扫描的淘汰分布。

        带 scan=1 会现扫一轮（耗 15 秒），否则读上一次 /金狗 或定时任务的结果。
        """
        if not _auth():
            return jsonify({"error": "unauthorized"}), 401
        if request.args.get("scan") == "1" or not _LAST_DIAG:
            scan_once(limit=8)
        out = dict(_LAST_DIAG or {})
        out["store"] = "redis" if _redis_ready() else "file:" + SHADOW_FILE
        return jsonify(out)

    @app.route("/selection/codes", methods=["POST"])
    def _xx_codes():
        if not _auth():
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        plan = str(body.get("plan", "MONTH")).upper()
        count = max(1, min(200, int(body.get("count", 1))))
        if PLAN_ALIAS.get(plan):
            plan = PLAN_ALIAS[plan]
        if plan not in PLANS:
            return jsonify({"error": "unknown plan", "plans": list(PLANS)}), 400
        return jsonify({"plan": plan, "days": PLANS[plan]["days"],
                        "codes": issue_code(plan, count)})


# ======================================================================
# 八、自检 / 演示（fixture 数据，非实时行情）
# ======================================================================
def _demo_fixtures():
    """构造三个候选走完整评分链路：优质 / 带税 / 高风险。仅验证逻辑与版式。"""
    base = {"network": "solana", "chain_id": None,
            "pair_url": "https://dexscreener.com/solana/demo"}

    def H(pool_pct, rest):
        """拼一份 holders：第一项是池子（会被排除），其余是个人地址。"""
        hs = [{"address": "POOLxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "percent": str(pool_pct)}]
        for i, p in enumerate(rest):
            hs.append({"address": f"Wallet{i:02d}" + "x" * 32, "percent": str(p)})
        return hs

    fx = [
        dict(base, addr="DEMO1", symbol="MOCHI", price=0.0012, liq=182000, vol24=560000,
             age_min=252, pc24h=64, pc1h=12, buys24=2140, sells24=1190,
             buyers24=1240, sellers24=760,
             info={"mintable": {"status": "0"}, "freezable": {"status": "0"},
                   "closable": {"status": "0"}, "holder_count": "1820",
                   "holders": H(0.09, [0.042, 0.038, 0.031, 0.026, 0.022, 0.018, 0.015]),
                   "lp_holders": [{"percent": "1", "is_locked": "1",
                                   "address": "0x000000000000000000000000000000000000dead"}]},
             websites=["https://mochi.xyz"], socials=["twitter"], has_desc=True, boost=False),
        dict(base, addr="DEMO2", symbol="HOTDOG", price=0.0089, liq=76000, vol24=380000,
             age_min=400, pc24h=120, pc1h=95, buys24=2100, sells24=1690,
             buyers24=900, sellers24=800,
             info={"mintable": {"status": "0"}, "freezable": {"status": "0"},
                   "closable": {"status": "0"}, "holder_count": "640",
                   "holders": H(0.10, [0.09, 0.075, 0.062, 0.055, 0.048, 0.04, 0.035, 0.03]),
                   "lp_holders": []},
             websites=[], socials=[], has_desc=False, boost=False),
        dict(base, addr="DEMO3", symbol="SAFEMOON2", price=0.0001, liq=42000, vol24=8000,
             age_min=3000, pc24h=-38, pc1h=-6, buys24=90, sells24=310,
             buyers24=60, sellers24=180,
             info={"mintable": {"status": "0"}, "freezable": {"status": "0"},
                   "closable": {"status": "1"}, "holder_count": "120",
                   "holders": H(0.05, [0.22, 0.16, 0.12, 0.09, 0.05, 0.03]),
                   "lp_holders": []},
             websites=[], socials=["twitter"], has_desc=False, boost=False),
    ]
    out = []
    for c in fx:
        info = c.pop("info")
        c["ctx"], c["invalidations"] = {}, []
        total, dims, ctx = score(c, info)
        c.update({"score": total, "dims": dims, "ctx": ctx,
                  "grade": capped_grade(total, ctx, c)})
        c["invalidations"] = invalidations(c, ctx)
        out.append(c)
    out.sort(key=lambda x: -x["score"])
    return [c for c in out if c["score"] >= SELECTION_MIN_SCORE]


if __name__ == "__main__":
    demo = _demo_fixtures()
    print("=" * 62)
    print("示例输出（fixture 数据，非实时行情；用于验证版式与打分）")
    print("=" * 62)
    print(render_digest(demo, scanned=412))
    print()
    print("-" * 62)
    print("免费版（延迟 2 小时 / 3 个 / 无理由）：")
    print("-" * 62)
    print(render_digest(demo, free=True, scanned=412))
    print()
    print("-" * 62)
    codes = issue_code("MONTH", 2)
    print("卡密自检：", codes)
    print("验签结果：", [parse_code(c) for c in codes])
    print("篡改后：", parse_code(codes[0][:-1] + ("A" if codes[0][-1] != "A" else "B")))
