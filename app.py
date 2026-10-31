# -*- coding: utf-8 -*-
"""链上警犬 · DeBox 群安全机器人（单文件部署版）

本文件由 tools/build_single.py 自动生成，请勿直接编辑 ——
改逻辑请改 bot/ 下对应模块，然后重新构建：

    python3 tools/build_single.py && pytest -q

分层（详见各节标题）：
    配置 → 基础设施 → 黑名单 → 取数 → 判定 → 渲染 → 编排 → 消息分支 → 路由

设计约束（改代码前请先读）：
  1. 只有 judge 里允许出现"判断"，fetch 只负责拿数据、失败返回空值。
  2. 所有出站请求走 SESSION，测试里替换掉它就能完全离线。
  3. 缓存一律带 TTL；"查不到"不写缓存（否则一次抖动会被永久记住）。
  4. 鉴权 fail-closed：环境变量没配就拒绝，不误放行。
"""

import hmac
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import selection   # 链上甄选模块（付费板块），见 selection.py


# ======================================================================
# 一、配置：环境变量 / 常量表 / 正则 / 阈值　（源：bot/config.py）
# ======================================================================
# 集中配置：环境变量、常量表、正则、阈值。
#
# 这里只放"数据"，不放逻辑 —— 加链、加品牌、调阈值都只动这个文件，
# 不用再去判定逻辑里翻。

# ===== 环境变量 =====
APP_KEY = os.getenv("DEBOX_APP_KEY", "")
WEBHOOK_KEY = os.getenv("DEBOX_WEBHOOK_KEY", "")

# 数据后台（Upstash Redis REST）
UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL", "")
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
UPSTASH_HEADERS = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}

# ⚠️ 管理员 ID（需是 Webhook 推送的真实 from_user_id，不是邀请链接 code）
ADMIN_USER_ID = "9410sfdk"

# ===== 防钓鱼：多源黑名单 =====
PHISHING_LIST_TTL = 3600  # 缓存有效期 1 小时；刷新由外部定时器调 /refresh-blocklist 触发
METAMASK_BLACKLIST_URL = "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json"
SCAMSNIFFER_BLACKLIST_URL = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json"

# 群里出现这些域名不检测（官方渠道 / 短链平台）
ALLOWED_DOMAINS = ["twitter.com", "x.com", "debox.pro", "t.me", "github.com"]

# ===== 仿冒域名识别（typosquatting） =====
# 主流合法站点清单：骗子常注册与这些站点高度相似的域名
TRUSTED_BRAND_DOMAINS = [
    "uniswap.org", "pancakeswap.finance", "sushi.com", "curve.fi",
    "aave.com", "compound.finance", "lido.fi", "raydium.io",
    "jup.ag", "orca.so", "metamask.io", "trustwallet.com",
    "binance.com", "okx.com", "bybit.com", "gate.io",
    "coinbase.com", "kucoin.com", "bitget.com", "htx.com",
    "ethereum.org", "solana.com", "debox.pro",
]

# 骗子仿冒域名常用拼接词
IMPERSONATION_TOKENS = {
    "app", "io", "official", "login", "exchange", "earn", "verify",
    "airdrop", "finance", "swap", "wallet", "connect", "pro", "auth",
    "secure", "support", "team", "site", "online", "vip", "claim",
    "stake", "launch", "web", "download", "help", "service",
}

# ===== 地址正则：同时支持 EVM 与 Solana =====
# 0x 分支加负向前瞻 (?![a-fA-F0-9])：避免把 64 位裸交易 hash 的前 42 字符误当合约地址
# 两个分支都必须有"边界断言"，否则会从更长的串里截出一段：
#   Solana 交易签名是 87~88 位 base58，无断言时会被截成前 44 位，
#   而那 44 位解码后恰好是 32 字节 → 通过 is_valid_solana_address 校验
#   → 把 tx 签名当代币地址去查，群里收到一条"数据不足"的假报告。
CA_PATTERN = re.compile(
    r"(0x[a-fA-F0-9]{40}(?![a-fA-F0-9]))"
    r"|(?<![1-9A-HJ-NP-Za-km-z])([1-9A-HJ-NP-Za-km-z]{32,44})(?![1-9A-HJ-NP-Za-km-z])"
)
# re.I：HTTPS:// 这种大写协议头也要认。不认的话 "HTTPS://x.com" 不会被当成链接，
# 裸域名规则又会从 "-" 后面截出错片段（binance-verify.vip → verify.vip），直接漏报。
URL_PATTERN = re.compile(r"https?://[^\s]+", re.I)
# 裸域名（不带 http 前缀）：metamask-io.app、binance-verify.vip 这类
# 只匹配 .常见TLD 结尾、至少两段的域名，避免把普通英文句子误判
# 后顾里排除 "-"：否则从 "binance-verify.vip" 里会截出 "verify.vip" 这种伪域名
DOMAIN_PATTERN = re.compile(
    r"(?<![\w@./-])((?:[a-zA-Z0-9][a-zA-Z0-9-]*\.)+"
    r"(?:com|net|org|io|app|xyz|vip|top|cc|me|pro|finance|site|online|info|biz|link|club|fun|"
    r"ltd|shop|store|tech|zone|page|dev|one|pw|tv|co|ai|cn|us|uk|jp|kr|de|fr|hk|tw|mo|asia|"
    r"mobi|gov|edu|id|my|sg|in|au))\b"
)

# 帮助指令：必须"整条消息"就是其中之一才触发教程，避免日常词误触发
HELP_COMMANDS = {"/help", "/帮助", "/menu", "帮助", "使用说明", "菜单", "教程"}

# ===== 链 =====
CHAIN_MAPPING = {
    "ethereum": "1", "bsc": "56", "polygon": "137",
    "arbitrum": "42161", "base": "8453", "avalanche": "43114",
    "optimism": "10"
}
CHAIN_NAMES = {
    "1": "ETH", "56": "BSC", "137": "POL",
    "42161": "ARB", "8453": "BASE", "43114": "AVAX",
    "10": "OP"
}

# 公共 RPC 端点（eth_getCode 验证地址是否为合约，GoPlus 无索引时的兜底）
RPC_ENDPOINTS = {
    "1":     ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com"],
    "56":    ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.binance.org"],
    "137":   ["https://polygon-bor-rpc.publicnode.com"],
    "42161": ["https://arbitrum-one-rpc.publicnode.com"],
    "8453":  ["https://base-rpc.publicnode.com"],
    "10":    ["https://optimism-rpc.publicnode.com"],
    # AVAX 在 CHAIN_MAPPING 里但长期缺这张表 → 该链所有币的持币地址
    # 都拿不到 eth_getCode 兜底，合约池子会被当成个人钱包（误报"死控盘"）
    "43114": ["https://avalanche-c-chain-rpc.publicnode.com",
              "https://api.avax.network/ext/bc/C/rpc"],
}

# Base58 字符集（用于 Solana 地址严格校验）
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# 黑洞/死地址：LP 销毁是最安全的状态，不算个人集中
BURN_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}

# 创建者/Owner 背景核查：这些标记命中即"涉黑"
MALICIOUS_FLAGS = ["phishing_activities", "stealing_attack",
                   "cybercrime", "money_laundering", "blackmail_activities"]

# 主流锚定资产白名单（按链分组）：这些币的 mint 权限属于官方锚定机制
# （充值 1:1 铸造 / 法币储备），由真实储备背书，不算项目方增发后门
KNOWN_PEGGED = {
    "56": {  # BSC
        "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c",  # BTCB
        "0x2170ed0880ac9a755fd29b2688956bd959f933f8",  # ETH
        "0x55d398326f99059ff775485246999027b3197955",  # USDT
        "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",  # USDC
        "0xe9e7cea3dedca5984780bafc599bd69add087d56",  # BUSD
        "0xc5f0f7b66764f6ec8c0dffba8a602c790a649b89",  # FDUSD
        "0x1af3f329e8be154074d8769d06ffa9a48c7a8d55",  # DAI
        "0xa2e3356610840701bdf5611a539f8356ca64c141",  # WBETH
    },
    "1": {   # Ethereum
        "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
        "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH
        "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",  # WBTC
    },
    "137": {  # Polygon
        "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",  # USDT
        "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",  # USDC
        "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063",  # DAI
    },
    "42161": {  # Arbitrum
        "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",  # USDT
        "0xaf88d065e77c8cc2239327c5edb3a432268e5831",  # USDC
        "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",  # WETH
    },
    "8453": {  # Base
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",  # USDC
        "0x4200000000000000000000000000000000000006",  # WETH
    },
    "10": {  # Optimism
        "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58",  # USDT
        "0x0b2c639c533813f4aa9d7837caf62653d097ff85",  # USDC
        "0x4200000000000000000000000000000000000006",  # WETH
    },
}

# ===== 缓存 =====
QUERY_CACHE_TTL = 60      # 同 CA 60 秒内不重复打 API
QUERY_CACHE_MAX = 10000
ADDR_CACHE_MAX = 20000
# 地址缓存必须有过期：合约/EOA 是事实，但"恶意标记"会更新；
# 更重要的是判定逻辑升级后，长驻实例不该继续吃旧语义的缓存。
ADDR_CACHE_TTL = 6 * 3600
# 同一目标同一 CA 多久内只回一次：DeBox 超时重试通常发生在 10~60 秒后，
# 期间结果已进缓存，不去重就会把同一份报告推两遍
REPLY_DEDUP_TTL = 45

# ===== 执行模式 =====
# async：webhook 立即返回 200，查币丢线程池（长驻进程必须用这个，DeBox 侧超时会重试）
# sync ：同步跑完整条查询链（Serverless 只能用这个：响应返回后实例即冻结，后台线程会被杀）
# 未显式配置时按部署环境自动选择，见 SERVERLESS_ENV_MARKERS。
QUERY_MODE = os.getenv("QUERY_MODE", "").strip().lower()
SERVERLESS_ENV_MARKERS = ("VERCEL", "AWS_LAMBDA_FUNCTION_NAME",
                          "FC_FUNCTION_NAME", "SCF_FUNCTIONNAME")

# ===== 外链 =====
EXPERIENCE_GROUP_URL = "https://m.debox.pro/group?id=sajshm5d&code=9410sfdk"


# ======================================================================
# 二、基础设施：连接池、线程池、TTL 缓存、工具函数　（源：bot/infra.py）
# ======================================================================
# 基础设施层：共享 HTTP 连接、线程池、TTL 缓存、纯工具函数。
#
# 不含任何业务判定。测试里替换 `infra.SESSION` 即可完全离线跑。

# ===== 共享 HTTP Session：复用 TCP/TLS 连接 + 自动重试 =====
# 每次请求新建并立即关闭 Session 会导致连接既不能复用、也不能自动重试。
# 模块级 Session + Retry：显著降低握手开销，消除偶发超时/限流造成的"数据不足"假阴性。
# Retry 默认只对幂等方法（GET 等）生效、不重试 POST，避免 Upstash 计数被重复自增。
RETRY = Retry(total=2, backoff_factor=0.3, status_forcelist=(429, 500, 502, 503, 504))
SESSION = requests.Session()
for _scheme in ("https://", "http://"):
    SESSION.mount(_scheme, HTTPAdapter(max_retries=RETRY,
                                       pool_connections=32, pool_maxsize=32))

# ===== 共享线程池（模块级复用，避免每个请求现建现弃） =====
# 三层池，职责严格分离，绝不能互相嵌套：
#   QUERY_EXECUTOR —— 只跑"一次完整查询"（外层任务）
#   SUB_EXECUTOR   —— 只跑查询内部的并行子调用（持仓分类 / 前科查询 / 多链探测）
#   STATS_EXECUTOR —— 只跑统计上报，必须与查询隔离，不能拖慢也不能被拖住
#
# 为什么必须分成两个池：外层任务运行在 QUERY_EXECUTOR 的线程里，它内部要
# `map()` 一批子任务并阻塞等结果。如果子任务提交回同一个池，而此刻池里
# 16 个线程全被外层任务占满，子任务就永远排不到线程 —— 典型线程饥饿死锁，
# 表现为这几个 CA 的查询永久挂起、Webhook 一直不回复，且不会自己恢复。
QUERY_EXECUTOR = ThreadPoolExecutor(max_workers=16, thread_name_prefix="query")
SUB_EXECUTOR = ThreadPoolExecutor(max_workers=32, thread_name_prefix="sub")
STATS_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="stats")


# ===== 查询结果缓存：同 CA 60 秒内不重复打 API =====
QUERY_CACHE = {}
QUERY_CACHE_LOCK = threading.Lock()


def query_cache_get(addr):
    """返回 60 秒内缓存的查询结果 (reply_text, markup)；未命中/已过期返回 None。
    缓存的是结果本身而非时间戳，这样命中时可以把同一条报告回复给任意群/用户。"""
    with QUERY_CACHE_LOCK:
        item = QUERY_CACHE.get(addr)
        if not item:
            return None
        ts, reply_text, markup = item
        if time.time() - ts >= QUERY_CACHE_TTL:
            QUERY_CACHE.pop(addr, None)
            return None
        return reply_text, markup


def query_cache_set(addr, reply_text, markup=None):
    """查询成功后才写入结果；带过期清理与上限保护，防止长期运行内存无限增长。

    到上限时淘汰最旧的 20%，而不是清空：清空会让紧接着的一批请求全部穿透，
    同一时刻打满上游接口（缓存雪崩）。
    """
    now = time.time()
    with QUERY_CACHE_LOCK:
        if len(QUERY_CACHE) >= QUERY_CACHE_MAX:
            expired = [k for k, v in QUERY_CACHE.items()
                       if now - v[0] >= QUERY_CACHE_TTL]
            for k in expired:
                del QUERY_CACHE[k]
            if len(QUERY_CACHE) >= QUERY_CACHE_MAX:
                oldest = sorted(QUERY_CACHE.items(), key=lambda kv: kv[1][0])
                drop = max(1, len(oldest) // 5)
                for k, _v in oldest[:drop]:
                    del QUERY_CACHE[k]
        QUERY_CACHE[addr] = (now, reply_text, markup)


def query_cache_clear():
    with QUERY_CACHE_LOCK:
        QUERY_CACHE.clear()


# ===== 地址分类缓存：合约/EOA 判定结果复用，避免重复打 API =====
ADDR_CACHE = {}
ADDR_CACHE_LOCK = threading.Lock()


def addr_cache_key(addr, chain_id):
    """缓存键含链 ID：同一地址在不同 EVM 链上的合约/EOA 状态可能不同。"""
    return (str(chain_id), addr)


def addr_cache_get(addr, chain_id):
    with ADDR_CACHE_LOCK:
        key = addr_cache_key(addr, chain_id)
        item = ADDR_CACHE.get(key)
        if item is None:
            return None
        if time.time() - item.get("_ts", 0) >= ADDR_CACHE_TTL:
            ADDR_CACHE.pop(key, None)
            return None
        return {k: v for k, v in item.items() if k != "_ts"}


def addr_cache_set(addr, value, chain_id):
    with ADDR_CACHE_LOCK:
        if len(ADDR_CACHE) >= ADDR_CACHE_MAX:
            oldest = sorted(ADDR_CACHE.items(), key=lambda kv: kv[1].get("_ts", 0))
            drop = max(1, len(oldest) // 5)
            for k, _v in oldest[:drop]:
                del ADDR_CACHE[k]
        ADDR_CACHE[addr_cache_key(addr, chain_id)] = {**value, "_ts": time.time()}


def addr_cache_merge(addr, chain_id, **updates):
    with ADDR_CACHE_LOCK:
        key = addr_cache_key(addr, chain_id)
        old = ADDR_CACHE.get(key, {})
        # 合并时刷新时间戳：本次刚拿到的字段是新的，不该被旧时间戳带着一起过期
        merged = {**{k: v for k, v in old.items() if k != "_ts"}, **updates,
                  "_ts": time.time()}
        ADDR_CACHE[key] = merged
        return {k: v for k, v in merged.items() if k != "_ts"}


def addr_cache_clear():
    with ADDR_CACHE_LOCK:
        ADDR_CACHE.clear()


# ===== 在途去重：同一"目标 + CA"同时只跑一次查询 =====
# 只靠 60 秒结果缓存挡不住并发：查询要跑十几秒，DeBox 超时重试的第二条请求
# 会在第一条还没写完缓存时就进来，两条都发消息 → 群里出现重复报告。
INFLIGHT = set()
INFLIGHT_LOCK = threading.Lock()


def inflight_begin(key):
    """抢占在途标记；已有人在查同一个目标同一币时返回 False。"""
    with INFLIGHT_LOCK:
        if key in INFLIGHT:
            return False
        INFLIGHT.add(key)
        return True


def inflight_end(key):
    with INFLIGHT_LOCK:
        INFLIGHT.discard(key)


def inflight_clear():
    with INFLIGHT_LOCK:
        INFLIGHT.clear()


# ===== 回复去重：同一目标同一 CA 短时间内只回一次 =====
# 在途去重只能挡住"同时"，挡不住"第一次已经跑完、DeBox 30 秒后才重试"：
# 那时结果已经进缓存，第二次请求会命中缓存再发一条 → 群里两条一样的报告。
_REPLY_TS = {}
_REPLY_LOCK = threading.Lock()


def should_reply(target, ca_address):
    """同一 (目标, CA) 在 REPLY_DEDUP_TTL 内只回复一次。target 为群/用户 ID。"""
    key = (str(target), ca_address)
    now = time.time()
    with _REPLY_LOCK:
        last = _REPLY_TS.get(key)
        if last is not None and now - last < REPLY_DEDUP_TTL:
            return False
        _REPLY_TS[key] = now
        if len(_REPLY_TS) > 5000:   # 顺手清理，避免长期运行无限增长
            for k, ts in list(_REPLY_TS.items()):
                if now - ts >= REPLY_DEDUP_TTL:
                    del _REPLY_TS[k]
        return True


def reply_dedup_clear():
    with _REPLY_LOCK:
        _REPLY_TS.clear()


def query_mode():
    """返回 "async" 或 "sync"。

    Serverless 上必须同步：响应返回后实例被冻结，后台线程拿不到 CPU，
    用户永远等不到回复。长驻进程用异步：DeBox 侧 10~30 秒必超时，重试会重复推送。
    """
    if QUERY_MODE in ("async", "sync"):
        return QUERY_MODE
    if any(os.getenv(m) for m in SERVERLESS_ENV_MARKERS):
        return "sync"
    return "async"


# ===== 工具函数 =====
def now_bj():
    """北京时间（UTC+8）。"""
    return datetime.now(timezone(timedelta(hours=8)))


def auth_ok(header_key, expected):
    """常量时间比对请求头密钥；任何异常一律视为不通过（fail-closed）。

    不能直接用 hmac.compare_digest(str, str)：HTTP 头按 latin-1 解码，
    一个 0x80~0xFF 的字节就会变成非 ASCII 字符，compare_digest 直接抛
    TypeError → 500。攻击者拿一个字节就能让接口吐堆栈、刷错误日志。
    统一 encode 成 bytes 再比，既能比较，又保留常量时间特性。
    """
    if not expected or not header_key:
        return False
    try:
        return hmac.compare_digest(str(header_key).encode("utf-8"),
                                   str(expected).encode("utf-8"))
    except Exception:
        return False


def fmt_money(n):
    try:
        n = float(n)
        if n >= 1000000:
            return f"${n/1000000:.2f}M"
        if n >= 1000:
            return f"${n/1000:.1f}K"
        return f"${n:.2f}"
    except (TypeError, ValueError):
        return "$0.00"


def to_float(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def calc_growth(current, previous):
    if previous == 0:
        return "🟢 +100%" if current > 0 else "0%"
    growth = ((current - previous) / previous) * 100
    icon = "🟢 +" if growth >= 0 else "🔴 "
    return f"{icon}{growth:.1f}%"


def fire_and_forget(fn, *args, **kwargs):
    """把慢速的外部统计写入丢到后台线程，避免拖慢 Webhook 响应。"""
    try:
        STATS_EXECUTOR.submit(fn, *args, **kwargs)
    except Exception as e:
        print(f"[stats] 后台任务提交失败: {e}")


# ======================================================================
# 三、钓鱼黑名单：多源拉取与匹配　（源：bot/blocklist.py）
# ======================================================================
# 钓鱼域名黑名单：多源拉取（MetaMask + ScamSniffer）+ 本地匹配。
#
# 数据源故障时保留旧缓存，绝不因上游挂掉而漏报已确认的钓鱼站。

CACHE = {"domains": set(), "ts": 0.0, "loaded": False}
CACHE_LOCK = threading.Lock()   # 保护缓存读写
REFRESH_LOCK = threading.Lock()  # 保证同时只有一个线程在下载


def load_phishing_blocklist():
    """拉取并合并 MetaMask 与 ScamSniffer 黑名单。
    两个源均为 JSON：MetaMask 取 blacklist 字段，ScamSniffer 直接是域名数组。"""
    domains = set()
    try:
        res = SESSION.get(METAMASK_BLACKLIST_URL, timeout=25)
        res.raise_for_status()
        data = res.json()
        domains.update(str(d).strip().lower().strip(".") for d in (data.get("blacklist") or []))
    except Exception as e:
        print(f"[phishing] MetaMask 黑名单拉取失败: {e}")
    try:
        res = SESSION.get(SCAMSNIFFER_BLACKLIST_URL, timeout=25)
        res.raise_for_status()
        data = res.json()
        if isinstance(data, list):
            domains.update(str(d).strip().lower().strip(".") for d in data)
    except Exception as e:
        print(f"[phishing] ScamSniffer 黑名单拉取失败: {e}")
    return domains


def refresh_phishing_blocklist(force=False, wait=False):
    """加载/刷新黑名单。失败时保留旧缓存，绝不因数据源故障而漏报已确认的钓鱼站。
    wait=True 时阻塞等待下载完成（供外部定时刷新接口使用）；否则非阻塞，请求线程快速返回旧缓存。"""
    now = time.time()
    with CACHE_LOCK:
        if not force and CACHE["loaded"] and now - CACHE["ts"] < PHISHING_LIST_TTL:
            return CACHE["domains"]
    if not REFRESH_LOCK.acquire(blocking=wait):
        # 已有线程在刷新，直接返回现有缓存（可能为空/稍旧，但绝不阻塞请求线程）
        with CACHE_LOCK:
            return CACHE["domains"]
    if not wait:
        # 非阻塞调用且手里已有旧数据：立刻把旧数据还给请求线程，下载丢给后台。
        # 原实现在这里同步下载（两个源各 25s），TTL 一到，第一条带链接的群消息
        # 就会被卡住最长 50 秒 —— 和 docstring 承诺的"快速返回旧缓存"完全相反。
        with CACHE_LOCK:
            has_data = CACHE["loaded"]
        if has_data:
            REFRESH_LOCK.release()
            threading.Thread(target=refresh_phishing_blocklist,
                             kwargs={"force": True, "wait": True}, daemon=True).start()
            with CACHE_LOCK:
                return CACHE["domains"]
    try:
        domains = load_phishing_blocklist()
        if domains:  # 只有拉到了新数据才更新缓存
            with CACHE_LOCK:
                CACHE.update({"domains": domains, "ts": time.time(), "loaded": True})
            print(f"[phishing] 黑名单已加载 {len(domains)} 个域名")
    finally:
        REFRESH_LOCK.release()
    with CACHE_LOCK:
        return CACHE["domains"]


def get_phishing_blocklist():
    return refresh_phishing_blocklist(force=False)


def check_domain_in_blocklist(domain):
    """精确匹配 + 子域匹配（如 evil.uniswap.com 命中 uniswap.com 的变体子域）。"""
    bl = get_phishing_blocklist()
    if not bl:
        return False
    if domain in bl:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        if ".".join(parts[i:]) in bl:
            return True
    return False


def set_blocklist(domains):
    """测试/应急用：直接注入一份域名集合。"""
    with CACHE_LOCK:
        CACHE.update({"domains": set(domains), "ts": time.time(), "loaded": True})


_WARMED_PID = None


def start_background_tasks():
    """启动时预热一次黑名单（daemon 线程，失败不影响主流程）。
    之后的定时刷新由外部 cron / 云函数定时器调用 POST /refresh-blocklist 完成。

    幂等，但按 **PID** 判断而不是用 Event：gunicorn --preload 会先导入再 fork，
    fork 会把 Event 的"已触发"状态一起复制过去，子进程里就再也不会预热了；
    而 fork 只复制主线程，那条预热线程在子进程里根本不存在 ——
    结果是每个 worker 的首条消息都要同步等 10~30 秒下载黑名单。
    """
    global _WARMED_PID
    pid = os.getpid()
    if _WARMED_PID == pid:
        return
    _WARMED_PID = pid
    threading.Thread(target=refresh_phishing_blocklist,
                     kwargs={"force": True}, daemon=True).start()


# ======================================================================
# 四、取数：所有出站请求（DexScreener / GoPlus / RPC / DeBox / Upstash）　（源：bot/fetch.py）
# ======================================================================
# 取数层：所有出站网络请求集中在这里。
#
# 只负责"拿数据、失败返回空值"，不做任何风险判定、不拼接文案。
# 想离线测试，替换 `infra.SESSION` 即可。

# ================= DexScreener =================
def dexscreener_pairs(ca_address, tag="EVM"):
    """拉取代币的全部交易对；失败返回 []。"""
    url = f"https://api.dexscreener.com/latest/dex/tokens/{ca_address}"
    try:
        res = SESSION.get(url, timeout=5)
        res.raise_for_status()
        return res.json().get("pairs", []) or []
    except Exception as e:
        print(f"[query] DexScreener{' SOL' if tag == 'SOL' else ''} 异常: {e}")
        return []


# ================= GoPlus =================
def goplus_evm(chain_id, ca_address):
    """查询 GoPlus EVM 安全数据，失败返回 {}"""
    url = f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={ca_address}"
    try:
        res = SESSION.get(url, timeout=5)
        res.raise_for_status()
        data = res.json()
        if data.get("code") == 1 and data.get("result"):
            return data["result"].get(ca_address.lower(), {}) or {}
    except Exception as e:
        print(f"[query] GoPlus EVM 异常: {e}")
    return {}


def goplus_solana(ca_address):
    """查询 GoPlus Solana 安全数据，失败返回 {}"""
    url = f"https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses={ca_address}"
    try:
        res = SESSION.get(url, timeout=5)
        res.raise_for_status()
        data = res.json()
        if data.get("code") == 1 and data.get("result"):
            return data["result"].get(ca_address, {}) or {}
    except Exception as e:
        print(f"[query] GoPlus SOL 异常: {e}")
    return {}


def goplus_address_security(addr, chain_id):
    """查询地址安全画像，失败抛异常（由调用方决定降级策略）。"""
    res = SESSION.get(
        f"https://api.gopluslabs.io/api/v1/address_security/{addr}?chain_id={chain_id}",
        timeout=5)
    res.raise_for_status()
    return res.json().get("result", {}) or {}


def goplus_phishing_site(domain):
    """GoPlus 实时钓鱼接口：确认钓鱼返回 True，其余（含超时/字段缺失）返回 False。"""
    resp = SESSION.get(
        f"https://api.gopluslabs.io/api/v1/phishing_site?url=https://{domain}", timeout=3)
    resp.raise_for_status()
    g_data = resp.json()
    result = g_data.get("result") or {}
    phishing_flag = None
    if isinstance(result, dict):
        if result.get("phishing_site") is not None:
            phishing_flag = str(result.get("phishing_site"))
        else:
            for v in result.values():
                if isinstance(v, dict) and v.get("phishing_site") is not None:
                    phishing_flag = str(v.get("phishing_site"))
                    break
    return g_data.get("code") == 1 and phishing_flag == "1"


# ================= 链上 RPC =================
def is_contract_via_rpc(addr, chain_id):
    """链上终极验证：eth_getCode 有代码 = 合约。数据来自节点，不依赖任何索引商。
    节点返回 JSON-RPC 错误/限流时继续尝试下一个节点，避免误判为 EOA。"""
    for rpc in RPC_ENDPOINTS.get(str(chain_id), []):
        try:
            res = SESSION.post(rpc, json={
                "jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
                "params": [addr, "latest"]
            }, timeout=5).json()
            if res.get("error") is not None or res.get("result") is None:
                continue  # 节点异常/限流 → 换下一个
            return res["result"] != "0x"  # 有代码 → 合约
        except Exception:
            continue
    return None  # 所有节点都失败 → 无法判定


# ================= DeBox 发送 =================
def send_message(chat_type, chat_id, content, reply_markup=None):
    url = "https://open.debox.pro/openapi/bot/sendMessage"
    headers = {"Content-Type": "application/json", "X-API-KEY": APP_KEY}
    payload = {"chat_type": chat_type, "chat_id": chat_id, "content": content, "parse_mode": "text"}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        res = SESSION.post(url, json=payload, headers=headers, timeout=10)
        if res.status_code != 200:
            print(f"[send] 发送失败 status={res.status_code} body={res.text[:200]}")
    except Exception as e:
        print(f"==== 发送消息异常: {e} ====")


# ================= 运营统计（Upstash） =================
def _do_record_realtime_group(group_id):
    try:
        # 写操作用 POST：GET 可能被 CDN/代理缓存导致统计不更新
        SESSION.post(
            f"{UPSTASH_URL}/sadd/all_groups/{group_id}",
            headers=UPSTASH_HEADERS, timeout=3)
    except Exception as e:
        print(f"[stats] record_realtime_group 异常: {e}")


def record_realtime_group(group_id):
    if not UPSTASH_URL or not UPSTASH_TOKEN or not group_id:
        return
    fire_and_forget(_do_record_realtime_group, group_id)


def _do_record_user_activity(user_id):
    now = now_bj()
    today_str = now.strftime("%Y%m%d")
    start_of_week = now - timedelta(days=now.weekday())
    week_str = start_of_week.strftime("%Y%m%d")
    month_str = now.strftime("%Y%m")
    try:
        # 写操作一律用 POST：GET 可能被 CDN/代理缓存，导致统计不更新
        SESSION.post(
            f"{UPSTASH_URL}/sadd/all_users/{user_id}",
            headers=UPSTASH_HEADERS, timeout=3)
        SESSION.post(
            f"{UPSTASH_URL}/incr/total_queries",
            headers=UPSTASH_HEADERS, timeout=3)
        SESSION.post(
            f"{UPSTASH_URL}/sadd/active_daily_{today_str}/{user_id}",
            headers=UPSTASH_HEADERS, timeout=3)
        SESSION.post(
            f"{UPSTASH_URL}/sadd/active_weekly_{week_str}/{user_id}",
            headers=UPSTASH_HEADERS, timeout=3)
        SESSION.post(
            f"{UPSTASH_URL}/sadd/active_monthly_{month_str}/{user_id}",
            headers=UPSTASH_HEADERS, timeout=3)
    except Exception as e:
        print(f"[stats] record_user_activity 异常: {e}")


def record_user_activity(user_id):
    if not UPSTASH_URL or not UPSTASH_TOKEN or not user_id:
        return
    fire_and_forget(_do_record_user_activity, user_id)


def get_cardinality(key):
    if not UPSTASH_URL:
        return 0
    try:
        res = SESSION.get(
            f"{UPSTASH_URL}/scard/{key}",
            headers=UPSTASH_HEADERS, timeout=3).json()
        return res.get("result", 0)
    except Exception as e:
        print(f"[stats] get_cardinality({key}) 异常: {e}")
        return 0


def get_value(key):
    if not UPSTASH_URL:
        return None
    try:
        res = SESSION.get(
            f"{UPSTASH_URL}/get/{key}",
            headers=UPSTASH_HEADERS, timeout=3).json()
        return res.get("result")
    except Exception as e:
        print(f"[stats] get({key}) 异常: {e}")
        return None


def get_usage_stats():
    now = now_bj()
    today = now.strftime("%Y%m%d")
    yesterday = (now - timedelta(days=1)).strftime("%Y%m%d")
    this_week = (now - timedelta(days=now.weekday())).strftime("%Y%m%d")
    last_week = (now - timedelta(days=now.weekday() + 7)).strftime("%Y%m%d")
    this_month = now.strftime("%Y%m")
    last_month = (now.replace(day=1) - timedelta(days=1)).strftime("%Y%m")

    # 并发拉取所有基数指标 + 累计查询数，把串行 8 次请求压到 1 轮
    keys = {
        "total_groups": "all_groups",
        "total_users": "all_users",
        "today": f"active_daily_{today}",
        "yesterday": f"active_daily_{yesterday}",
        "this_week": f"active_weekly_{this_week}",
        "last_week": f"active_weekly_{last_week}",
        "this_month": f"active_monthly_{this_month}",
        "last_month": f"active_monthly_{last_month}",
    }
    futures = {name: STATS_EXECUTOR.submit(get_cardinality, key)
               for name, key in keys.items()}
    q_future = STATS_EXECUTOR.submit(get_value, "total_queries")
    card = {name: f.result() for name, f in futures.items()}

    stats = {
        "total_groups": card["total_groups"],
        "total_users": card["total_users"],
        "total_queries": int(q_future.result() or 0),
    }

    today_active = card["today"]
    yesterday_active = card["yesterday"]
    this_week_active = card["this_week"]
    last_week_active = card["last_week"]
    this_month_active = card["this_month"]
    last_month_active = card["last_month"]

    stats["daily_str"] = f"{today_active} 人 (较昨日 {calc_growth(today_active, yesterday_active)})"
    stats["weekly_str"] = f"{this_week_active} 人 (较上周 {calc_growth(this_week_active, last_week_active)})"
    stats["monthly_str"] = f"{this_month_active} 人 (较上月 {calc_growth(this_month_active, last_month_active)})"
    return stats


# ======================================================================
# 五、判定：地址识别、域名研判、持仓分类、风险规则　（源：bot/judge.py）
# ======================================================================
# 判定层：地址识别、域名研判、持仓分类、风险规则。
#
# 原则：这里不做网络请求（只通过 fetch 取已拿到的数据），不拼最终文案。
# `build_evm_lines` / `build_solana_lines` 拿到 info 就能算出结论，方便用 fixture 单测。

# ================= 地址识别 =================
def is_valid_solana_address(addr):
    if not isinstance(addr, str) or not (32 <= len(addr) <= 44):
        return False
    num = 0
    try:
        for ch in addr:
            num = num * 58 + BASE58_ALPHABET.index(ch)
    except ValueError:
        return False
    leading_zeros = 0
    for ch in addr:
        if ch == '1':
            leading_zeros += 1
        else:
            break
    if num == 0:
        byte_len = leading_zeros
    else:
        byte_len = leading_zeros + (num.bit_length() + 7) // 8
    return byte_len == 32


def extract_valid_ca(message):
    """剔除 URL 后提取第一个通过校验的 CA 地址"""
    cleaned = URL_PATTERN.sub(" ", message)
    for m in CA_PATTERN.finditer(cleaned):
        addr = m.group()
        if addr.startswith("0x") or is_valid_solana_address(addr):
            return addr
    return None


# ================= 仿冒域名 =================
def _levenshtein(a, b):
    """编辑距离（纯 Python 实现，域名短字符串足够快）。"""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur = [i + 1]
        for j, cb in enumerate(b):
            cur.append(min(prev[j + 1] + 1, cur[j] + 1, prev[j] + (ca != cb)))
        prev = cur
    return prev[-1]


def check_domain_lookalike(domain):
    """识别与主流站点高度相似的仿冒域名。
    规则（按 MetaMask fuzzy 思路简化）：
    - 域名长度 <= 8：编辑距离 1 即报警（短域名错一个字母就很可疑）
    - 域名长度 9-15：编辑距离 <= 2
    - 更长域名：编辑距离 <= 2 且长度差 <= 2
    返回命中的合法域名，未命中返回 None。"""
    core = domain.split(".")[0]  # 取主域部分比对
    for brand in TRUSTED_BRAND_DOMAINS:
        brand_core = brand.split(".")[0]
        # 官方域名出现在开头、后面还接别的域名（metamask.io.evil.com）：
        # 正规站点不会有"官方域名.别人的域名"这种结构，这是经典钓法。
        # 必须放在 core == brand_core 那条之前 —— 它的 core 也是 "metamask"，
        # 会被"同名不同后缀不硬判"的规则提前 continue 掉。
        if domain.startswith(brand + "."):
            return brand
        # 完全相同或就是其子域 → 合法，跳过
        if domain == brand or domain.endswith("." + brand):
            continue
        # 品牌名完全相同、只是后缀不同（binance.us / binance.org / okx.us）：
        # 官方地区站与抢注站长得一样，本地规则无法区分，交给黑名单与 GoPlus 判定，
        # 不在这里硬判 —— 曾把官方 binance.us 报成"仿冒 binance.com"。
        if core == brand_core:
            continue
        dist = _levenshtein(core, brand_core)
        limit = 1 if len(brand_core) <= 8 else 2
        if dist <= limit and abs(len(core) - len(brand_core)) <= 2:
            return brand
        # 连字符/拼接仿冒：按分隔符拆词，品牌名是一个词，其余是典型骗子词汇
        # 如 metamask-io.app、uniswap-exchange.net、okx-earn.vip（纯拼接如 sushiswap 不误伤）
        tokens = re.split(r"[-_.]", core)
        if brand_core in tokens and len(tokens) >= 2 and all(
            t == brand_core or t in IMPERSONATION_TOKENS or t.isdigit() for t in tokens
        ):
            return brand
    return None


# ================= 持仓地址分类 =================
def classify_holder(addr, chain_id):
    """判断持仓地址是否为合约地址（交易所/质押池/金库等通常是合约或平台地址）"""
    addr = (addr or "").lower()
    if not addr.startswith("0x"):
        return {"is_contract": False}
    cached = addr_cache_get(addr, chain_id)
    # 缓存可能是"只写了 flags 的半成品"（创建者查询留下的），必须确有 is_contract 才可复用
    if cached and "is_contract" in cached:
        return cached
    try:
        info = goplus_address_security(addr, chain_id)
        # 实测字段名为 contract_address（"1"=合约）；兼容 is_contract 命名
        is_contract = info.get("contract_address") == "1" or info.get("is_contract") == "1"
        # 关键补刀：GoPlus 无索引数据时（data_source 为空），"0"只是默认值不可信，
        # 必须用链上 eth_getCode 验证——V3 池子合约等未索引地址全靠这步洗清冤屈
        if not is_contract and not info.get("data_source"):
            rpc_result = is_contract_via_rpc(addr, chain_id)
            if rpc_result is not None:
                is_contract = rpc_result
    except Exception as e:
        print(f"[query] address_security 异常: {e}")
        # 查不到时按个人地址处理，不放大风险；
        # 但绝不写缓存 —— 一次接口抖动不该让该地址永久被当成 EOA（会误报"死控盘"）
        return {"is_contract": False}
    out = {"is_contract": is_contract}
    # 用 merge 而不是 set：保留此前写入的 flags，避免互相覆盖
    addr_cache_merge(addr, chain_id, **out)
    return out


# ================= EVM 判定 =================
def build_evm_lines(info, chain_id=None, ca_address=None):
    """根据 GoPlus 数据生成元信息条目、异常审计项、风险标签列表"""
    risks = []
    buy_tax = to_float(info.get("buy_tax")) * 100
    sell_tax = to_float(info.get("sell_tax")) * 100
    holders = [(h.get("address", "") or "", to_float(h.get("percent")) * 100)
               for h in (info.get("holders") or [])[:10]
               if (h.get("address", "") or "").lower() not in BURN_ADDRESSES]
    top10_pct = sum(pct for _, pct in holders)

    # 细化：前10里拆出合约地址（质押池/金库/交易所等）与个人地址（并行查询不拖慢回复）
    contract_pct = 0.0
    if holders and chain_id:
        results = list(SUB_EXECUTOR.map(lambda ap: classify_holder(ap[0], chain_id), holders))
        contract_pct = sum(pct for (addr, pct), r in zip(holders, results) if r["is_contract"])
        eoa_pct = top10_pct - contract_pct
    else:
        eoa_pct = top10_pct

    if contract_pct > 0:
        holders_str = f"{top10_pct:.1f}%（个人 {eoa_pct:.1f}% / 合约 {contract_pct:.1f}%）"
    else:
        holders_str = f"{top10_pct:.1f}%"

    # LP 锁仓：池子代币（LP）被锁定的比例。
    # 注意：交易所官方流动性（BTCB）与 V3 集中流动性（PancakeSwap V3）不走锁仓合约，
    # is_locked 全为 0 但并非"可撤池跑路"，0% 一律视为"无法判定"，不显示不报警，
    # 只有明确检测到锁仓记录（>0%）才据此展示与判断，避免冤枉主流币。
    lp_locked_pct = None
    lp_holders = info.get("lp_holders") or []
    if lp_holders:
        locked = sum(to_float(h.get("percent")) * 100 for h in lp_holders
                     if str(h.get("is_locked")) == "1")
        if locked > 0:
            lp_locked_pct = min(locked, 100.0)

    # 盲区补刀：锁仓记录全 0 时，查 LP 最大持有者身份。
    # 个人地址(EOA)独占大额 LP = 项目方可随时撤池 → 报"LP集中个人"；
    # 合约地址（交易所/金库/锁仓合约，如币安钱包）→ 正常，不报警
    lp_personal_warn = False
    if lp_holders and lp_locked_pct is None and chain_id:
        real_lp = [h for h in lp_holders
                   if (h.get("address", "") or "").lower() not in BURN_ADDRESSES]
        if real_lp:
            top_lp = max(real_lp, key=lambda h: to_float(h.get("percent")))
            top_lp_pct = to_float(top_lp.get("percent")) * 100
            if top_lp_pct > 50 and not classify_holder(top_lp.get("address", ""), chain_id)["is_contract"]:
                lp_personal_warn = True

    # 持有人总数：热度数据，与安全无关，不展示（保持报告纯安全视角）
    # holder_count = int(to_float(info.get("holder_count")))

    meta_items = [
        ("🩸 税率", f"{buy_tax:.1f}% / {sell_tax:.1f}%"),
        ("👥 前10", holders_str),
    ]
    if lp_locked_pct is not None:
        icon = "🔒" if lp_locked_pct >= 80 else ("🔓" if lp_locked_pct <= 20 else "⚠️")
        meta_items.append((f"{icon} LP锁仓", f"{lp_locked_pct:.1f}%"))

    # 审计分级：致命❌ / 可控⚠️ / 未知➖；全绿时不显示审计段落
    # 致命项：存在即可被利用造成直接损失
    fatal_defs = [
        ("开源", info.get("is_open_source"), "1", "未开源"),
        ("改余额", info.get("owner_change_balance"), "0", "可改余额"),
        ("藏Owner", info.get("hidden_owner"), "0", "隐藏Owner"),
        ("收回权", info.get("can_take_back_ownership"), "0", "可收回权限"),
        ("增发", info.get("is_mintable"), "0", "增发"),
        ("黑名单", info.get("is_blacklisted"), "0", "黑名单"),
    ]
    # 可控项：权限存在但不必然后门，仅提示留意
    # 与致命项逻辑不同：数据缺失不算"未知"（缺失≠风险，GoPlus 覆盖不全很常见），
    # 只有明确查到 "1" 才提示，避免常驻噪音
    # （致命项必须保留未知栏：如"开源"没查到，无法确认安全，缺失本身就是风险信号）
    warn_defs = [
        ("暂停", info.get("transfer_pausable"), "暂停交易"),
        ("白名单", info.get("is_whitelisted"), "白名单限制"),
        ("代理", info.get("is_proxy"), "代理合约"),
    ]

    fatal_items, warn_items, unknown_items = [], [], []

    # 创建者/Owner 背景核查：合约可以写得干净，但惯犯开的合约一票否决
    # 检查 creator_address 与 owner_address 的恶意前科（钓鱼/盗窃/网诈/洗钱）
    suspicious_roles = []

    def _fetch_malicious_flags(ra, cid):
        """查询地址恶意标记，结果写入缓存（键含链 ID）。"""
        cached = addr_cache_get(ra, cid) or {}
        if "flags" in cached:
            return cached["flags"]
        bad_flags = []
        try:
            rinfo = goplus_address_security(ra, cid)
            if rinfo.get("data_source"):  # 有真实索引数据才采信，默认值不算数
                bad_flags = [f for f in MALICIOUS_FLAGS if str(rinfo.get(f)) == "1"]
        except Exception:
            bad_flags = []
        # 只合并 flags：绝不能在这里写 is_contract。
        # 此处地址只是"创建者/Owner"，从未做过合约判定，写 False 会污染缓存，
        # 导致它日后作为持币大户时被当成个人地址（误报"死控盘"）。
        merge = {"flags": bad_flags}
        if "is_contract" in cached:
            merge["is_contract"] = cached["is_contract"]
        addr_cache_merge(ra, cid, **merge)
        return bad_flags

    # 并发查询创建者/Owner 前科（与持币地址一致走线程池：最坏 10s → 5s）
    role_addrs = [(role, (addr or "").lower())
                  for role, addr in (("创建者", info.get("creator_address")),
                                     ("Owner", info.get("owner_address")))
                  if ((addr or "").lower()).startswith("0x")]
    if role_addrs:
        flag_results = list(SUB_EXECUTOR.map(
            lambda item: _fetch_malicious_flags(item[1], chain_id), role_addrs))
        for (role, ra), bad_flags in zip(role_addrs, flag_results):
            if bad_flags:
                suspicious_roles.append(f"{role}涉黑")
    if suspicious_roles:
        fatal_items.extend(suspicious_roles)
        risks.append("创建者有前科")

    for name, val, safe_when, risk_label in fatal_defs:
        # 主流锚定币的增发是官方锚定机制（充值 1:1 铸造），不算后门，直接跳过
        if name == "增发" and chain_id and ca_address \
                and ca_address.lower() in KNOWN_PEGGED.get(chain_id, set()):
            continue
        if val is None or str(val) == "":
            unknown_items.append(name)
        elif str(val) != safe_when:
            fatal_items.append(name)
            risks.append(risk_label)
    for name, val, warn_label in warn_defs:
        if str(val) == "1":
            warn_items.append(warn_label)

    # 自毁：同可控项逻辑，仅明确查到 "1" 时提示，缺失不进未知栏
    if str(info.get("self_destruct") or "") == "1":
        warn_items.append("可自毁")

    # LP 锁仓过低：项目方可随时撤池，属可控偏高风险
    if lp_locked_pct is not None and lp_locked_pct <= 20:
        warn_items.append("LP未锁")

    # LP 集中在个人地址：无锁仓记录但 LP 握在项目方个人钱包里，随时可撤
    if lp_personal_warn:
        warn_items.append("LP集中个人")

    if info.get("is_honeypot") == "1":
        risks.append("貔貅")
    if buy_tax > 10 or sell_tax > 10:
        risks.append("高税")
    # 死控盘只看个人地址（EOA）持仓：合约持仓多为质押池/金库/交易所，不直接算砸盘风险
    if eoa_pct > 80:
        risks.append("死控盘")

    return meta_items, (fatal_items, warn_items, unknown_items), risks


# ================= Solana 判定 =================
def build_solana_lines(info, meta_items, risks):
    """根据 GoPlus Solana 数据生成审计项；meta_items / risks 原地追加（与原实现一致）"""
    fatal_items, warn_items, unknown_items = [], [], []
    if not info:
        return fatal_items, warn_items, unknown_items

    mint_status = (info.get("mintable") or {}).get("status", "")
    freeze_status = (info.get("freezable") or {}).get("status", "")
    close_status = (info.get("closable") or {}).get("status", "")
    holders = info.get("holders", []) or []
    top10_pct = sum(to_float(h.get("percent")) * 100 for h in holders[:10])

    meta_items.append(("👥 前10", f"{top10_pct:.1f}%"))

    # 分级：Mint/Freeze 可增发/冻结他人资产=致命；Close 仅提示
    if mint_status == "1":
        fatal_items.append("Mint未弃")
        risks.append("Mint未放弃")
    elif mint_status == "":
        unknown_items.append("Mint")
    if freeze_status == "1":
        fatal_items.append("Freeze未弃")
        risks.append("Freeze未放弃")
    elif freeze_status == "":
        unknown_items.append("Freeze")
    if close_status == "1":
        warn_items.append("Close未弃")
    if top10_pct > 80:
        risks.append("死控盘")
    return fatal_items, warn_items, unknown_items


def risk_level(risks, warn_items, unknown_items):
    """三级风险定级：red=极高危 / orange=需留意 / green=安全"""
    if risks:
        return "red"
    if warn_items or unknown_items:
        return "orange"
    return "green"


# ======================================================================
# 六、渲染：把判定结果拼成文案　（源：bot/render.py）
# ======================================================================
# 渲染层：把判定结果拼成最终文案。
#
# 纯字符串函数，输入输出都是数据 —— 改文案永远不会碰到判定逻辑。

# 最终版式：标题无装饰杠杠，等级靠 🐕/⚠️/🚨/❓ 区分
LEVEL_STYLE = {
    "red":     {"title": "🚨 链上警犬 · 极度危险"},
    "orange":  {"title": "⚠️ 链上警犬 · 需留意"},
    "green":   {"title": "🐕 链上警犬 · 安全报告"},
    "unknown": {"title": "❓ 链上警犬 · 数据不足"},
}


def assemble_report(meta_items, audit, risks, low_liq=False, dex_url=None, no_data=False):
    """海报式卡片：分级标题 + 图标键值对 + 审计分级段落；no_data=True 表示安全数据完全查不到"""
    fatal_items, warn_items, unknown_items = audit

    if no_data:
        # 安全数据完全查不到（GoPlus 无此合约），不能装作"扫描通过"误导用户
        lines = [LEVEL_STYLE["unknown"]["title"]]
        for label, value in meta_items:
            lines.append(f"{label}　{value}")
        lines.append("▱▱▱▱▱▱▱▱▱▱")
        lines.append("❓ 数据不足，无法判定（可能是未上线的新币，请谨慎）")
        return "\n".join(lines)

    level = risk_level(risks, warn_items, unknown_items)
    # 池子太小 → 至少黄色：捞不起来 ≠ 资金危险。
    # 曾把它塞进 risks，导致 $300 池子的干净新币被报"极度危险，千万别碰"。
    if low_liq and level == "green":
        level = "orange"
    style = LEVEL_STYLE[level]

    if risks:
        conclusion = f"🚨 极度危险（{'、'.join(risks)}），千万别碰！"
    elif warn_items:
        conclusion = "⚠️ 有需留意的可控项，自行判断"
    elif unknown_items:
        # 标题已经是"需留意"，结尾不能再说"扫描通过" —— 自相矛盾会让人以为没事
        conclusion = "⚠️ 数据不全，无法完全判定，自行判断"
    elif low_liq:
        conclusion = "💧 池子太小，易被砸盘/撤池，谨慎参与"
    else:
        conclusion = "✅ 扫描通过，自行判断"

    lines = [style["title"]]
    for label, value in meta_items:
        lines.append(f"{label}　{value}")
    lines.append("▱▱▱▱▱▱▱▱▱▱")

    # 审计按优先级显示：有致命项时只显示致命项（其他项再好，随时可被后门利用，无参考价值）
    if fatal_items:
        lines.append(f"❌ 致命　{' | '.join(fatal_items)}")
    else:
        if warn_items:
            lines.append(f"⚠️ 可控　{' | '.join(warn_items)}")
        if unknown_items:
            # 未知项太多时只报数量（新币数据索引中，全列出来是一大坨）
            if len(unknown_items) > 4:
                lines.append(f"➖ 未知　{len(unknown_items)} 项（数据索引中）")
            else:
                lines.append(f"➖ 未知　{' | '.join(unknown_items)}")

    lines.append(conclusion)
    return "\n".join(lines)


def help_text():
    return (
        "🐕‍🦺 链上警犬使用说明\n\n"
        "👉 查代币安全：直接在群内发送合约地址（支持 EVM 0x 开头 及 Solana Base58 地址），警犬会立刻帮你排雷。\n"
        "👉 防钓鱼雷达：群内出现不明链接，警犬会自动调用安全接口拦截。\n"
        "👉 深度数据：自动聚合全链池子，EVM 检测貔貅/税率/锁仓，Solana 检测 Mint/Freeze 权限。\n\n"
        "💡 觉得好用？点击下方链接加入产品体验群，获取最新功能！\n"
        f"🔗 体验群链接：{EXPERIENCE_GROUP_URL}"
    )


def admin_text(stats, hhmm):
    return (
        f"📊 链上警犬 · 实时运营看板\n\n"
        f"👥 服务群组 (实时): {stats['total_groups']} 个\n"
        f"🔍 累计查币次数: {stats['total_queries']:,} 次\n"
        f"🧑‍💻 累计独立用户: {stats['total_users']:,} 人\n\n"
        f"📈 活跃用户环比 (日/周/月):\n"
        f"🔸 今日: {stats['daily_str']}\n"
        f"🔸 本周: {stats['weekly_str']}\n"
        f"🔸 本月: {stats['monthly_str']}\n\n"
        f"数据更新于 {hhmm}"
    )


# ======================================================================
# 七、编排：取数 → 判定 → 渲染　（源：bot/pipeline.py）
# ======================================================================
# 编排层：取数 → 判定 → 渲染，输出一条可直接发送的文本。
#
# 这里只描述"顺序"，不含规则细节。改规则去 judge，改文案去 render。

def _liq_of(pair):
    return to_float((pair.get("liquidity") or {}).get("usd"))


def _own_pairs(pairs, ca_address):
    """只统计本代币作为基础代币(baseToken)的池子：
    排除"别的代币拿它当计价货币"的池子，那些流动性不属于本代币。"""
    own = [p for p in pairs
           if (p.get("baseToken") or {}).get("address", "").lower() == ca_address.lower()]
    return own or pairs


def get_token_full_info(ca_address):
    """返回 (报告文本, reply_markup 或 None)"""
    if not ca_address.startswith("0x"):
        return get_solana_token_info(ca_address)

    dex_url = f"https://api.dexscreener.com/latest/dex/tokens/{ca_address}"
    pairs = _own_pairs(dexscreener_pairs(ca_address), ca_address)

    low_liq = False
    dex_page = None
    if pairs:
        best_pair = max(pairs, key=_liq_of)
        dex_chain = best_pair.get("chainId", "bsc")
        chain_id = CHAIN_MAPPING.get(dex_chain)
        chain_name = CHAIN_NAMES.get(chain_id, dex_chain.upper())
        symbol = (best_pair.get("baseToken") or {}).get("symbol", "未知")
        total_liq = sum(_liq_of(p) for p in pairs)
        if total_liq < 1000:
            low_liq = True
        # 详情页直达链接（DexScreener 交易对页）
        dex_page = best_pair.get("url") or dex_url
    else:
        # 无行情（极早期）：并发探测所有支持的链，尽快拿到安全数据（最坏 35s → 约 5s）
        chain_id, chain_name, symbol = None, "", "未知"
        chain_ids = list(CHAIN_MAPPING.values())
        probes = list(SUB_EXECUTOR.map(
            lambda cid: (cid, goplus_evm(cid, ca_address)), chain_ids))
        for cid, info_probe in probes:
            if info_probe:
                chain_id = cid
                chain_name = CHAIN_NAMES.get(cid, cid)
                break

    meta_items = [("🪙 代币", f"{symbol} · {chain_name or '未知链'}")]
    if pairs:
        meta_items.insert(1, ("💰 池子", fmt_money(total_liq)))
    else:
        meta_items.insert(1, ("💰 池子", "$0.00"))  # 无池子也显示

    # 查不到代币数据（可能是钱包地址或未收录合约）
    if not chain_id:
        return assemble_report(meta_items, ([], [], []), [], no_data=True), None

    info = goplus_evm(chain_id, ca_address)
    if not info:
        return assemble_report(meta_items, ([], [], []), [], no_data=True), None

    meta, audit, risks = build_evm_lines(info, chain_id, ca_address)
    meta_items.extend(meta)
    return assemble_report(meta_items, audit, risks, low_liq, dex_page), None


def get_solana_token_info(ca_address):
    """返回 (报告文本, reply_markup 或 None)"""
    dex_url = f"https://api.dexscreener.com/latest/dex/tokens/{ca_address}"
    pairs = _own_pairs(dexscreener_pairs(ca_address, tag="SOL"), ca_address)

    risks = []
    low_liq = False
    meta_items = [("🪙 代币", "SOL")]
    meta_items.append(("💰 池子", "$0.00"))  # 默认 $0.00，查到池子后覆盖
    dex_page = None
    if pairs:
        best_pair = max(pairs, key=_liq_of)
        symbol = (best_pair.get("baseToken") or {}).get("symbol", "SOL")
        total_liq = sum(_liq_of(p) for p in pairs)
        if total_liq < 1000:
            low_liq = True  # 流动性极低由 assemble_report 统一追加，避免重复
        meta_items[0] = ("🪙 代币", f"{symbol} · SOL")
        meta_items[1] = ("💰 池子", fmt_money(total_liq))
        dex_page = best_pair.get("url") or dex_url

    info = goplus_solana(ca_address)
    audit = build_solana_lines(info, meta_items, risks)
    return assemble_report(meta_items, audit, risks, low_liq, dex_page), None


# ======================================================================
# 八、消息分支：帮助 / 后台 / 钓鱼 / 查币　（源：bot/handlers.py）
# ======================================================================
# 消息处理：把 Webhook 事件翻译成"发什么消息"。
#
# 路由（app.py）只管鉴权和 HTTP，这里管业务分支：
# 帮助 → 管理后台 → 钓鱼检测 → 查币。

def _send(data, content, reply_markup=None):
    """按群聊/私聊自动选投递目标"""
    if data.get("group_id"):
        send_message("group", data["group_id"], content, reply_markup)
    elif data.get("from_user_id"):
        send_message("private", data["from_user_id"], content, reply_markup)


MAX_DOMAINS_PER_MESSAGE = 50   # 一条消息最多看几个域名（防极端刷屏）
MAX_REMOTE_CHECKS = 3          # 其中最多几个走 GoPlus（有网络成本，3s 超时）

URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
HOST_CHARS_RE = re.compile(r"[a-zA-Z0-9._-]+")


def _host_of(url):
    """从一段 URL 里取出干净的 hostname。

    不能直接用 urlparse().hostname：它会把后面的中文标点一起吞进去。
    "https://scam.com，快领" → hostname 是 "scam.com，快领"，黑名单查不到，
    等于白查一遍。这里按字符集截断，并顺手剥掉 userinfo 和端口。
    """
    rest = URL_SCHEME_RE.sub("", url)          # 去协议头（大小写都认）
    rest = re.split(r"[/?#]", rest, 1)[0]      # 只留 authority 部分
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]          # 去 user:pw@
    rest = rest.split(":")[0]                  # 去端口
    m = HOST_CHARS_RE.match(rest)              # 中文标点/全角符号在这里被截断
    return (m.group(0) if m else "").lower().strip(".")


def _domains_of(message):
    """提取消息里所有待检测域名（去重、保持出现顺序）。

    原实现只取第一个链接：先放一个正常链接、再放钓鱼链接即可稳定绕过。
    """
    seen, out = set(), []
    for m in URL_PATTERN.finditer(message):
        host = _host_of(m.group())
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    # 裸域名：先把已识别的 URL 整段抹掉再扫，否则会从链接内部截出错片段
    # （HTTPS://binance-verify.vip 曾被提取成 verify.vip）
    cleaned = URL_PATTERN.sub(" ", message)
    for m in DOMAIN_PATTERN.finditer(cleaned):
        dom = m.group(1).lower()
        if dom not in seen:
            seen.add(dom)
            out.append(dom)
    return out[:MAX_DOMAINS_PER_MESSAGE]


def check_phishing_local(domain):
    """前两层：本地黑名单 + 仿冒识别。纯内存查表 + 纯计算，毫秒级、无网络成本，
    所以可以对消息里的**每个**域名都跑一遍。"""
    if check_domain_in_blocklist(domain):
        return "MetaMask/ScamSniffer 安全库"
    lookalike = check_domain_lookalike(domain)
    if lookalike:
        return f"仿冒域名检测（高度疑似 {lookalike} 的仿冒站点）"
    return None


def check_phishing_remote(domain):
    """第三层：GoPlus 实时接口。有网络成本（3s 超时），调用方必须限量。"""
    try:
        return "GoPlus 安全库" if goplus_phishing_site(domain) else None
    except Exception:
        return None  # 超时不报警（宁可漏一条也不误报）


def check_phishing(domain, remote=True):
    """单个域名的完整三层检测（保留给外部调用与测试）。"""
    source = check_phishing_local(domain)
    if source is None and remote:
        source = check_phishing_remote(domain)
    return source


def handle_message(data):
    """处理一条 webhook 事件，返回要回给平台的 JSON 体。"""
    # message_raw 为空/缺失时回退到 message
    message = data.get("message_raw") or data.get("message") or ""
    if not isinstance(message, str):
        message = str(message)  # 消息体非字符串（dict/list 等）时强转，避免 .lower() 抛异常
    group_id = data.get("group_id")
    from_user_id = data.get("from_user_id")

    if group_id:
        record_realtime_group(group_id)

    if not message:
        return {"status": "ok"}

    # 1. 使用教程（仅认"整条消息就是命令"，避免"说明""菜单"等日常词误触发，
    #    也避免钓鱼消息靠塞关键词绕过检测）
    _cmd = re.sub(r"^(?:@[^\s]+\s*)+", "", message.strip()).strip().lower()
    if _cmd in HELP_COMMANDS or _cmd.startswith("/help") or _cmd.startswith("/帮助"):
        text = help_text()
        if group_id:
            send_message("group", group_id, text)
        elif from_user_id:
            send_message("private", from_user_id, text)
        return {"status": "ok"}

    # 2. 管理员查后台
    # 必须"整条消息就是命令"：曾用 `"/admin" in message` 子串匹配，
    # 结果 https://metamask-io.app/admin 这类钓鱼链接会命中并提前 return，
    # 整条消息跳过第 3 步检测 —— 等于给攻击者开了后门。
    _admin_cmd = _cmd.split(" ", 1)[0]
    if _admin_cmd in ("/admin", "/stats"):
        if str(from_user_id) == ADMIN_USER_ID or str(from_user_id) == f"@{ADMIN_USER_ID}":
            stats = get_usage_stats()
            current_time = now_bj().strftime('%H:%M')
            send_message("private", from_user_id, admin_text(stats, current_time))
        elif from_user_id:
            send_message("private", from_user_id, "🐕 警告：这是内部管理指令，你没有权限查看哦！")
        return {"status": "ok"}

    # 2.5 甄选指令：/金狗 /订阅 /激活 /甄选战绩
    # 放在防钓鱼之前：这些指令不含域名和 CA，不会被第 3、4 步误判；
    # 放在帮助分支之后：避免"整条消息就是命令"的逻辑把 /订阅 当教程吞掉。
    if selection.handle_selection_command(data, message):
        return {"status": "ok"}

    # 3. 精准防钓鱼检测（仅群聊触发；静默模式：只有确认钓鱼才报警）
    # 支持：带协议链接（https://xxx）和裸域名（metamask-io.app）
    # 一条消息里的**每个**域名都要查：只查第一个的话，前面放个正常链接就能绕过。
    domains = _domains_of(message)
    if domains and group_id:
        allowed = ALLOWED_DOMAINS
        hits, remote_left = [], MAX_REMOTE_CHECKS
        for domain in domains:
            if any(domain == d or domain.endswith("." + d) for d in allowed):
                continue
            # 本地两层对每个域名都跑：没有网络成本，若在这里也限个数，
            # 攻击者只要把钓鱼链接排到第 4 个（或塞 5 个正常链接垫在前面）就能绕过。
            source = check_phishing_local(domain)
            if source is None and remote_left > 0:
                remote_left -= 1
                source = check_phishing_remote(domain)
            if source:
                hits.append((domain, source))
        if hits:
            # 命中多个时合并成一条：逐个报警会刷屏，反而让人屏蔽机器人
            if len(hits) == 1:
                domain, source = hits[0]
                text = (f"🚨 高危警告：{source}检测到该链接为钓鱼网站！\n"
                        f"🌐 域名: {domain}\n请勿点击，谨防钱包被盗！")
            else:
                rows = "\n".join(f"🎯 {d} —— {s}" for d, s in hits)
                text = (f"🚨 高危警告：检测到 {len(hits)} 个钓鱼链接！\n"
                        f"{rows}\n请勿点击，谨防钱包被盗！")
            send_message("group", group_id, text)
        # 未命中任何黑名单 → 静默放行；继续往下走，不拦截同一消息里的合约地址

    # 4. 查 CA 风险（先剔除 URL 再匹配，避免污染）
    ca_address = extract_valid_ca(message)
    if ca_address:
        run_query(data, ca_address)
    return {"status": "ok"}


def _do_query(data, ca_address):
    """执行一次查询并回复。

    缓存命中也要回复：否则别的群/用户在 60 秒内查同一个币会收不到任何消息。
    但同一目标（群）在 REPLY_DEDUP_TTL 内只回一次 —— DeBox 超时重试进来的
    第二次请求会命中缓存，不去重就会把同一份报告再推一遍。
    """
    target = data.get("group_id") or data.get("from_user_id") or "-"
    if not should_reply(target, ca_address):
        return

    cached = query_cache_get(ca_address)
    if cached is not None:
        reply_text, markup = cached
    else:
        reply_text, markup = get_token_full_info(ca_address)
        query_cache_set(ca_address, reply_text, markup)  # 成功才写缓存
    _send(data, reply_text, markup)
    record_user_activity(data.get("from_user_id"))


def _safe_query(data, ca_address, key):
    """线程池里跑的包装：异常不外抛（线程池里抛了没人接），但要让用户知道失败了。"""
    try:
        _do_query(data, ca_address)
    except Exception as e:
        print(f"[query] 查币任务异常: {e}")
        try:
            _send(data, "🐕 查询失败：上游接口暂时不可用，请稍后重试")
        except Exception:
            pass
    finally:
        inflight_end(key)


def run_query(data, ca_address):
    """按部署模式执行查询：async 丢线程池立即返回，sync 就地跑完。

    在途去重按 (目标, CA)：DeBox 超时重试进来的第二条请求会被直接丢弃，
    既不重复回复，也不会让 total_queries 多计一次。
    """
    target = data.get("group_id") or data.get("from_user_id") or "-"
    key = (str(target), ca_address)
    if not inflight_begin(key):
        return False

    if query_mode() == "sync":
        try:
            _do_query(data, ca_address)
        except Exception as e:
            print(f"[query] 查币任务异常: {e}")
            try:
                _send(data, "🐕 查询失败：上游接口暂时不可用，请稍后重试")
            except Exception:
                pass
        finally:
            inflight_end(key)
        return True

    try:
        QUERY_EXECUTOR.submit(_safe_query, data, ca_address, key)
    except Exception as e:
        # 线程池已关闭（进程退出中）或提交失败：不能把在途标记永远挂在那里，
        # 否则这个 CA 之后再也查不了。降级为就地执行，_safe_query 自己会释放标记。
        print(f"[query] 线程池不可用，改为同步执行: {e}")
        _safe_query(data, ca_address, key)
    return True


# ======================================================================
# 九、HTTP 层：鉴权 + 路由　（源：bot/server.py）
# ======================================================================
# HTTP 层：鉴权 + 路由。dev 运行：python -m bot.server；单文件版由 tools/build_single.py 拼装。

app = Flask(__name__)


@app.before_request
def _ensure_warm():
    """首次请求兜底预热（幂等）。

    gunicorn --preload 先导入再 fork，fork 只复制主线程 —— 导入时启动的预热
    线程在 worker 里并不存在。这里补一次，否则每个 worker 的首条消息要等
    10~30 秒下载黑名单才回复。
    """
    start_background_tasks()
    selection.ensure_scheduler()   # 同理会丢在 fork 之后，必须在请求期启动


@app.route("/refresh-blocklist", methods=["GET", "POST"])
def refresh_blocklist():
    """黑名单手动刷新接口（供外部 cron / 云函数定时器预热用）。
    同时支持 GET/POST：curl 与部分只支持 GET 的云平台定时器（如 Vercel Cron）都能触发。"""
    header_key = request.headers.get("X-API-KEY", "")
    if not auth_ok(header_key, WEBHOOK_KEY):
        return jsonify({"error": "unauthorized"}), 401
    try:
        # 立即返回：45 万行黑名单下载可能耗时 10~30 秒，超过 Serverless 平台请求超时
        # （如 Vercel Hobby 仅 10s）会导致刷新失败；改由后台线程执行，接口毫秒级响应。
        threading.Thread(target=refresh_phishing_blocklist,
                         kwargs={"force": True, "wait": True}, daemon=True).start()
        return jsonify({"status": "accepted", "msg": "刷新已触发，后台执行中"}), 202
    except Exception as e:
        print(f"[phishing] 手动刷新异常: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/webhook", methods=["POST"])
def webhook():
    """DeBox Webhook 入口。鉴权 fail-closed：环境变量未配置时直接拒绝，避免误放行。"""
    header_key = request.headers.get("X-API-KEY", "")
    if not auth_ok(header_key, WEBHOOK_KEY):
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        data = {}  # 非对象（如 JSON 数组）直接兜底，避免 .get() 抛异常
    return jsonify(handle_message(data)), 200


# ===== 启动预热：拉一次黑名单（daemon 线程，失败不影响主流程）=====
start_background_tasks()

# ===== 链上甄选接线 =====
# bind 让甄选模块复用本模块的 SESSION / 线程池 / send_message / GoPlus 函数
selection.bind(sys.modules[__name__])
selection.selection_routes(app)

# Serverless（Vercel）入口
handler = app


if __name__ == "__main__":
    # 本地调试用；生产由 WSGI / Serverless 托管
    import os
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
