from __future__ import annotations

import ipaddress
import os
import re
import sys
import urllib.parse
import urllib.request
import uuid as uuid_lib
from html import unescape
from typing import Dict, List, Optional, Set, Tuple

import yaml

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore

# ----------------------------------------------------------------------------
# تنظیمات کلی
# ----------------------------------------------------------------------------

SOURCE_URL = (
    "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main"
    "/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt"
)

OUTPUT_DIR = "files"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "clash_iran.yaml")

HEALTH_CHECK_URL = "http://www.gstatic.com/generate_204"
AUTO_TEST_INTERVAL = 180       # ثانیه
AUTO_TEST_TOLERANCE = 80       # میلی‌ثانیه
FALLBACK_INTERVAL = 120
BENCHMARK_TIMEOUT = 5000       # میلی‌ثانیه (mihomo این فیلد رو به ms می‌خونه)

MAX_PROXIES = 250              # سقف تعداد سرور در خروجی (برای سبک ماندن کانفیگ)

# مقادیر مجاز client-fingerprint در Clash Meta / mihomo
VALID_FINGERPRINTS = {
    "chrome", "firefox", "safari", "ios", "android",
    "edge", "360", "qq", "random", "randomized",
}

# تنها flowـی که Reality+TCP در Clash Meta ازش پشتیبانی می‌کنه
VALID_FLOWS = {"", "xtls-rprx-vision"}

SHORT_ID_RE = re.compile(r"^([0-9a-fA-F]{2}){0,8}$")   # 0 تا 16 کاراکتر هگز، طول زوج
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# کلید عمومی x25519 به‌صورت base64url، معمولاً 43 کاراکتر (بدون پدینگ)
PBK_RE = re.compile(r"^[A-Za-z0-9_\-]{40,50}$")

IR_RULES_BASE = "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release"
RULESET_TTL = 86400


# ----------------------------------------------------------------------------
# دانلود لیست سرورها
# ----------------------------------------------------------------------------

def fetch_source(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (ClashConfigGen)"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return resp.read().decode("utf-8", errors="ignore")


# ----------------------------------------------------------------------------
# اعتبارسنجی‌های کمکی
# ----------------------------------------------------------------------------

def is_valid_server(server: str) -> bool:
    if not server or len(server) < 2:
        return False
    try:
        ipaddress.ip_address(server)
        return True
    except ValueError:
        pass
    if len(server) > 253 or "." not in server:
        return False
    for label in server.split("."):
        if not label or len(label) > 63:
            return False
        if not re.match(r"^[A-Za-z0-9\u0600-\u06FF_-]+$", label):
            return False
    return True


def is_valid_short_id(sid: str) -> bool:
    return bool(SHORT_ID_RE.match(sid or ""))


def is_valid_uuid(u: str) -> bool:
    if not u:
        return False
    if UUID_RE.match(u):
        return True
    try:
        uuid_lib.UUID(u)
        return True
    except (ValueError, AttributeError):
        return False


def is_valid_pbk(pbk: str) -> bool:
    return bool(pbk) and bool(PBK_RE.match(pbk))


# ----------------------------------------------------------------------------
# پارس هر خط vless://
# ----------------------------------------------------------------------------

def parse_line(line: str, stats: Dict[str, int]) -> Optional[Dict]:
    line = line.strip()
    if not line or not line.startswith("vless://"):
        return None

    # برخی خط‌ها &amp; دارند به‌جای & (اسکیپ اشتباه HTML در سورس)
    line = unescape(line)

    if "#" in line:
        url_part, remark_raw = line.split("#", 1)
        remark = urllib.parse.unquote(remark_raw.strip())
    else:
        url_part, remark = line, ""
    remark = remark.strip() or f"Reality-{uuid_lib.uuid4().hex[:6]}"

    try:
        parsed = urllib.parse.urlparse(url_part)
    except Exception:
        stats["parse_error"] += 1
        return None

    netloc = parsed.netloc
    if "@" not in netloc:
        stats["no_at"] += 1
        return None

    uuid_val, _, host_port = netloc.rpartition("@")
    uuid_val = uuid_val.strip()

    if not is_valid_uuid(uuid_val):
        stats["bad_uuid"] += 1
        return None

    if ":" not in host_port:
        stats["no_port"] += 1
        return None

    server, _, port_str = host_port.rpartition(":")
    server = server.strip("[]").strip()
    try:
        port = int(port_str)
    except ValueError:
        stats["bad_port"] += 1
        return None
    if not (1 <= port <= 65535):
        stats["bad_port"] += 1
        return None
    if not is_valid_server(server):
        stats["bad_server"] += 1
        return None

    params = urllib.parse.parse_qs(parsed.query)

    def first(key: str, default: str = "") -> str:
        v = params.get(key, [default])
        return (v[0] if v else default) or default

    security = first("security").lower()
    if security != "reality":
        stats["not_reality"] += 1
        return None

    net_type = first("type", "tcp").lower()
    if net_type not in ("", "tcp"):
        stats["not_tcp"] += 1
        return None

    pbk = first("pbk")
    if not is_valid_pbk(pbk):
        stats["bad_pbk"] += 1
        return None

    sid = first("sid")
    if not is_valid_short_id(sid):
        stats["bad_sid"] += 1
        return None

    sni = first("sni")
    if not sni:
        stats["no_sni"] += 1
        return None

    fp = first("fp", "chrome").lower()
    if fp not in VALID_FINGERPRINTS:
        fp = "chrome"

    flow = first("flow")
    if flow not in VALID_FLOWS:
        stats["bad_flow"] += 1
        return None

    return {
        "name": remark,
        "server": server,
        "port": port,
        "uuid": uuid_val,
        "sni": sni,
        "pbk": pbk,
        "sid": sid,
        "fp": fp,
        "flow": flow,
    }


# ----------------------------------------------------------------------------
# حذف داپلیکیت و یکتاسازی نام‌ها
# ----------------------------------------------------------------------------

def dedup(proxies: List[Dict]) -> List[Dict]:
    seen: Set[Tuple] = set()
    out: List[Dict] = []
    for p in proxies:
        key = (p["server"].lower(), p["port"], p["uuid"].lower(), p["pbk"], p["sid"])
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def uniquify_names(proxies: List[Dict]) -> None:
    counts: Dict[str, int] = {}
    used: Set[str] = set()
    for p in proxies:
        base = re.sub(r"\s+", " ", p["name"]).strip()[:60] or "Reality"
        name = base
        i = 2
        while name in used:
            name = f"{base} #{i}"
            i += 1
        used.add(name)
        p["name"] = name


# ----------------------------------------------------------------------------
# ساخت entry نهایی هر proxy برای YAML
# ----------------------------------------------------------------------------

def safe_short_id(raw) -> str:
    """
    لایه‌ی ایمنی نهایی: مهم نیست raw چی باشه (None، عدد، رشته‌ی نامعتبر)،
    این تابع همیشه یک str معتبر و قابل قبول برای mihomo برمی‌گردونه.
    دلیل وجودش: باگ معروف mihomo/OpenClash که وقتی reality-opts.short-id
    در YAML به‌جای رشته‌ی خالی '' به null تبدیل بشه، هسته با خطای دقیقاً
    همین "invalid REALITY short ID" کرش می‌کنه (نگاه کن به
    vernesong/OpenClash#5053 و MetaCubeX/mihomo#2637). چون مقدار sid قبلاً
    در parse_line اعتبارسنجی شده، اینجا فقط از تبدیل تصادفی به None جلوگیری
    می‌کنیم.
    """
    if raw is None:
        return ""
    s = str(raw).strip()
    if not is_valid_short_id(s):
        return ""
    return s


def build_proxy_entry(p: Dict) -> Dict:
    entry: Dict = {
        "name": p["name"],
        "type": "vless",
        "server": p["server"],
        "port": p["port"],
        "uuid": p["uuid"],
        "network": "tcp",
        "tls": True,
        "udp": True,
        "servername": p["sni"],
        "client-fingerprint": p["fp"],
        "reality-opts": {
            "public-key": p["pbk"],
            # هرگز None/null نمی‌فرستیم؛ رشته‌ی خالی معتبره، null معتبر نیست.
            "short-id": safe_short_id(p.get("sid")),
        },
    }
    if p["flow"]:
        entry["flow"] = p["flow"]
    return entry


# ----------------------------------------------------------------------------
# DNS مخصوص ایران
# ----------------------------------------------------------------------------

def build_dns() -> Dict:
    ir_doh = "https://free.shecan.ir/dns-query"
    fallback_doh_1 = "https://doh.403.online/dns-query"
    global_doh_1 = "https://1.1.1.1/dns-query"
    global_doh_2 = "https://8.8.8.8/dns-query"

    ir_domains = [
        "+.ir", "+.aparat.com", "+.digikala.com", "+.snapp.ir",
        "+.tapsi.ir", "+.divar.ir", "+.varzesh3.com", "+.filimo.com",
        "+.namava.ir", "+.telewebion.com", "+.irancell.ir", "+.mci.ir",
    ]

    return {
        "enable": True,
        "ipv6": False,
        "prefer-h3": False,
        "use-hosts": True,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": [
            "*.lan", "*.local", "*.localhost", "localhost",
            "*.arpa", "time.*.com", "time.*.gov", "*.ntp.org",
            "+.stun.*.*", "*.msftconnecttest.com", "*.msftncsi.com",
            *ir_domains,
        ],
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        "nameserver": [global_doh_1, global_doh_2],
        "proxy-server-nameserver": [global_doh_1, fallback_doh_1],
        "nameserver-policy": {
            **{d: ir_doh for d in ir_domains},
        },
    }


# ----------------------------------------------------------------------------
# گروه‌های پراکسی
# ----------------------------------------------------------------------------

def build_proxy_groups(names: List[str]) -> List[Dict]:
    common = dict(url=HEALTH_CHECK_URL, proxies=names)
    return [
        {
            "name": "🚀 SELECT",
            "type": "select",
            "proxies": ["♻️ AUTO", "🔯 FALLBACK", *names, "DIRECT"],
        },
        {
            "name": "♻️ AUTO",
            "type": "url-test",
            "interval": AUTO_TEST_INTERVAL,
            "tolerance": AUTO_TEST_TOLERANCE,
            "lazy": True,
            **common,
        },
        {
            "name": "🔯 FALLBACK",
            "type": "fallback",
            "interval": FALLBACK_INTERVAL,
            **common,
        },
        {
            "name": "🇮🇷 IRAN",
            "type": "select",
            "proxies": ["DIRECT", "🚀 SELECT"],
        },
        {
            "name": "🌐 FINAL",
            "type": "select",
            "proxies": ["🚀 SELECT", "♻️ AUTO", "DIRECT"],
        },
    ]


def build_rule_providers() -> Dict:
    def r(behavior: str, filename: str) -> Dict:
        return {
            "type": "http",
            "behavior": behavior,
            "format": "text",
            "url": f"{IR_RULES_BASE}/{filename}",
            "path": f"./rule-providers/{filename}",
            "interval": RULESET_TTL,
        }

    return {
        "ir-domains": r("domain", "domains.txt"),
        "ir-direct":  r("domain", "direct.txt"),
        "ir-cidr":    r("ipcidr", "ir.txt"),
        "ads":        r("domain", "ads.txt"),
    }


def build_rules() -> List[str]:
    return [
        "RULE-SET,ads,REJECT",
        "RULE-SET,ir-domains,🇮🇷 IRAN",
        "RULE-SET,ir-direct,🇮🇷 IRAN",
        "RULE-SET,ir-cidr,🇮🇷 IRAN,no-resolve",
        "GEOIP,IR,🇮🇷 IRAN,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR,198.18.0.0/16,DIRECT,no-resolve",
        "MATCH,🌐 FINAL",
    ]


# ----------------------------------------------------------------------------
# اصلی
# ----------------------------------------------------------------------------

def main() -> None:
    print("=" * 60)
    print(" Clash / Clash Meta / FlClash Config Generator — Iran")
    print("=" * 60)

    print(f"\n[1/5] دانلود لیست سرورها از:\n  {SOURCE_URL}")
    try:
        raw_text = fetch_source(SOURCE_URL)
    except Exception as exc:
        print(f"  ❌ خطا در دانلود: {exc}")
        sys.exit(1)

    lines = [ln for ln in raw_text.splitlines() if ln.strip()]
    print(f"  خط‌های خام: {len(lines)}")

    print("\n[2/5] پارس و اعتبارسنجی هر سرور (سازگاری با Clash Meta)...")
    stats: Dict[str, int] = {
        "parse_error": 0, "no_at": 0, "bad_uuid": 0, "no_port": 0,
        "bad_port": 0, "bad_server": 0, "not_reality": 0, "not_tcp": 0,
        "bad_pbk": 0, "bad_sid": 0, "no_sni": 0, "bad_flow": 0,
    }
    parsed: List[Dict] = []
    for ln in lines:
        p = parse_line(ln, stats)
        if p:
            parsed.append(p)

    total_bad = sum(stats.values())
    print(f"  ✅ معتبر: {len(parsed)}   |   ❌ رد شده: {total_bad}")
    for k, v in stats.items():
        if v:
            print(f"     - {k}: {v}")

    if not parsed:
        print("\n  هیچ سرور معتبری پیدا نشد. خروجی تولید نمی‌شود.")
        sys.exit(1)

    print("\n[3/5] حذف داپلیکیت‌ها و یکتاسازی نام‌ها...")
    before = len(parsed)
    unique = dedup(parsed)
    print(f"  {before} → {len(unique)} (حذف {before - len(unique)} تکراری)")

    if len(unique) > MAX_PROXIES:
        print(f"  محدود کردن به {MAX_PROXIES} سرور اول (از {len(unique)})")
        unique = unique[:MAX_PROXIES]

    uniquify_names(unique)
    names = [p["name"] for p in unique]

    print("\n[4/5] ساخت proxies و ساختار کامل YAML...")
    proxies = [build_proxy_entry(p) for p in unique]

    # بازبینی نهایی دفاعی: هر آیتمی که reality-opts.short-id توش None باشه یا
    # از regex هگز رد نشه، همون‌جا با اندیسش لاگ و اصلاح می‌شه. اگه این پیام
    # چاپ بشه یعنی یه جای دیگه (نه parse_line) مقدار غیرمنتظره تولید کرده.
    for idx, entry in enumerate(proxies):
        sid = entry.get("reality-opts", {}).get("short-id")
        if sid is None or not is_valid_short_id(sid):
            print(f"  ⚠️  proxy {idx} ({entry.get('name')}): short-id نامعتبر بود، به '' تبدیل شد")
            entry["reality-opts"]["short-id"] = ""

    config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "bind-address": "*",
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "unified-delay": True,
        "tcp-concurrent": True,
        "external-controller": "127.0.0.1:9090",
        "profile": {"store-selected": True, "store-fake-ip": True},
        "dns": build_dns(),
        "proxies": proxies,
        "proxy-groups": build_proxy_groups(names),
        "rule-providers": build_rule_providers(),
        "rules": build_rules(),
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n[5/5] ذخیره در {OUTPUT_FILE} ...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("# تولید شده توسط clash_iran_generator.py\n")
        f.write(f"# منبع: {SOURCE_URL}\n")
        f.write(f"# تعداد سرور: {len(proxies)}\n\n")
        yaml.safe_dump(
            config, f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
            width=1000,
        )

    size_kb = os.path.getsize(OUTPUT_FILE) / 1024
    print(f"  ✅ ذخیره شد — {size_kb:.1f} KB — {len(proxies)} سرور")
    print("\nاین فایل رو مستقیماً در FlClash / Clash Meta / Clash Verge")
    print("از مسیر Profiles → Import from file/URL بارگذاری کن.")


if __name__ == "__main__":
    main()
