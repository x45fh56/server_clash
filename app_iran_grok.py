import urllib.request
import urllib.parse
import uuid
import yaml
from typing import Dict, Optional, List
import sys

# Force UTF-8 output for console (especially useful on Windows)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore

# Fixed settings
SOURCE_URL = "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt"
OUTPUT_FILE = "clash_iran_grok.yaml"

MIXED_PORT = 7890
ALLOW_LAN = True
LOG_LEVEL = "info"
MODE = "rule"
EXTERNAL_CONTROLLER = "127.0.0.1:9090"

def parse_vless_url(line: str) -> Optional[Dict]:
    line = line.strip()
    if not line.startswith("vless://") or "#" not in line:
        return None

    try:
        url_part, remark_part = line.split("#", 1)
        remark = urllib.parse.unquote(remark_part.strip()) if remark_part.strip() else f"Reality-{uuid.uuid4().hex[:6]}"

        parsed = urllib.parse.urlparse(url_part)
        uuid_and_host = parsed.netloc
        uuid_val, host_port = uuid_and_host.split("@", 1)
        server, port_str = host_port.rsplit(":", 1)
        port = int(port_str)

        params = urllib.parse.parse_qs(parsed.query)

        security = params.get("security", [""])[0]
        if security != "reality":
            return None

        pbk = params.get("pbk", [None])[0]
        sid = params.get("sid", [""])[0]
        sni = params.get("sni", [""])[0]
        fp = params.get("fp", ["chrome"])[0]
        flow = params.get("flow", [None])[0]
        spx = params.get("spx", [None])[0]

        if not pbk or not sni:
            return None

        return {
            "name": remark,
            "server": server,
            "port": port,
            "uuid": uuid_val,
            "flow": flow,
            "tls": True,
            "udp": True,
            "network": "tcp",
            "servername": sni,
            "client-fingerprint": fp,
            "reality-opts": {
                "public-key": pbk,
                "short-id": sid
            },
            "spiderX": spx if spx else None
        }
    except Exception as e:
        print(f"Parse error: {line[:60]}... → {e}")
        return None


def build_dns() -> Dict:
    return {
        "enable": True,
        "listen": "0.0.0.0:53",
        "ipv6": False,   
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": [
            "*.lan",
            "*.localdomain",
            "*.example",
            "*.invalid",
            "*.localhost",
            "*.test",
            "*.local",
            "*.home.arpa",
            "router.asus.com",
            "localhost.sec.qq.com",
            "localhost.ptlogin2.qq.com",
            "+.msftconnecttest.com",
            "+.ir"  
        ],
        "default-nameserver": [
            "223.5.5.5",
            "114.114.114.114"
        ],
        "nameserver": [
            "https://dns.google/dns-query",
            "https://cloudflare-dns.com/dns-query",
            "223.5.5.5"
        ],
        "fallback": [
            "tls://8.8.4.4:853",
            "tls://1.1.1.1:853",
            "https://dns.google/dns-query"
        ],
        "fallback-filter": {
            "geoip": True,
            "geoip-code": "IR",
            "ipcidr": [
                "240.0.0.0/4"
            ]
        }
    }


def build_tun() -> Dict:
    return {
        "enable": True,
        "stack": "mixed",
        "auto-route": True,
        "strict-route": True,
        "auto-detect-interface": True,
        "dns-hijack": [
            "any:53",
            "tcp://any:53"
        ]
    }


def build_sniffer() -> Dict:
    return {
        "enable": True,
        "force-dns-mapping": True,
        "parse-pure-ip": True,
        "override-destination": True,
        "sniff": {
            "HTTP": {
                "ports": [80, 8080, 8880, 2052, 2082, 2086, 2095]
            },
            "TLS": {
                "ports": [443, 8443, 2053, 2083, 2087, 2096]
            }
        }
    }


def main():
    print("Downloading server list...")
    try:
        with urllib.request.urlopen(SOURCE_URL) as response:
            text = response.read().decode("utf-8")
    except Exception as e:
        print(f"Download failed: {e}")
        return

    proxies: List[Dict] = []
    for line in text.splitlines():
        proxy = parse_vless_url(line)
        if proxy:
            proxies.append(proxy)

    if not proxies:
        print("No valid VLESS Reality servers found.")
        return

    print(f"Found {len(proxies)} servers.")

    # Fix duplicate names
    proxy_names = []
    seen = set()
    name_counters = {}

    for p in proxies:
        base_name = p["name"]
        if base_name in name_counters:
            name_counters[base_name] += 1
            new_name = f"{base_name} - {name_counters[base_name]}"
        else:
            name_counters[base_name] = 1
            new_name = base_name

        while new_name in seen:
            new_name = f"{new_name} ~{uuid.uuid4().hex[:4]}"

        p["name"] = new_name
        seen.add(new_name)
        proxy_names.append(new_name)

    print(f"Unique proxy names after fix: {len(proxy_names)}")

    config = {
        "mixed-port": MIXED_PORT,
        "allow-lan": ALLOW_LAN,
        "mode": MODE,
        "log-level": LOG_LEVEL,
        "ipv6": False,   
        "external-controller": EXTERNAL_CONTROLLER,
        "external-ui": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
        "profile": {
            "store-selected": True
        },
        "dns": build_dns(),
        "tun": build_tun(),
        "sniffer": build_sniffer(),
        "proxies": [],
        "proxy-groups": [
            {
                "name": "🚀 Main Select",
                "type": "select",
                "proxies": proxy_names + ["♻️ Auto Best", "DIRECT"]
            },
            {
                "name": "♻️ Auto Best",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names
            },
            {
                "name": "🎯 Iran Direct",
                "type": "select",
                "proxies": ["DIRECT", "🚀 Main Select"]
            }
        ],
        "rule-providers": {
            "ir": {
                "type": "http",
                "behavior": "domain",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt",
                "path": "./ruleset/ir.yaml",
                "interval": 86400
            },
            "adblock": {
                "type": "http",
                "behavior": "domain",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ads.txt",
                "path": "./ruleset/adblock.yaml",
                "interval": 86400
            },
            "direct": {
                "type": "http",
                "behavior": "domain",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/direct.txt",
                "path": "./ruleset/direct.yaml",
                "interval": 86400
            }
        },
        "rules": [
            "RULE-SET,ir,🎯 Iran Direct",
            "RULE-SET,adblock,REJECT",
            "RULE-SET,direct,🎯 Iran Direct",
            "GEOIP,IR,🎯 Iran Direct",
            "MATCH,🚀 Main Select"
        ]
    }

    for p in proxies:
        entry = {
            "name": p["name"],
            "type": "vless",
            "server": p["server"],
            "port": p["port"],
            "uuid": p["uuid"],
            "network": "tcp",
            "tls": True,
            "udp": True,
            "flow": p["flow"],
            "servername": p["servername"],
            "client-fingerprint": p["client-fingerprint"],
            "reality-opts": p["reality-opts"]
        }
        if p.get("spiderX"):
            entry["spider-x"] = p["spiderX"]

        config["proxies"].append(entry)

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False, indent=2, default_flow_style=False)
        print(f"\nConfig saved successfully: {OUTPUT_FILE}")
        print("Optimized for Iran users → load in mihomo / Clash Meta / FlClash / ...")
    except Exception as e:
        print(f"Error saving file: {e}")


if __name__ == "__main__":
    main()