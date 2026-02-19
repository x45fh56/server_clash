import requests
import yaml
from urllib.parse import urlparse, parse_qs, unquote
import os

os.makedirs("files", exist_ok=True)
OUTPUT_FILE = os.path.join("files", "clash_iran_gpt.yaml")

SOURCE_URL = "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt"


def make_unique(name, existing_names):
    """
    Ensure proxy names are unique to avoid Clash duplicate name errors
    """
    original = name
    counter = 1
    while name in existing_names:
        name = f"{original}_{counter}"
        counter += 1
    return name


def parse_vless(link, existing_names):
    """
    Parse a VLESS link and convert it into Clash Meta proxy format
    """
    link = link.strip()
    if not link.startswith("vless://"):
        return None

    parsed = urlparse(link)

    uuid_value = parsed.username
    server = parsed.hostname
    port = parsed.port

    if not server or not port or not uuid_value:
        return None

    params = parse_qs(parsed.query)

    # Extract parameters
    security = params.get("security", ["none"])[0]
    sni = params.get("sni", [server])[0]
    fingerprint = params.get("fp", ["chrome"])[0]
    public_key = params.get("pbk", [None])[0]
    short_id = params.get("sid", [None])[0]
    flow = params.get("flow", [""])[0]

    # Generate proxy name
    remark = unquote(parsed.fragment) if parsed.fragment else f"{server}:{port}"
    remark = make_unique(remark, existing_names)

    # Build base proxy structure
    proxy = {
        "name": remark,
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid_value,
        "network": "tcp",
        "udp": True,
        "tls": security in ["tls", "reality"],
        "servername": sni,
        "client-fingerprint": fingerprint,
        "skip-cert-verify": False
    }

    if flow:
        proxy["flow"] = flow

    # Add Reality options if applicable
    if security == "reality" and public_key and short_id:
        proxy["reality-opts"] = {
            "public-key": public_key,
            "short-id": short_id
        }

    return proxy


def main():
    print("Downloading VLESS servers...")

    response = requests.get(SOURCE_URL, timeout=15)
    lines = response.text.splitlines()

    proxies = []
    existing_names = set()

    for line in lines:
        proxy = parse_vless(line, existing_names)
        if proxy:
            existing_names.add(proxy["name"])
            proxies.append(proxy)

    print(f"Parsed {len(proxies)} proxies.")

    # Build optimized Clash config for Iran
    config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,

        # Optimized DNS settings for Iran
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:1053",
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": [
                "1.1.1.1",
                "8.8.8.8"
            ],
            "nameserver": [
                "https://cloudflare-dns.com/dns-query",
                "https://dns.google/dns-query"
            ],
            "fallback": [
                "tls://8.8.4.4:853",
                "tls://1.0.0.1:853"
            ],
            "fallback-filter": {
                "geoip": True,
                "geoip-code": "IR"
            }
        },

        # Enable TUN for better routing in Iran networks
        "tun": {
            "enable": True,
            "stack": "system",
            "auto-route": True,
            "auto-detect-interface": True
        },

        "proxies": proxies,

        # Smart auto selection group
        "proxy-groups": [
            {
                "name": "AUTO-IRAN",
                "type": "url-test",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 180,
                "tolerance": 50,
                "proxies": [p["name"] for p in proxies]
            },
            {
                "name": "SELECT",
                "type": "select",
                "proxies": ["AUTO-IRAN"] + [p["name"] for p in proxies] + ["DIRECT"]
            }
        ],

        # Lightweight rules optimized for Iran usage
        "rules": [
            "GEOIP,IR,DIRECT",
            "MATCH,SELECT"
        ]
    }

    # Save YAML output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print(f"Config successfully saved as {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
