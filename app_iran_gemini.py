import requests
import yaml
from urllib.parse import urlparse, parse_qs, unquote
import sys

# ---------------------------------------------------------
# Input Settings
# ---------------------------------------------------------
SOURCE_URL = "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt"
OUTPUT_FILE = "clash_iran_gemini.yaml"

# ---------------------------------------------------------
# Base Configuration (Optimized for Iran)
# ---------------------------------------------------------
BASE_CONFIG = {
    "mixed-port": 7890,
    "ipv6": False,  # Disabled for better stability in Iran
    "allow-lan": False,
    "mode": "rule",
    "log-level": "info",
    "external-controller": "127.0.0.1:9090",
    "external-ui": "ui",
    "external-ui-url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
    
    "tun": {
        "enable": True,
        "stack": "mixed",
        "auto-route": True,
        "strict-route": True,
        "auto-detect-interface": True,
        "dns-hijack": ["any:53", "tcp://any:53"],
        "mtu": 9000
    },
    
    "sniffer": {
        "enable": True,
        "force-dns-mapping": True,
        "parse-pure-ip": True,
        "override-destination": True,
        "sniff": {
            "HTTP": {"ports": [80, 8080, 8880, 2052, 2082, 2086, 2095]},
            "TLS": {"ports": [443, 8443, 2053, 2083, 2087, 2096]}
        }
    },
    
    "dns": {
        "enable": True,
        "ipv6": False,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": "0.0.0.0:53",
        "respect-rules": True,  
        
        # REQUIRED when respect-rules is True:
        "proxy-server-nameserver": ["1.1.1.1", "8.8.8.8", "119.29.29.29"], 
        
        "default-nameserver": ["1.1.1.1", "8.8.8.8", "119.29.29.29"],
        "nameserver": [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query"
        ],
        "fallback": [
            "tcp://1.1.1.1",
            "tcp://8.8.8.8"
        ],
        "fallback-filter": {
            "geoip": True,
            "geoip-code": "IR",
            "ipcidr": ["240.0.0.0/4"]
        }
    },
    
    # Rule Providers (Using jsdelivr for better accessibility in Iran)
    "rule-providers": {
        "Iran_Domains": {
            "type": "http",
            "behavior": "domain",
            "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/clash/iran.yaml",
            "path": "./rules/iran_domains.yaml",
            "interval": 86400
        },
        "Iran_IP": {
            "type": "http",
            "behavior": "ipcidr",
            "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/clash/iran_ip.yaml",
            "path": "./rules/iran_ip.yaml",
            "interval": 86400
        },
        "Ads": {
            "type": "http",
            "behavior": "domain",
            "url": "https://cdn.jsdelivr.net/gh/privacy-protection-tools/anti-AD@master/anti-ad-clash.yaml",
            "path": "./rules/ads.yaml",
            "interval": 86400
        }
    }
}

# ---------------------------------------------------------
# Parsing Functions (VLESS Reality Logic)
# ---------------------------------------------------------

def build_transport(net_type, path, host, service_name, header_type):
    transport = {}
    if path and "?" in path:
        path = path.split("?")[0]
    if not path:
        path = "/"

    if net_type == 'tcp':
        if header_type == 'http':
            transport = {
                "network": "http",
                "http-opts": {
                    "method": "GET",
                    "path": [path],
                    "headers": {"Host": [host]} if host else {}
                }
            }
        else:
            transport = {"network": "tcp"}

    elif net_type == 'ws':
        transport = {
            "network": "ws",
            "ws-opts": {
                "path": path,
                "headers": {"Host": host} if host else {}
            }
        }

    elif net_type == 'grpc':
        transport = {
            "network": "grpc",
            "grpc-opts": {
                "grpc-service-name": service_name
            }
        }
    return transport

def build_tls(security, sni, fp, pbk, sid, alpn):
    if security not in ["tls", "reality"]:
        return {}

    tls_config = {
        "tls": True,
        "servername": sni,
        "client-fingerprint": "random" if fp == "randomized" else fp
    }

    if security == "tls":
        if alpn:
            tls_config["alpn"] = alpn.split(",")
        tls_config["skip-cert-verify"] = True

    elif security == "reality" and pbk and sid:
        tls_config["reality-opts"] = {
            "public-key": pbk,
            "short-id": sid
        }
    
    return tls_config

def parse_vless_bpb_style(link):
    if not link.startswith("vless://"):
        return None

    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        
        # Extract base parameters
        uuid = parsed.username
        server = parsed.hostname
        port = parsed.port
        name = unquote(parsed.fragment) if parsed.fragment else "VLESS Node"
        
        # Extract query parameters
        security = params.get("security", [""])[0]
        net_type = params.get("type", ["tcp"])[0]
        sni = params.get("sni", [""])[0] or server
        pbk = params.get("pbk", [""])[0]
        sid = params.get("sid", [""])[0]
        fp = params.get("fp", ["chrome"])[0]
        path = params.get("path", ["/"])[0]
        host = params.get("host", [""])[0]
        service_name = params.get("serviceName", [""])[0]
        header_type = params.get("headerType", [""])[0]
        flow = params.get("flow", [""])[0]
        alpn = params.get("alpn", [""])[0]

        # Build Transport and TLS objects
        tls_settings = build_tls(security, sni, fp, pbk, sid, alpn)
        transport_settings = build_transport(net_type, path, host, service_name, header_type)

        # Base Proxy Object
        proxy = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "tfo": False,
            "udp": True,
            "ip-version": "ipv4-prefer",
        }

        if flow:
            proxy["flow"] = flow

        # Merge settings
        proxy.update(tls_settings)
        proxy.update(transport_settings)

        # Remove None/Empty values
        return {k: v for k, v in proxy.items() if v is not None}

    except Exception as e:
        return None

# ---------------------------------------------------------
# Main Execution
# ---------------------------------------------------------

if __name__ == "__main__":
    print(f"Downloading links from: {SOURCE_URL}")
    try:
        response = requests.get(SOURCE_URL, timeout=15)
        response.raise_for_status()
        links = response.text.splitlines()
    except Exception as e:
        print(f"Failed to download: {e}")
        exit(1)

    proxies = []
    name_counter = {}  # To handle duplicate proxy names

    print("Processing links...")
    for link in links:
        if link.strip():
            p = parse_vless_bpb_style(link.strip())
            if p:
                original_name = p["name"]
                
                # Check for duplicates and rename if necessary
                if original_name in name_counter:
                    name_counter[original_name] += 1
                    new_name = f"{original_name}_{name_counter[original_name]}"
                    p["name"] = new_name
                else:
                    name_counter[original_name] = 1
                
                proxies.append(p)

    print(f"Parsed {len(proxies)} proxies.")

    if proxies:
        proxy_names = [p["name"] for p in proxies]
        
        # Proxy Groups definition (Emojis here are safe for file writing)
        proxy_groups = [
            # Manual Selector
            {
                "name": "🚀 Proxy",
                "type": "select",
                "proxies": ["⚡ Auto", "DIRECT"] + proxy_names
            },
            # Auto URL Test (Best Ping)
            {
                "name": "⚡ Auto",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names
            },
            # Iran Direct Group
            {
                "name": "🇮🇷 Iran Direct",
                "type": "select",
                "proxies": ["DIRECT", "🚀 Proxy"]
            }
        ]

        # Routing Rules
        rules = [
            "RULE-SET,Ads,REJECT",                  # Block Ads
            "RULE-SET,Iran_Domains,🇮🇷 Iran Direct", # Iran Domains -> Direct
            "RULE-SET,Iran_IP,🇮🇷 Iran Direct",      # Iran IPs -> Direct
            "DOMAIN-SUFFIX,ir,🇮🇷 Iran Direct",       # .ir Domains -> Direct
            "GEOIP,IR,🇮🇷 Iran Direct",               # GeoIP IR -> Direct
            "GEOIP,PRIVATE,DIRECT",                 # LAN -> Direct
            "MATCH,🚀 Proxy"                        # Default -> Proxy
        ]

        # Assemble Final Config
        final_config = BASE_CONFIG.copy()
        final_config["proxies"] = proxies
        final_config["proxy-groups"] = proxy_groups
        final_config["rules"] = rules

        # Write to file (Using UTF-8 encoding handles emojis correctly)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            yaml.dump(final_config, f, allow_unicode=True, sort_keys=False)
        
        # Use simple text for console output to avoid Windows Unicode errors
        print(f"[SUCCESS] Configuration saved as: {OUTPUT_FILE}")
        print("Features: proxy-server-nameserver added, Duplicate names fixed, Iran traffic bypassed.")
    else:
        print("[ERROR] No valid proxies found.")