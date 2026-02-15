"""
fetch_proxies.py
================
从 addr.txt 中读取订阅链接，抓取并提取代理节点，
测试每个节点到 www.google.com 的 TCP 连通性延迟，
删除超时不可达节点，最终生成可在 Clash Verge (Meta 内核) 中使用的 outcome.meta.yml 配置文件。

用法：
    python fetch_proxies.py

依赖：
    pip install requests pyyaml
"""

import re
import sys
import time
import socket
import logging
from pathlib import Path
from datetime import datetime
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml
import requests

# ======================== 日志配置 ========================
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ======================== 路径定义 ========================
BASE_DIR = Path(__file__).resolve().parent
ADDR_FILE = BASE_DIR / "addr.yaml"          # 订阅链接文件 (YAML 格式)
OUTPUT_FILE = BASE_DIR / "outcome.meta.yml"  # 输出文件

# ======================== 网络请求配置 ========================
REQUEST_TIMEOUT = 30   # 单个订阅请求超时秒数
MAX_RETRIES = 2        # 失败重试次数
HEADERS = {
    "User-Agent": "ClashMetaForAndroid/2.10.1.Meta Mihomo/1.18"
}

# ======================== 延迟测试配置 ========================
LATENCY_TEST_HOST = "www.google.com"  # 延迟测试目标主机
LATENCY_TEST_PORT = 443               # 延迟测试目标端口 (HTTPS)
LATENCY_TIMEOUT = 3                   # 单节点延迟测试超时秒数（超过3秒直接删除）
LATENCY_MAX_WORKERS = 50              # 并发测试线程数

# ======================== 节点过滤配置 ========================
# 需要排除的地区关键词（中国大陆、香港、台湾）
BLOCKED_REGION_PATTERN = re.compile(
    r"(?:🇨🇳|🇭🇰|🇹🇼|🇻🇳|CN|HK|TW|VN|中国|香港|台湾|越南|China|Hong.?Kong|Taiwan|Vietnam|回国)",
    re.I,
)

# ======================== 国家/地区分类映射 ========================
# 关键词 → (组名, 排序权重)  权重越小越靠前
REGION_MAP: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:🇯🇵|JP|日本|Japan|东京|大阪)", re.I), "🇯🇵 日本"),
    (re.compile(r"(?:🇺🇸|US|美国|United.?States|洛杉矶|硅谷|纽约|达拉斯|凤凰城|西雅图)", re.I), "🇺🇸 美国"),
    (re.compile(r"(?:🇸🇬|SG|新加坡|Singapore|狮城)", re.I), "🇸🇬 新加坡"),
    (re.compile(r"(?:🇰🇷|KR|韩国|Korea|首尔)", re.I), "🇰🇷 韩国"),
    (re.compile(r"(?:🇬🇧|UK|GB|英国|United.?Kingdom|伦敦)", re.I), "🇬🇧 英国"),
    (re.compile(r"(?:🇩🇪|DE|德国|Germany|法兰克福)", re.I), "🇩🇪 德国"),
    (re.compile(r"(?:🇫🇷|FR|法国|France|巴黎)", re.I), "🇫🇷 法国"),
    (re.compile(r"(?:🇷🇺|RU|俄罗斯|Russia|莫斯科)", re.I), "🇷🇺 俄罗斯"),
    (re.compile(r"(?:🇨🇦|CA|加拿大|Canada)", re.I), "🇨🇦 加拿大"),
    (re.compile(r"(?:🇦🇺|AU|澳大利亚|Australia|悉尼)", re.I), "🇦🇺 澳大利亚"),
    (re.compile(r"(?:🇮🇳|IN|印度|India|孟买)", re.I), "🇮🇳 印度"),
    (re.compile(r"(?:🇧🇷|BR|巴西|Brazil)", re.I), "🇧🇷 巴西"),
]

# 所有可能出现的地区组名（固定顺序）
ALL_REGION_NAMES = [item[1] for item in REGION_MAP]


# ======================== 工具函数 ========================

def read_urls(filepath: Path) -> list[str]:
    """
    从 YAML 配置文件中读取订阅 URL 列表。
    期望格式:
        urls:
          - https://example.com/sub1.yaml
          - https://example.com/sub2.yaml
    """
    if not filepath.exists():
        log.error(f"订阅链接文件不存在: {filepath}")
        sys.exit(1)

    try:
        data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        log.error(f"订阅链接文件 YAML 解析失败: {e}")
        sys.exit(1)

    if not isinstance(data, dict) or "urls" not in data:
        log.error("订阅链接文件格式错误，缺少 'urls' 字段")
        sys.exit(1)

    raw_urls = data["urls"]
    if not isinstance(raw_urls, list):
        log.error("'urls' 字段必须为列表")
        sys.exit(1)

    # 过滤有效的 URL
    urls = [str(u).strip() for u in raw_urls
            if isinstance(u, str) and str(u).strip().startswith("http")]

    log.info(f"从 {filepath.name} 中读取到 {len(urls)} 条订阅链接")
    return urls


def fetch_content(url: str) -> str | None:
    """
    请求订阅链接并返回响应文本。
    支持重试机制，返回 None 表示获取失败。
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            log.info(f"  正在抓取 ({attempt}/{MAX_RETRIES}): {url[:80]}...")
            resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return resp.text
        except requests.RequestException as e:
            log.warning(f"  请求失败: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(2)
    return None


def extract_proxies(raw_text: str) -> list[dict]:
    """
    从 YAML 文本中提取 proxies 列表。
    兼容两种格式：
      1. 完整 Clash 配置（含 proxies 字段）
      2. proxy-provider 格式（顶层就是 proxies 列表）
    """
    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        log.warning(f"  YAML 解析失败: {e}")
        return []

    if not isinstance(data, dict):
        return []

    # 情况1: 标准 Clash 配置
    if "proxies" in data and isinstance(data["proxies"], list):
        return data["proxies"]

    # 情况2: proxy-provider 格式 (payload 字段)
    if "payload" in data and isinstance(data["payload"], list):
        return data["payload"]

    return []


def deduplicate_proxies(all_proxies: list[dict]) -> list[dict]:
    """
    去重代理节点（以 name 为主键）。
    当出现重名节点时，在名称后追加序号。
    同时过滤掉缺少必要字段的无效节点。
    """
    seen_names: dict[str, int] = {}  # name -> 出现次数
    result: list[dict] = []

    for proxy in all_proxies:
        # 基本有效性校验
        if not isinstance(proxy, dict):
            continue
        if "name" not in proxy or "type" not in proxy or "server" not in proxy:
            continue

        name = str(proxy["name"]).strip()
        if not name:
            continue

        # 处理重名
        if name in seen_names:
            seen_names[name] += 1
            name = f"{name}_{seen_names[name]}"
        else:
            seen_names[name] = 0

        proxy["name"] = name
        result.append(proxy)

    return result


def filter_blocked_regions(proxies: list[dict]) -> list[dict]:
    """
    过滤掉属于被屏蔽地区（中国大陆、香港、台湾）的节点。
    通过节点名称中的关键词进行匹配。
    """
    result: list[dict] = []
    blocked_count = 0

    for proxy in proxies:
        name = proxy.get("name", "")
        if BLOCKED_REGION_PATTERN.search(name):
            blocked_count += 1
        else:
            result.append(proxy)

    if blocked_count > 0:
        log.info(f"已过滤 {blocked_count} 个中国大陆/香港/台湾/越南节点，剩余 {len(result)} 个")

    return result


def test_single_proxy(proxy: dict) -> tuple[dict, float | None]:
    """
    测试单个代理节点的连通性延迟。
    通过 TCP 连接到节点的 server:port，再经由该连接尝试到达 www.google.com:443。
    由于无法在脚本层面实现各种代理协议的握手，这里采用两步策略：
      1. TCP 连接到代理服务器的 server:port（验证服务器是否可达）
      2. 返回 TCP 连接耗时作为延迟参考值（单位：毫秒）
    返回 (proxy, latency_ms)，超时/失败返回 (proxy, None)。
    """
    server = proxy.get("server", "")
    port = proxy.get("port", 0)
    name = proxy.get("name", "unknown")

    if not server or not port:
        return proxy, None

    try:
        port = int(port)
    except (ValueError, TypeError):
        return proxy, None

    # TCP 连通性测试：连接代理服务器
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(LATENCY_TIMEOUT)
        start = time.monotonic()
        sock.connect((server, port))
        latency_ms = (time.monotonic() - start) * 1000  # 转为毫秒
        sock.close()
        return proxy, round(latency_ms, 1)
    except (socket.timeout, socket.error, OSError):
        return proxy, None


def test_proxies_latency(proxies: list[dict]) -> list[dict]:
    """
    并发测试所有代理节点的延迟。
    删除超时（不可达）的节点，保留的节点按延迟从低到高排序。
    在节点名称前添加延迟标记，例如 "[123ms] 节点名"。
    """
    total = len(proxies)
    log.info(f"开始延迟测试（共 {total} 个节点，超时 {LATENCY_TIMEOUT}s，并发 {LATENCY_MAX_WORKERS} 线程）...")
    log.info(f"测试目标: TCP 连接到各节点的 server:port")

    alive_proxies: list[tuple[dict, float]] = []  # (proxy, latency_ms)
    timeout_count = 0
    tested = 0

    with ThreadPoolExecutor(max_workers=LATENCY_MAX_WORKERS) as executor:
        # 提交所有测试任务
        future_to_proxy = {
            executor.submit(test_single_proxy, p): p for p in proxies
        }

        for future in as_completed(future_to_proxy):
            tested += 1
            proxy, latency = future.result()
            name = proxy.get("name", "unknown")

            if latency is not None:
                alive_proxies.append((proxy, latency))
                if tested % 20 == 0 or tested == total:
                    log.info(f"  测试进度: {tested}/{total}  "
                             f"存活: {len(alive_proxies)}  超时: {timeout_count}")
            else:
                timeout_count += 1
                if tested % 20 == 0 or tested == total:
                    log.info(f"  测试进度: {tested}/{total}  "
                             f"存活: {len(alive_proxies)}  超时: {timeout_count}")

    # 按延迟从低到高排序
    alive_proxies.sort(key=lambda x: x[1])

    # 在节点名称前添加延迟标记
    result: list[dict] = []
    for proxy, latency in alive_proxies:
        proxy["name"] = f"[{int(latency)}ms] {proxy['name']}"
        result.append(proxy)

    log.info(f"延迟测试完成: 存活 {len(result)}/{total}，"
             f"超时淘汰 {timeout_count} 个节点")

    if result:
        best = alive_proxies[0]
        worst = alive_proxies[-1]
        avg = sum(lat for _, lat in alive_proxies) / len(alive_proxies)
        log.info(f"  最低延迟: {int(best[1])}ms  "
                 f"最高延迟: {int(worst[1])}ms  "
                 f"平均延迟: {int(avg)}ms")

    return result


def classify_by_region(proxies: list[dict]) -> dict[str, list[str]]:
    """
    根据节点名称中的关键词，将节点分类到对应的地区组。
    返回 {地区组名: [节点名称列表]}。
    """
    region_groups: dict[str, list[str]] = OrderedDict()

    for proxy in proxies:
        name = proxy["name"]
        matched = False
        for pattern, region_name in REGION_MAP:
            if pattern.search(name):
                region_groups.setdefault(region_name, []).append(name)
                matched = True
                break  # 一个节点只归入第一个匹配的地区
        # 未匹配任何地区的节点不归入地区组，但仍在"全部节点"组中

    return region_groups


def build_config(proxies: list[dict]) -> dict:
    """
    基于提取到的代理节点列表，构建完整的 Clash Meta 配置。
    结构参照 list.meta.yml 样本。
    """
    # 所有节点名称列表
    all_names = [p["name"] for p in proxies]

    # 按地区分类
    region_groups = classify_by_region(proxies)

    # ---------- 构建 proxy-groups ----------
    proxy_groups: list[dict] = []

    # 1. 🚀 选择代理 (总入口)
    proxy_groups.append({
        "name": "🚀 选择代理",
        "type": "select",
        "proxies": ["♻ 自动选择", "🔰 延迟最低", "✅ 手动选择", "🗺️ 选择地区"],
    })

    # 2. ♻ 自动选择 (fallback)
    proxy_groups.append({
        "name": "♻ 自动选择",
        "type": "fallback",
        "url": "https://www.google.com/",
        "interval": 300,
        "proxies": list(all_names),  # 全部节点
    })

    # 3. 🔰 延迟最低 (url-test)
    proxy_groups.append({
        "name": "🔰 延迟最低",
        "type": "url-test",
        "url": "https://www.google.com/",
        "interval": 300,
        "tolerance": 20,
        "proxies": list(all_names),
    })

    # 4. ✅ 手动选择
    proxy_groups.append({
        "name": "✅ 手动选择",
        "type": "select",
        "proxies": list(all_names),
    })

    # 5. 🌐 突破锁区
    proxy_groups.append({
        "name": "🌐 突破锁区",
        "type": "select",
        "proxies": ["DIRECT", "🚀 选择代理"],
    })

    # 6. ❓ 疑似国内
    proxy_groups.append({
        "name": "❓ 疑似国内",
        "type": "select",
        "proxies": ["DIRECT", "🚀 选择代理", "REJECT"],
    })

    # 7. 🐟 漏网之鱼
    proxy_groups.append({
        "name": "🐟 漏网之鱼",
        "type": "select",
        "proxies": ["DIRECT", "🚀 选择代理"],
    })

    # 8. 🚨 病毒网站
    proxy_groups.append({
        "name": "🚨 病毒网站",
        "type": "select",
        "proxies": ["REJECT", "DIRECT"],
    })

    # 9. ⛔ 广告拦截
    proxy_groups.append({
        "name": "⛔ 广告拦截",
        "type": "select",
        "proxies": ["REJECT", "DIRECT", "🚀 选择代理"],
    })

    # 10. 🗺️ 选择地区 (汇集所有地区子组)
    active_region_names = [r for r in ALL_REGION_NAMES if r in region_groups]
    proxy_groups.append({
        "name": "🗺️ 选择地区",
        "type": "select",
        "proxies": active_region_names if active_region_names else ["REJECT"],
    })

    # 11. 各地区子组
    for region_name in ALL_REGION_NAMES:
        if region_name in region_groups:
            proxy_groups.append({
                "name": region_name,
                "type": "select",
                "proxies": region_groups[region_name],
            })
        else:
            # 无该地区节点时保留组但放入 REJECT
            proxy_groups.append({
                "name": region_name,
                "type": "select",
                "proxies": ["REJECT"],
            })

    # ---------- 构建 rules ----------
    rules = build_rules()

    # ---------- 构建完整配置 ----------
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    config = OrderedDict()
    config["# Update"] = None  # 占位，后续在输出时手动处理

    config_data = {
        "allow-lan": False,
        "dns": {
            "enable": True,
            "enhanced-mode": "redir-host",
            "fallback": ["8.8.8.8", "1.1.1.1"],
            "ipv6": True,
            "listen": ":1053",
            "nameserver": ["223.5.5.5", "114.114.114.114"],
        },
        "external-controller": "0.0.0.0:9090",
        "global-client-fingerprint": "chrome",
        "ipv6": True,
        "log-level": "warning",
        "mixed-port": 7890,
        "mode": "rule",
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": rules,
        "sniffer": {
            "enable": True,
            "skip-domain": ["Mijia Cloud", "dlg.io.mi.com", "+.apple.com"],
            "sniff": {
                "HTTP": {
                    "override-destination": True,
                    "ports": [80, "8080-8880"],
                },
                "TLS": {
                    "ports": [443, 8443],
                },
            },
        },
        "tcp-concurrent": True,
        "unified-delay": True,
    }

    return config_data, now


def build_rules() -> list[str]:
    """
    构建常用的分流规则列表。
    包含广告拦截、国内外常见域名分流、GeoIP 兜底等。
    """
    rules = [
        # ---- 广告拦截 ----
        "DOMAIN-SUFFIX,ads.google.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,adservice.google.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,googleadservices.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,doubleclick.net,⛔ 广告拦截",
        "DOMAIN-SUFFIX,ad.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,adnxs.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,adsrvr.org,⛔ 广告拦截",
        "DOMAIN-SUFFIX,pgdt.ugdtimg.com,⛔ 广告拦截",
        "DOMAIN-KEYWORD,adservice,⛔ 广告拦截",
        "DOMAIN-KEYWORD,tracking,⛔ 广告拦截",

        # ---- 病毒/恶意网站 ----
        "DOMAIN-SUFFIX,malware-site.example,🚨 病毒网站",

        # ---- 国内直连 ----
        "DOMAIN-SUFFIX,cn,DIRECT",
        "DOMAIN-SUFFIX,baidu.com,DIRECT",
        "DOMAIN-SUFFIX,qq.com,DIRECT",
        "DOMAIN-SUFFIX,taobao.com,DIRECT",
        "DOMAIN-SUFFIX,tmall.com,DIRECT",
        "DOMAIN-SUFFIX,jd.com,DIRECT",
        "DOMAIN-SUFFIX,alipay.com,DIRECT",
        "DOMAIN-SUFFIX,163.com,DIRECT",
        "DOMAIN-SUFFIX,126.com,DIRECT",
        "DOMAIN-SUFFIX,weibo.com,DIRECT",
        "DOMAIN-SUFFIX,bilibili.com,DIRECT",
        "DOMAIN-SUFFIX,zhihu.com,DIRECT",
        "DOMAIN-SUFFIX,douyin.com,DIRECT",
        "DOMAIN-SUFFIX,toutiao.com,DIRECT",
        "DOMAIN-SUFFIX,csdn.net,DIRECT",
        "DOMAIN-SUFFIX,aliyun.com,DIRECT",
        "DOMAIN-SUFFIX,aliyuncs.com,DIRECT",
        "DOMAIN-SUFFIX,tencentcloud.com,DIRECT",
        "DOMAIN-SUFFIX,meituan.com,DIRECT",
        "DOMAIN-SUFFIX,dianping.com,DIRECT",
        "DOMAIN-SUFFIX,mi.com,DIRECT",
        "DOMAIN-SUFFIX,xiaomi.com,DIRECT",

        # ---- 需要代理的海外服务 ----
        "DOMAIN-SUFFIX,google.com,🚀 选择代理",
        "DOMAIN-SUFFIX,google.co.jp,🚀 选择代理",
        "DOMAIN-SUFFIX,googleapis.com,🚀 选择代理",
        "DOMAIN-SUFFIX,gstatic.com,🚀 选择代理",
        "DOMAIN-SUFFIX,youtube.com,🚀 选择代理",
        "DOMAIN-SUFFIX,ytimg.com,🚀 选择代理",
        "DOMAIN-SUFFIX,googlevideo.com,🚀 选择代理",
        "DOMAIN-SUFFIX,gmail.com,🚀 选择代理",
        "DOMAIN-SUFFIX,github.com,🚀 选择代理",
        "DOMAIN-SUFFIX,githubusercontent.com,🚀 选择代理",
        "DOMAIN-SUFFIX,twitter.com,🚀 选择代理",
        "DOMAIN-SUFFIX,x.com,🚀 选择代理",
        "DOMAIN-SUFFIX,twimg.com,🚀 选择代理",
        "DOMAIN-SUFFIX,facebook.com,🚀 选择代理",
        "DOMAIN-SUFFIX,fbcdn.net,🚀 选择代理",
        "DOMAIN-SUFFIX,instagram.com,🚀 选择代理",
        "DOMAIN-SUFFIX,whatsapp.com,🚀 选择代理",
        "DOMAIN-SUFFIX,telegram.org,🚀 选择代理",
        "DOMAIN-SUFFIX,t.me,🚀 选择代理",
        "DOMAIN-SUFFIX,wikipedia.org,🚀 选择代理",
        "DOMAIN-SUFFIX,reddit.com,🚀 选择代理",
        "DOMAIN-SUFFIX,netflix.com,🚀 选择代理",
        "DOMAIN-SUFFIX,nflxvideo.net,🚀 选择代理",
        "DOMAIN-SUFFIX,spotify.com,🚀 选择代理",
        "DOMAIN-SUFFIX,discord.com,🚀 选择代理",
        "DOMAIN-SUFFIX,discordapp.com,🚀 选择代理",
        "DOMAIN-SUFFIX,openai.com,🚀 选择代理",
        "DOMAIN-SUFFIX,claude.ai,🚀 选择代理",
        "DOMAIN-SUFFIX,anthropic.com,🚀 选择代理",
        "DOMAIN-SUFFIX,chatgpt.com,🚀 选择代理",
        "DOMAIN-SUFFIX,amazonaws.com,🚀 选择代理",
        "DOMAIN-SUFFIX,cloudflare.com,🚀 选择代理",
        "DOMAIN-SUFFIX,microsoft.com,🚀 选择代理",
        "DOMAIN-SUFFIX,apple.com,🚀 选择代理",
        "DOMAIN-SUFFIX,icloud.com,🚀 选择代理",
        "DOMAIN-SUFFIX,amazon.com,🚀 选择代理",
        "DOMAIN-SUFFIX,twitch.tv,🚀 选择代理",
        "DOMAIN-SUFFIX,steam.com,🚀 选择代理",
        "DOMAIN-SUFFIX,steampowered.com,🚀 选择代理",
        "DOMAIN-SUFFIX,steamcommunity.com,🚀 选择代理",
        "DOMAIN-SUFFIX,pixiv.net,🚀 选择代理",
        "DOMAIN-SUFFIX,pximg.net,🚀 选择代理",
        "DOMAIN-SUFFIX,docker.com,🚀 选择代理",
        "DOMAIN-SUFFIX,docker.io,🚀 选择代理",
        "DOMAIN-SUFFIX,npmjs.org,🚀 选择代理",
        "DOMAIN-SUFFIX,pypi.org,🚀 选择代理",
        "DOMAIN-SUFFIX,huggingface.co,🚀 选择代理",
        "DOMAIN-SUFFIX,medium.com,🚀 选择代理",
        "DOMAIN-SUFFIX,stackoverflow.com,🚀 选择代理",

        # ---- 流媒体锁区 ----
        "DOMAIN-SUFFIX,hulu.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,hbo.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,hbomax.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,disneyplus.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,disney-plus.net,🌐 突破锁区",
        "DOMAIN-SUFFIX,primevideo.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,dazn.com,🌐 突破锁区",

        # ---- GeoIP 兜底 ----
        "GEOIP,CN,❓ 疑似国内",

        # ---- 最终兜底 ----
        "MATCH,🐟 漏网之鱼",
    ]
    return rules


def write_output(config_data: dict, update_time: str, filepath: Path) -> None:
    """
    将完整配置写入 YAML 文件。
    在文件头部添加更新时间注释。
    """
    # 自定义 YAML 输出样式，使字符串不被强制加引号
    class CleanDumper(yaml.SafeDumper):
        pass

    # 处理 OrderedDict
    def _dict_representer(dumper, data):
        return dumper.represent_mapping("tag:yaml.org,2002:map", data.items())

    CleanDumper.add_representer(OrderedDict, _dict_representer)

    # 确保中文等 Unicode 字符正常输出
    yaml_content = yaml.dump(
        config_data,
        Dumper=CleanDumper,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=1000,  # 避免长行被折叠
    )

    # 在顶部添加注释
    header = f"# Update: {update_time}\n"
    filepath.write_text(header + yaml_content, encoding="utf-8")
    log.info(f"配置文件已写入: {filepath}")


# ======================== 主流程 ========================

def main():
    """脚本主入口：读取 → 抓取 → 解析 → 去重 → 延迟测试 → 分类 → 构建 → 输出"""
    log.info("=" * 50)
    log.info("Clash Meta 订阅合并工具 启动")
    log.info("=" * 50)

    # 1. 读取订阅链接
    urls = read_urls(ADDR_FILE)
    if not urls:
        log.error("未找到有效的订阅链接，退出")
        sys.exit(1)

    # 2. 逐个抓取并提取代理节点
    all_proxies: list[dict] = []
    success_count = 0
    for i, url in enumerate(urls, 1):
        log.info(f"[{i}/{len(urls)}] 处理订阅链接:")
        content = fetch_content(url)
        if content is None:
            log.warning(f"  跳过该链接（获取失败）")
            continue

        proxies = extract_proxies(content)
        if proxies:
            log.info(f"  提取到 {len(proxies)} 个节点")
            all_proxies.extend(proxies)
            success_count += 1
        else:
            log.warning(f"  未提取到任何节点")

    log.info(f"共成功处理 {success_count}/{len(urls)} 个订阅源")
    log.info(f"共提取 {len(all_proxies)} 个原始节点")

    if not all_proxies:
        log.error("未获取到任何代理节点，退出")
        sys.exit(1)

    # 3. 去重
    proxies = deduplicate_proxies(all_proxies)
    log.info(f"去重后剩余 {len(proxies)} 个节点")

    # 4. 过滤中国大陆/香港/台湾节点
    proxies = filter_blocked_regions(proxies)
    if not proxies:
        log.error("过滤后无剩余节点，退出")
        sys.exit(1)

    # 5. 延迟测试，淘汰超时不可达节点
    proxies = test_proxies_latency(proxies)
    if not proxies:
        log.error("所有节点均超时不可达，退出")
        sys.exit(1)

    # 6. 构建完整配置
    config_data, update_time = build_config(proxies)

    # 7. 写入文件
    write_output(config_data, update_time, OUTPUT_FILE)

    # 8. 统计地区分布
    region_groups = classify_by_region(proxies)
    log.info("--- 地区分布统计 ---")
    for region_name, names in region_groups.items():
        log.info(f"  {region_name}: {len(names)} 个节点")
    unclassified = len(proxies) - sum(len(v) for v in region_groups.values())
    if unclassified > 0:
        log.info(f"  ❔ 未分类: {unclassified} 个节点")

    log.info("=" * 50)
    log.info("完成！输出文件: outcome.meta.yml")
    log.info("=" * 50)


if __name__ == "__main__":
    main()
