"""What the security scan looks for: crypto-miner programs, mining pools, suspicious
ports, remote-access and tunnel tools, and Windows process names malware imitates.

Matching is by lower-case program name without ``.exe``. The lists are heuristics:
each hit is a lead to check, not proof (a remote-access tool you installed
yourself is fine; trust it from the Security tab and it stops being reported).
"""

from __future__ import annotations

import re

MINER_PROGRAMS = frozenset(
    {
        "xmrig",
        "xmrig-cuda",
        "xmrig-amd",
        "xmr-stak",
        "xmr-stak-cpu",
        "xmrstak",
        "nbminer",
        "t-rex",
        "trex",
        "phoenixminer",
        "lolminer",
        "gminer",
        "miner",
        "teamredminer",
        "nanominer",
        "ethminer",
        "cgminer",
        "bfgminer",
        "ccminer",
        "cpuminer",
        "cpuminer-opt",
        "minerd",
        "srbminer",
        "srbminer-multi",
        "excavator",
        "wildrig",
        "bminer",
        "z-enemy",
        "claymore",
        "ethdcrminer64",
        "nheqminer",
        "kawpowminer",
        "rigel",
        "bzminer",
        "onezerominer",
        "hellminer",
        "verthashminer",
        "nicehashminer",
        "nicehashquickminer",
        "minergate",
        "kryptex",
        "cudominer",
        "honeyminer",
        "nsgminer",
        "sgminer",
        "jceminer",
        "castxmr",
        "xmrminer",
        "cryptominer",
    }
)

MINER_COMMAND_LINE = re.compile(
    r"stratum\+(?:tcp|ssl|tls)://"
    r"|--donate-level"
    r"|--(?:algo|algorithm|coin)[= ](?:rx|randomx|cn|cryptonight|kawpow|ethash|etchash"
    r"|autolykos|xmr|monero|eth|etc|rvn|erg|kas|kheavyhash)\b"
    r"|\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
    re.IGNORECASE,
)

MINING_POOL_DOMAINS = (
    "2miners.com",
    "antpool.com",
    "c3pool.com",
    "c3pool.org",
    "crazypool.org",
    "dxpool.com",
    "emcd.io",
    "ethermine.org",
    "f2pool.com",
    "flypool.org",
    "hashvault.pro",
    "herominers.com",
    "hiveon.net",
    "k1pool.com",
    "kryptex.com",
    "kryptex.network",
    "luckpool.net",
    "minergate.com",
    "minexmr.com",
    "mining-dutch.nl",
    "moneroocean.stream",
    "monerohash.com",
    "nanopool.org",
    "nicehash.com",
    "p2pool.io",
    "poolin.com",
    "prohashing.com",
    "rplant.xyz",
    "supportxmr.com",
    "unmineable.com",
    "viabtc.com",
    "woolypooly.com",
    "xmrfast.com",
    "xmrig.com",
    "xmrpool.eu",
    "zergpool.com",
    "zpool.ca",
)

_POOL_WORDS = re.compile(r"(xmr|monero|stratum).*(pool|mine)|(pool|mine).*(xmr|monero|stratum)")


def is_pool_domain(name: str) -> bool:
    host = name.lower().rstrip(".")
    if any(host == d or host.endswith("." + d) for d in MINING_POOL_DOMAINS):
        return True
    return bool(_POOL_WORDS.search(host))


SUSPICIOUS_PORTS = {
    3333: "mining pool (stratum)",
    7777: "mining pool (stratum)",
    14433: "mining pool (stratum)",
    14444: "mining pool (stratum)",
    20535: "mining pool (stratum)",
    20580: "mining pool (stratum)",
    45560: "mining pool (stratum)",
    45700: "mining pool (stratum)",
    4444: "mining pool / common backdoor port",
    5555: "mining pool / common backdoor port",
    6666: "mining pool / IRC botnet",
    1337: "classic backdoor port",
    31337: "classic backdoor port",
    6667: "IRC (botnet command channel)",
    6697: "IRC over TLS (botnet command channel)",
    9001: "Tor relay",
    9030: "Tor directory",
    9050: "Tor SOCKS proxy",
    9150: "Tor Browser SOCKS proxy",
    1080: "SOCKS proxy",
    23: "Telnet (unencrypted remote shell)",
    2323: "Telnet (IoT botnets)",
}

REMOTE_ACCESS_PORTS = {
    3389: "Remote Desktop",
    5900: "VNC",
    5938: "TeamViewer",
    7070: "AnyDesk",
    21115: "RustDesk",
    21116: "RustDesk",
    21118: "RustDesk",
}

REMOTE_ACCESS_TOOLS = {
    "teamviewer": "TeamViewer",
    "teamviewer_service": "TeamViewer",
    "anydesk": "AnyDesk",
    "rustdesk": "RustDesk",
    "screenconnect.clientservice": "ScreenConnect / ConnectWise Control",
    "screenconnect.windowsclient": "ScreenConnect / ConnectWise Control",
    "connectwisecontrol.client": "ScreenConnect / ConnectWise Control",
    "srservice": "Splashtop",
    "splashtopstreamer": "Splashtop",
    "logmein": "LogMeIn",
    "lmiguardiansvc": "LogMeIn",
    "tvnserver": "TightVNC",
    "winvnc": "VNC server",
    "vncserver": "RealVNC",
    "uvnc_service": "UltraVNC",
    "rserver3": "Radmin",
    "radmin": "Radmin",
    "aa_v3": "Ammyy Admin",
    "ammyy_admin": "Ammyy Admin",
    "ultraviewer_service": "UltraViewer",
    "ultraviewer_desktop": "UltraViewer",
    "supremo": "Supremo",
    "supremoservice": "Supremo",
    "ateraagent": "Atera",
    "client32": "NetSupport Manager",
    "dwagent": "DWService",
    "dwagsvc": "DWService",
    "remoting_host": "Chrome Remote Desktop",
    "parsecd": "Parsec",
    "meshagent": "MeshCentral",
    "za_connect": "Zoho Assist",
    "zohoassist": "Zoho Assist",
    "remotepcservice": "RemotePC",
    "action1_agent": "Action1",
    "quickassist": "Quick Assist",
    "ngrok": "ngrok tunnel",
    "frpc": "frp reverse proxy",
    "chisel": "chisel tunnel",
    "plink": "PuTTY plink tunnel",
    "cloudflared": "Cloudflare tunnel",
}

SYSTEM_PROCESSES = frozenset(
    {
        "svchost",
        "csrss",
        "lsass",
        "lsm",
        "winlogon",
        "wininit",
        "services",
        "smss",
        "spoolsv",
        "taskhostw",
        "taskhost",
        "dllhost",
        "conhost",
        "rundll32",
        "explorer",
        "dwm",
        "sihost",
        "ctfmon",
        "searchindexer",
        "wuauclt",
        "msiexec",
        "regsvr32",
        "fontdrvhost",
    }
)

MALICIOUS_COMMAND = re.compile(
    r"\s-e(?:c|n[a-z]*)?\s+[A-Za-z0-9+/=]{20,}"
    r"|\b(?:iex|invoke-expression)\b"
    r"|downloadstring|downloadfile|frombase64string|invoke-webrequest|\biwr\b"
    r"|mshta(?:\.exe)?\s+[\"']?(?:https?|javascript|vbscript):"
    r"|regsvr32(?:\.exe)?\s+.*/i:https?:"
    r"|rundll32(?:\.exe)?\s+.*javascript:"
    r"|certutil(?:\.exe)?\s+.*-urlcache"
    r"|bitsadmin(?:\.exe)?\s+.*/transfer",
    re.IGNORECASE,
)

HIDDEN_COMMAND = re.compile(r"\s-w(?:indowstyle)?\s+hidden\b", re.IGNORECASE)


def program_key(name_or_path: str) -> str:
    """'C:\\X\\XMRig.EXE' -> 'xmrig'."""
    base = re.split(r"[\\/]", name_or_path.strip().strip('"'))[-1].lower()
    return base[:-4] if base.endswith(".exe") else base
