"""Heuristic features extracted from the free-text CVE description."""

EXPLOIT_KEYWORDS = [
    "exploit",
    "remote code execution",
    "rce",
    "zero-day",
    "zero day",
]

# Checked in order; the first matching category wins.
VENDOR_KEYWORDS: list[tuple[str, list[str]]] = [
    ("browser", ["chrome", "firefox", "safari browser", "microsoft edge", "web browser"]),
    ("mobile", ["android", "ios app", "mobile app", "iphone", "ipad"]),
    ("cloud", ["aws", "amazon web services", "azure", "kubernetes", "docker", "cloud platform"]),
    ("network", ["router", "firewall", "vpn", "switch", "cisco", "juniper", "fortinet", "network device"]),
    ("iot", ["iot", "firmware", "embedded device", "smart camera"]),
    ("database", ["sql server", "mysql", "postgresql", "mongodb", "oracle database", "database server"]),
    ("os", ["windows", "linux kernel", "macos", "microsoft windows", "operating system", "unix"]),
    ("web", ["wordpress", "plugin", "cms", "web application", "website", "apache", "nginx", "php"]),
]


def has_exploit_keyword(description: str | None) -> bool:
    if not description:
        return False
    lowered = description.lower()
    return any(keyword in lowered for keyword in EXPLOIT_KEYWORDS)


def vendor_category(description: str | None) -> str:
    if not description:
        return "other"
    lowered = description.lower()
    for category, keywords in VENDOR_KEYWORDS:
        if any(keyword in lowered for keyword in keywords):
            return category
    return "other"
