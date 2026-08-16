"""Map CWE (Common Weakness Enumeration) ids to a small set of readable categories."""

CWE_CATEGORIES: dict[str, str] = {
    # Injection
    "CWE-79": "injection",  # XSS
    "CWE-89": "injection",  # SQL injection
    "CWE-78": "injection",  # OS command injection
    "CWE-77": "injection",  # Command injection
    "CWE-94": "injection",  # Code injection
    "CWE-611": "injection",  # XXE
    "CWE-91": "injection",  # XML injection
    # Memory safety
    "CWE-119": "memory",
    "CWE-120": "memory",
    "CWE-125": "memory",
    "CWE-787": "memory",
    "CWE-416": "memory",  # use after free
    "CWE-476": "memory",  # null pointer dereference
    "CWE-190": "memory",  # integer overflow
    "CWE-415": "memory",  # double free
    # Path / file handling
    "CWE-22": "path-traversal",
    "CWE-98": "path-traversal",
    "CWE-434": "path-traversal",  # unrestricted upload
    # Cross-site request forgery
    "CWE-352": "csrf",
    # Access control / authorization
    "CWE-287": "access-control",  # improper authentication
    "CWE-269": "access-control",  # improper privilege management
    "CWE-284": "access-control",
    "CWE-862": "access-control",  # missing authorization
    "CWE-863": "access-control",  # incorrect authorization
    "CWE-732": "access-control",  # incorrect permission assignment
    # Credentials
    "CWE-798": "credentials",  # hardcoded credentials
    "CWE-522": "credentials",
    # Cryptography
    "CWE-295": "crypto",  # improper certificate validation
    "CWE-326": "crypto",
    "CWE-327": "crypto",  # broken/risky crypto algorithm
    "CWE-330": "crypto",  # insufficiently random values
    "CWE-347": "crypto",  # improper signature verification
    # Deserialization
    "CWE-502": "deserialization",
    # Input validation
    "CWE-20": "input-validation",
    # Information disclosure
    "CWE-200": "info-disclosure",
    "CWE-209": "info-disclosure",
    # Denial of service / resource management
    "CWE-400": "dos",
    "CWE-770": "dos",
    "CWE-835": "dos",
    # Race conditions
    "CWE-362": "race-condition",
    "CWE-367": "race-condition",
    # Server-side request forgery
    "CWE-918": "ssrf",
}


def categorize_cwe(cwe_ids: str | None) -> str:
    """Map a comma-separated CWE-id string to a category.

    Returns "none" if no CWE is present, "other" if none of the listed
    CWE ids are in the mapping, otherwise the category of the first
    recognized CWE id.
    """
    if not cwe_ids:
        return "none"

    for cwe_id in cwe_ids.split(","):
        category = CWE_CATEGORIES.get(cwe_id.strip())
        if category:
            return category
    return "other"
