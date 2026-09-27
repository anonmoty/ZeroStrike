# core/owasp_db.py
# OWASP Top 10 (2021) Vulnerability Database

OWASP_TOP_10 = {
    "A01": {
        "name": "Broken Access Control",
        "desc": "Users can access resources they should not be able to.",
        "checks": ["admin_panel", "idor", "directory_listing", "cors_wildcard"]
    },
    "A02": {
        "name": "Cryptographic Failures",
        "desc": "Weak or missing encryption of sensitive data.",
        "checks": ["http_no_tls", "weak_ssl", "no_hsts", "weak_cipher"]
    },
    "A03": {
        "name": "Injection",
        "desc": "SQL, NoSQL, OS, LDAP injection flaws.",
        "checks": ["sql_error", "nosql_error", "command_injection", "ldap_error"]
    },
    "A04": {
        "name": "Insecure Design",
        "desc": "Missing or ineffective security design patterns.",
        "checks": ["no_rate_limit", "no_captcha", "weak_password_policy"]
    },
    "A05": {
        "name": "Security Misconfiguration",
        "desc": "Missing hardening, default configs, verbose errors.",
        "checks": ["server_banner", "debug_mode", "default_creds", "verbose_error", "xxe"]
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "desc": "Using components with known vulnerabilities.",
        "checks": ["old_jquery", "old_bootstrap", "old_wordpress", "old_php", "old_server"]
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "desc": "Weak session management and authentication.",
        "checks": ["no_session_secure", "no_httponly", "weak_cookie", "no_csrf"]
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "desc": "Insecure deserialization and CI/CD pipeline issues.",
        "checks": ["insecure_deser", "no_sri", "unsigned_updates"]
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "desc": "Insufficient logging of security events.",
        "checks": ["no_csp_report", "no_error_logging", "exposed_logs"]
    },
    "A10": {
        "name": "Server-Side Request Forgery (SSRF)",
        "desc": "Server makes requests to unintended locations.",
        "checks": ["open_redirect", "ssrf_param"]
    }
}

# Extra checks beyond OWASP
EXTRA_CHECKS = {
    "X01": {"name": "CORS Misconfiguration", "desc": "Improper Cross-Origin Resource Sharing"},
    "X02": {"name": "Cookie Security Issues", "desc": "Missing Secure/HttpOnly/SameSite flags"},
    "X03": {"name": "Information Disclosure", "desc": "Sensitive files or data exposed publicly"},
    "X04": {"name": "Missing Security Headers", "desc": "Critical HTTP security headers absent"},
}
