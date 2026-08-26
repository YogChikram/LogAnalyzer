import re
from collections import defaultdict

SQLI_RE = re.compile(
    r"(\bunion\b.{0,40}\bselect\b)|(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)|"
    r"(\bselect\b.{0,40}\bfrom\b)|(\bdrop\b\s+\btable\b)|(--\s*$)|(;\s*--)|"
    r"(\bsleep\(\d+\))|(\bbenchmark\()|(\bxp_cmdshell\b)|(\binformation_schema\b)|"
    r"(\bor\b\s+1\s*=\s*1)|('\s*or\s*')",
    re.IGNORECASE,
)

XSS_RE = re.compile(
    r"(<script\b)|(javascript:)|(onerror\s*=)|(onload\s*=)|(%3cscript)|(<img\s+src=)|(document\.cookie)",
    re.IGNORECASE,
)

PATH_TRAVERSAL_RE = re.compile(
    r"(\.\./)|(\.\.%2f)|(%2e%2e%2f)|(/etc/passwd)|(/windows/system32)|(\.\.\\)",
    re.IGNORECASE,
)

CMD_INJECTION_RE = re.compile(
    r"(;\s*cat\s)|(\|\s*id\b)|(`id`)|(\$\(.*\))|(wget\s+http)|(curl\s+http)|(/bin/(ba)?sh)",
    re.IGNORECASE,
)

SENSITIVE_PATH_RE = re.compile(
    r"(\.env\b)|(\.git/config)|(wp-admin)|(wp-login)|(phpmyadmin)|(\.ssh/)|"
    r"(config\.php)|(backup\.sql)|(\.htaccess)|(\.aws/credentials)|(id_rsa)",
    re.IGNORECASE,
)

SCANNER_UA_RE = re.compile(
    r"(sqlmap)|(nikto)|(nmap)|(masscan)|(dirbuster)|(gobuster)|(acunetix)|"
    r"(nessus)|(w3af)|(zgrab)|(python-urllib)|(havij)",
    re.IGNORECASE,
)

LOGIN_PATH_RE = re.compile(r"(login|signin|wp-login|admin|auth)", re.IGNORECASE)

SEVERITY_DEFAULTS = {
    "SQL Injection Attempt": "Critical",
    "Cross-Site Scripting (XSS) Attempt": "High",
    "Path Traversal Attempt": "High",
    "Command Injection Attempt": "Critical",
    "Sensitive File / Admin Path Probing": "Medium",
    "Known Scanner Tool Detected": "Medium",
    "Directory / Vulnerability Scanning": "Medium",
    "Possible Brute Force Login Attempts": "High",
    "High-Volume Request Burst (Possible DoS)": "Medium",
    "Suspicious HTTP Method": "Low",
    "Elevated Server Error Rate": "Low",
}


def _new_bucket():
    return {
        "count": 0,
        "first_seen": None,
        "last_seen": None,
        "sample_lines": [],
        "ips": set(),
    }


def _record(buckets, finding_type, ip, timestamp, raw_line):
    key = (finding_type, ip or "unknown")
    b = buckets[key]
    b["count"] += 1
    if timestamp:
        if b["first_seen"] is None:
            b["first_seen"] = timestamp
        b["last_seen"] = timestamp
    if len(b["sample_lines"]) < 5:
        b["sample_lines"].append(raw_line)
    if ip:
        b["ips"].add(ip)


def detect(entries):
    """Run rule-based detection over parsed log entries.

    Returns a list of aggregated finding dicts, ready to hand to the AI
    analyzer for severity/summary/solution enrichment.
    """
    buckets = defaultdict(_new_bucket)

    ip_paths_404 = defaultdict(set)
    ip_auth_failures = defaultdict(int)
    ip_total_requests = defaultdict(int)
    status_5xx_count = 0
    total_entries = len(entries) or 1

    for e in entries:
        haystack = f"{e['path']} {e.get('referrer', '')}"
        ip = e.get("ip")
        ts = e.get("timestamp")
        raw = e.get("raw", "")

        if SQLI_RE.search(haystack):
            _record(buckets, "SQL Injection Attempt", ip, ts, raw)
        if XSS_RE.search(haystack):
            _record(buckets, "Cross-Site Scripting (XSS) Attempt", ip, ts, raw)
        if PATH_TRAVERSAL_RE.search(haystack):
            _record(buckets, "Path Traversal Attempt", ip, ts, raw)
        if CMD_INJECTION_RE.search(haystack):
            _record(buckets, "Command Injection Attempt", ip, ts, raw)
        if SENSITIVE_PATH_RE.search(e["path"]):
            _record(buckets, "Sensitive File / Admin Path Probing", ip, ts, raw)
        if SCANNER_UA_RE.search(e.get("user_agent", "")):
            _record(buckets, "Known Scanner Tool Detected", ip, ts, raw)
        if e.get("method") in ("TRACE", "CONNECT"):
            _record(buckets, "Suspicious HTTP Method", ip, ts, raw)

        if ip:
            ip_total_requests[ip] += 1

        status = e.get("status")
        if status == 404 and ip:
            ip_paths_404[ip].add(e["path"])
        if status in (401, 403) and ip and LOGIN_PATH_RE.search(e["path"]):
            ip_auth_failures[ip] += 1
        if status and status >= 500:
            status_5xx_count += 1

    # Directory / vulnerability scanning: many distinct 404 paths from one IP
    for ip, paths in ip_paths_404.items():
        if len(paths) >= 15:
            b = buckets[("Directory / Vulnerability Scanning", ip)]
            b["count"] = len(paths)
            b["ips"] = {ip}
            b["sample_lines"] = list(paths)[:5]

    # Brute force: many auth failures on login-like paths from one IP
    for ip, fails in ip_auth_failures.items():
        if fails >= 10:
            b = buckets[("Possible Brute Force Login Attempts", ip)]
            b["count"] = fails
            b["ips"] = {ip}
            if not b["sample_lines"]:
                b["sample_lines"] = [f"{fails} failed auth requests from {ip}"]

    # High-volume burst: single IP responsible for a large share of traffic
    for ip, count in ip_total_requests.items():
        if count >= 300 or count / total_entries >= 0.3:
            b = buckets[("High-Volume Request Burst (Possible DoS)", ip)]
            b["count"] = count
            b["ips"] = {ip}
            if not b["sample_lines"]:
                b["sample_lines"] = [f"{count} requests from {ip} ({count / total_entries:.0%} of traffic)"]

    if status_5xx_count and status_5xx_count / total_entries >= 0.1:
        b = buckets[("Elevated Server Error Rate", None)]
        b["count"] = status_5xx_count
        if not b["sample_lines"]:
            b["sample_lines"] = [f"{status_5xx_count} 5xx responses out of {total_entries} requests"]

    findings = []
    for (finding_type, ip), b in buckets.items():
        if b["count"] == 0:
            continue
        findings.append({
            "finding_type": finding_type,
            "source_ip": ip,
            "match_count": b["count"],
            "first_seen": b["first_seen"],
            "last_seen": b["last_seen"],
            "sample_lines": b["sample_lines"],
            "default_severity": SEVERITY_DEFAULTS.get(finding_type, "Info"),
        })

    findings.sort(key=lambda f: f["match_count"], reverse=True)
    return findings
