import re
from urllib.parse import unquote

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<protocol>[^"]+))?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

# Generic fallback: pull an IP and a bracketed/ISO timestamp out of any line.
GENERIC_IP_RE = re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")
GENERIC_TS_RE = re.compile(r"\[(?P<ts1>[^\]]+)\]|(?P<ts2>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")


def parse_log_file(text):
    """Parse raw log text into a list of structured entry dicts.

    Tries Apache/Nginx combined (and common) log format per line; falls back
    to a loose generic parse so any text log still yields usable entries.
    Returns (entries, log_type) where log_type is 'apache_nginx' or 'generic'.
    """
    lines = text.splitlines()
    entries = []
    matched = 0

    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        m = COMBINED_RE.match(line)
        if m:
            matched += 1
            gd = m.groupdict()
            entries.append({
                "line_no": i,
                "ip": gd.get("ip"),
                "timestamp": gd.get("timestamp"),
                "method": gd.get("method") or "",
                "path": unquote(gd.get("path") or ""),
                "protocol": gd.get("protocol") or "",
                "status": int(gd["status"]) if gd.get("status") else None,
                "size": gd.get("size"),
                "referrer": gd.get("referrer") or "",
                "user_agent": gd.get("user_agent") or "",
                "raw": line.strip(),
            })
        else:
            ip_m = GENERIC_IP_RE.search(line)
            ts_m = GENERIC_TS_RE.search(line)
            ts = None
            if ts_m:
                ts = ts_m.group("ts1") or ts_m.group("ts2")
            entries.append({
                "line_no": i,
                "ip": ip_m.group("ip") if ip_m else None,
                "timestamp": ts,
                "method": "",
                "path": line.strip(),
                "protocol": "",
                "status": None,
                "size": None,
                "referrer": "",
                "user_agent": "",
                "raw": line.strip(),
            })

    log_type = "apache_nginx" if matched >= max(1, len(entries) * 0.5) else "generic"
    return entries, log_type
