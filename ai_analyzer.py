import json
from typing import List, Literal

import anthropic
from pydantic import BaseModel

SEVERITY_LEVELS = Literal["Critical", "High", "Medium", "Low", "Info"]

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst reviewing web server log findings that were "
    "already flagged by a rule-based detector. For each finding, assign an accurate "
    "severity, write a concise plain-English summary of what happened and why it "
    "matters, and give concrete, actionable remediation steps a sysadmin could "
    "follow immediately. Be precise and avoid generic filler. Base your assessment "
    "on the finding type, how many times it occurred, and the sample log lines."
)


class AIFinding(BaseModel):
    id: int
    severity: SEVERITY_LEVELS
    summary: str
    solution: str


class AIAnalysisResult(BaseModel):
    findings: List[AIFinding]


class AIAnalyzer:
    def __init__(self, api_key, model="claude-opus-5"):
        self.model = model
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else None

    def available(self):
        return self.client is not None

    def analyze(self, findings):
        """Enrich rule-based findings with AI severity/summary/solution.

        `findings` is the list produced by detector.detect(). Returns a new
        list of dicts with severity/summary/solution filled in. Falls back to
        rule-based defaults if the API is unavailable or the call fails.
        """
        if not findings:
            return []

        if not self.available():
            return [self._fallback(f, reason="No Anthropic API key configured.") for f in findings]

        indexed = [{**f, "id": i} for i, f in enumerate(findings)]
        prompt_payload = [
            {
                "id": f["id"],
                "finding_type": f["finding_type"],
                "source_ip": f["source_ip"],
                "match_count": f["match_count"],
                "first_seen": f["first_seen"],
                "last_seen": f["last_seen"],
                "sample_log_lines": f["sample_lines"],
            }
            for f in indexed
        ]

        user_message = (
            "Assess each of the following log findings. Return one result per "
            "finding `id`.\n\n" + json.dumps(prompt_payload, indent=2, default=str)
        )

        try:
            response = self.client.messages.parse(
                model=self.model,
                max_tokens=16000,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
                output_format=AIAnalysisResult,
            )
            result = response.parsed_output
            by_id = {r.id: r for r in result.findings}
        except (anthropic.APIError, anthropic.APIConnectionError) as exc:
            return [self._fallback(f, reason=f"AI analysis failed: {exc}") for f in findings]
        except Exception as exc:  # malformed/unparsable response, etc.
            return [self._fallback(f, reason=f"AI analysis failed: {exc}") for f in findings]

        enriched = []
        for f in indexed:
            ai = by_id.get(f["id"])
            if ai:
                enriched.append({
                    **f,
                    "severity": ai.severity,
                    "summary": ai.summary,
                    "solution": ai.solution,
                })
            else:
                enriched.append(self._fallback(f, reason="AI did not return a result for this finding."))
        return enriched

    @staticmethod
    def _fallback(finding, reason):
        return {
            **finding,
            "severity": finding.get("default_severity", "Info"),
            "summary": (
                f"{finding['finding_type']} detected {finding['match_count']} time(s)"
                f"{' from ' + finding['source_ip'] if finding.get('source_ip') else ''}. "
                f"({reason})"
            ),
            "solution": _GENERIC_SOLUTIONS.get(
                finding["finding_type"],
                "Review the flagged log lines manually and cross-reference the "
                "source IP against known threat intelligence feeds.",
            ),
        }


_GENERIC_SOLUTIONS = {
    "SQL Injection Attempt": (
        "Use parameterized queries/prepared statements everywhere; deploy a WAF "
        "rule blocking common SQLi payloads; block or rate-limit the source IP."
    ),
    "Cross-Site Scripting (XSS) Attempt": (
        "Ensure all user input is output-encoded; add a strict Content-Security-"
        "Policy header; validate and sanitize input server-side."
    ),
    "Path Traversal Attempt": (
        "Reject requests containing '../' sequences at the web server/WAF layer; "
        "never build file paths directly from user input."
    ),
    "Command Injection Attempt": (
        "Never pass user input to a shell; use safe APIs instead of shell "
        "invocation; block the source IP immediately."
    ),
    "Sensitive File / Admin Path Probing": (
        "Ensure sensitive files (.env, .git, backups) are not web-accessible; "
        "restrict admin panels by IP allowlist or VPN."
    ),
    "Known Scanner Tool Detected": (
        "Block the source IP/user-agent at the firewall or WAF; review what "
        "endpoints the scanner accessed for exposed vulnerabilities."
    ),
    "Directory / Vulnerability Scanning": (
        "Rate-limit or block the source IP; ensure no sensitive endpoints were "
        "discovered and are unprotected."
    ),
    "Possible Brute Force Login Attempts": (
        "Enforce account lockout/rate limiting on login endpoints; require MFA; "
        "block the source IP after repeated failures."
    ),
    "High-Volume Request Burst (Possible DoS)": (
        "Apply rate limiting per IP; consider a CDN/DDoS protection service if "
        "this pattern recurs."
    ),
    "Suspicious HTTP Method": (
        "Disable unused HTTP methods (TRACE, CONNECT) at the web server config."
    ),
    "Elevated Server Error Rate": (
        "Investigate application logs for the cause of 5xx errors; may indicate "
        "instability or a failed exploitation attempt worth reviewing."
    ),
}
