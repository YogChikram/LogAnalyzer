import json
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    log_type = db.Column(db.String(50), nullable=False, default="generic")
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    total_lines = db.Column(db.Integer, default=0)
    parsed_lines = db.Column(db.Integer, default=0)
    ai_powered = db.Column(db.Boolean, default=False)

    findings = db.relationship(
        "Finding", backref="scan", cascade="all, delete-orphan", lazy="dynamic"
    )

    def severity_counts(self):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def overall_risk(self):
        counts = self.severity_counts()
        if counts["Critical"]:
            return "Critical"
        if counts["High"]:
            return "High"
        if counts["Medium"]:
            return "Medium"
        if counts["Low"]:
            return "Low"
        return "Info"


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)

    finding_type = db.Column(db.String(120), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="Info")
    source_ip = db.Column(db.String(64), nullable=True)
    match_count = db.Column(db.Integer, default=1)
    first_seen = db.Column(db.String(64), nullable=True)
    last_seen = db.Column(db.String(64), nullable=True)

    summary = db.Column(db.Text, nullable=True)
    solution = db.Column(db.Text, nullable=True)

    _sample_lines = db.Column("sample_lines", db.Text, nullable=True)

    @property
    def sample_lines(self):
        if not self._sample_lines:
            return []
        return json.loads(self._sample_lines)

    @sample_lines.setter
    def sample_lines(self, value):
        self._sample_lines = json.dumps(value or [])

    SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

    def severity_rank(self):
        return self.SEVERITY_ORDER.get(self.severity, 5)
