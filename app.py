import os
import uuid

from flask import Flask, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from ai_analyzer import AIAnalyzer
from config import Config
from detector import detect
from log_parser import parse_log_file
from models import Finding, Scan, db


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "instance"), exist_ok=True)

    db.init_app(app)
    with app.app_context():
        db.create_all()

    analyzer = AIAnalyzer(app.config["ANTHROPIC_API_KEY"], app.config["CLAUDE_MODEL"])

    SEVERITY_COLORS = {
        "Critical": "#ef4444",
        "High": "#f97316",
        "Medium": "#f59e0b",
        "Low": "#06b6d4",
        "Info": "#94a3b8",
    }
    TYPE_COLORS = [
        "#7c3aed", "#ec4899", "#f59e0b", "#06b6d4", "#10b981",
        "#ef4444", "#0ea5e9", "#f43f5e", "#eab308", "#14b8a6", "#94a3b8",
    ]

    @app.context_processor
    def inject_globals():
        return {"ai_available": analyzer.available(), "claude_model": app.config["CLAUDE_MODEL"]}

    def allowed_file(filename):
        return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

    @app.route("/")
    def index():
        recent_scans = Scan.query.order_by(Scan.uploaded_at.desc()).limit(5).all()
        all_scans = Scan.query.all()
        stats = {
            "total_scans": len(all_scans),
            "total_lines": sum(s.total_lines for s in all_scans),
            "total_findings": sum(s.findings.count() for s in all_scans),
            "critical_high": sum(
                1 for s in all_scans for f in s.findings if f.severity in ("Critical", "High")
            ),
        }
        return render_template(
            "index.html",
            recent_scans=recent_scans,
            stats=stats,
            max_upload_mb=app.config["MAX_UPLOAD_MB"],
        )

    @app.route("/upload", methods=["POST"])
    def upload():
        file = request.files.get("logfile")
        if not file or file.filename == "":
            flash("Please choose a log file to upload.", "error")
            return redirect(url_for("index"))

        if not allowed_file(file.filename):
            flash("Only .log and .txt files are supported.", "error")
            return redirect(url_for("index"))

        safe_name = secure_filename(file.filename)
        stored_name = f"{uuid.uuid4().hex}_{safe_name}"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
        file.save(save_path)

        try:
            with open(save_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        finally:
            try:
                os.remove(save_path)
            except OSError:
                pass

        entries, log_type = parse_log_file(text)
        raw_findings = detect(entries)
        enriched = analyzer.analyze(raw_findings)

        scan = Scan(
            filename=safe_name,
            log_type=log_type,
            total_lines=len(text.splitlines()),
            parsed_lines=len(entries),
            ai_powered=analyzer.available(),
        )
        db.session.add(scan)
        db.session.flush()

        for f in enriched:
            finding = Finding(
                scan_id=scan.id,
                finding_type=f["finding_type"],
                severity=f["severity"],
                source_ip=f.get("source_ip"),
                match_count=f["match_count"],
                first_seen=f.get("first_seen"),
                last_seen=f.get("last_seen"),
                summary=f.get("summary"),
                solution=f.get("solution"),
            )
            finding.sample_lines = f.get("sample_lines", [])
            db.session.add(finding)

        db.session.commit()
        return redirect(url_for("scan_results", scan_id=scan.id))

    @app.route("/scan/<int:scan_id>")
    def scan_results(scan_id):
        scan = Scan.query.get_or_404(scan_id)
        all_findings = scan.findings.all()
        findings = sorted(all_findings, key=lambda f: f.severity_rank())
        timeline_findings = sorted(all_findings, key=lambda f: f.first_seen or "", reverse=True)
        severity_counts = scan.severity_counts()

        type_totals = {}
        for f in all_findings:
            type_totals[f.finding_type] = type_totals.get(f.finding_type, 0) + 1
        type_counts = sorted(type_totals.items(), key=lambda kv: kv[1], reverse=True)

        severity_chart_data = {
            "labels": [lvl for lvl in ["Critical", "High", "Medium", "Low", "Info"] if severity_counts.get(lvl, 0)],
            "counts": [severity_counts[lvl] for lvl in ["Critical", "High", "Medium", "Low", "Info"] if severity_counts.get(lvl, 0)],
            "colors": [SEVERITY_COLORS[lvl] for lvl in ["Critical", "High", "Medium", "Low", "Info"] if severity_counts.get(lvl, 0)],
        }
        type_chart_data = {
            "labels": [t for t, _ in type_counts],
            "counts": [c for _, c in type_counts],
            "colors": [TYPE_COLORS[i % len(TYPE_COLORS)] for i in range(len(type_counts))],
        }

        return render_template(
            "results.html",
            scan=scan,
            findings=findings,
            timeline_findings=timeline_findings,
            severity_counts=severity_counts,
            severity_colors=SEVERITY_COLORS,
            type_counts=type_counts,
            type_colors=TYPE_COLORS,
            severity_chart_data=severity_chart_data,
            type_chart_data=type_chart_data,
            overall_risk=scan.overall_risk(),
        )

    @app.route("/history")
    def history():
        scans = Scan.query.order_by(Scan.uploaded_at.desc()).all()
        return render_template("history.html", scans=scans)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
