"""Flask REST API and dashboard."""

from __future__ import annotations

import os
import threading

import boto3
from flask import Flask, abort, jsonify, request, send_from_directory

from .checks import load_all
from .remediation import REMEDIATIONS, remediate
from .scanner import run_scan
from .storage import Store


def create_app(store: Store | None = None, session_factory=boto3.session.Session) -> Flask:
    app = Flask(__name__, static_folder="static")
    store = store or Store(os.environ.get("DATABASE_URL", "sqlite:///scans.db"))
    store.init_schema()
    lock = threading.Lock()  # one DB connection; serialise access
    app.config["STORE"] = store
    api_token = os.environ.get("API_TOKEN")

    @app.before_request
    def auth():
        # Mutating endpoints require a bearer token when API_TOKEN is set.
        if api_token and request.method == "POST" and request.path.startswith("/api/"):
            if request.headers.get("Authorization") != f"Bearer {api_token}":
                abort(401)

    @app.errorhandler(404)
    @app.errorhandler(400)
    @app.errorhandler(401)
    def err(e):
        return jsonify(error=e.name, message=e.description), e.code

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/")
    def dashboard():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/api/checks")
    def checks():
        return jsonify([{"id": s.id, "service": s.service, "severity": s.severity.value, "title": s.title,
                         "scope": s.scope, "auto_remediable": s.id in REMEDIATIONS}
                        for s in load_all().values()])

    @app.post("/api/scans")
    def create_scan():
        body = request.get_json(silent=True) or {}
        regions = body.get("regions")
        if regions is not None and (not isinstance(regions, list) or not all(isinstance(r, str) for r in regions)):
            abort(400, "regions must be a list of strings")
        result = run_scan(session_factory(), regions=regions, only=body.get("checks"))
        with lock:
            store.save_scan(result)
        return jsonify(result.to_dict()), 201

    @app.get("/api/scans")
    def list_scans():
        with lock:
            return jsonify(store.list_scans(int(request.args.get("limit", 50))))

    @app.get("/api/scans/<int:scan_id>")
    def get_scan(scan_id):
        with lock:
            scan = store.get_scan(scan_id)
        if not scan:
            abort(404, f"scan {scan_id} not found")
        return jsonify(scan)

    @app.get("/api/scans/<int:scan_id>/findings")
    def findings(scan_id):
        with lock:
            items = store.findings(scan_id, request.args.get("severity"), request.args.get("service"),
                                   request.args.get("status"))
        return jsonify([f.to_dict() for f in items])

    @app.get("/api/scans/<int:scan_id>/report")
    def report(scan_id):
        with lock:
            scan = store.get_scan(scan_id)
            if not scan:
                abort(404, f"scan {scan_id} not found")
            return jsonify({**scan, "by_service": store.service_breakdown(scan_id),
                            "top_resources": store.top_resources(scan_id),
                            "trend": store.trend(scan["account_id"])})

    @app.post("/api/findings/<int:finding_id>/remediate")
    def remediate_finding(finding_id):
        dry_run = (request.get_json(silent=True) or {}).get("dry_run", True) is not False
        with lock:
            f = store.get_finding(finding_id)
        if not f:
            abort(404, f"finding {finding_id} not found")
        outcome = remediate(f, session_factory(), dry_run=dry_run)
        if outcome["status"] == "remediated":
            with lock:
                store.set_finding_status(finding_id, "REMEDIATED")
        return jsonify(outcome)

    return app


if __name__ == "__main__":
    from .logging_config import setup_logging

    setup_logging()
    create_app().run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
