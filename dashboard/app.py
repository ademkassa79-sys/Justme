""" 
Dashboard

Layer 4 of the Cyber Defense Arsenal.

A small Flask app that reads data/detections.jsonl and shows it as a 
live-updating feed. Read-only by design.
"""

import json 
import os 
from collections import Counter

from flask import Flask, jsonify, render_template


def create_app(config): 
    app = Flask(__name__) 
    
    # تحديد مسار ملف التنبيهات بدقة
    detections_file = os.path.join( 
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
        config["storage"]["detections_file"], 
    )

    def read_detections(limit=200):
        if not os.path.exists(detections_file):
            return []
        with open(detections_file) as f:
            lines = f.readlines()[-limit:]
        records = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return list(reversed(records))

    @app.route("/")
    def index():
        return render_template("index.html", log_path=config["log_source"]["path"])

    @app.route("/api/detections")
    def api_detections():
        detections = read_detections()
        severity_counts = Counter(d["severity"] for d in detections)
        return jsonify(
            {
                "detections": detections,
                "total": len(detections),
                "by_severity": {
                    "critical": severity_counts.get("critical", 0),
                    "high": severity_counts.get("high", 0),
                    "medium": severity_counts.get("medium", 0),
                    "low": severity_counts.get("low", 0),
                },
            }
        )

    return app
