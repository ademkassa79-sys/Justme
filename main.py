""" 
Cyber Defense Arsenal — main entry point

Starts:
	1.	Log Collector  (watches the configured log file)
	2.	Pattern Engine  (checks each new line against known attack signatures)
	3.	Alert System    (persists detections, notifies via Telegram/email)
	4.	Dashboard       (web UI showing everything live, in a background thread)

Run with: 
python3 main.py
"""

import json 
import os 
import sys 
import threading

from log_collector import FileLogSource
from pattern_engine import PatternEngine
from alert_system import AlertSystem

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) 
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.json")


def load_config(): 
    with open(CONFIG_PATH) as f: 
        return json.load(f)


def start_dashboard(config): 
    """Runs the Flask dashboard in a background thread so it doesn't block monitoring.""" 
    sys.path.insert(0, os.path.join(BASE_DIR, "dashboard")) 
    from app import create_app

    app = create_app(config)
    app.run(
        host=config["dashboard"]["host"],
        port=config["dashboard"]["port"],
        debug=False,
        use_reloader=False,
    )


def main(): 
    config = load_config()

    print("=" * 50)
    print("  CYBER DEFENSE ARSENAL — monitoring started")
    print("=" * 50)
    print(f"Watching: {config['log_source']['path']}")
    print(f"Dashboard: http://{config['dashboard']['host']}:{config['dashboard']['port']}")
    print("Press Ctrl+C to stop.\n")

    dashboard_thread = threading.Thread(target=start_dashboard, args=(config,), daemon=True)
    dashboard_thread.start()

    collector = FileLogSource(config["log_source"]["path"])
    engine = PatternEngine(
        brute_force_max_attempts=config["brute_force"]["max_attempts"],
        brute_force_window_seconds=config["brute_force"]["window_seconds"],
    )
    alerts = AlertSystem(config)

    try:
        for timestamp, line in collector.watch():
            for detection in engine.analyze_line(timestamp, line):
                alerts.dispatch(detection)
    except KeyboardInterrupt:
        print("\nStopping Cyber Defense Arsenal...")
        collector.stop()


if __name__ == "__main__": 
    main()
