from flask import jsonify
from flask import Flask, render_template
import os
import json

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INCIDENT_FOLDER = os.path.join(BASE_DIR, "incidents")

@app.route("/live")
def live():

    status_file = os.path.join(
        BASE_DIR,
        "live_status.json"
    )

    if os.path.exists(status_file):

        with open(status_file, "r") as file:
            return jsonify(json.load(file))

    return jsonify({
        "status": "MONITORING",
        "risk_score": 0,
        "reasons": [],
        "affected_files": []
    })
@app.route("/")
def dashboard():

    incidents = []

    if os.path.exists(INCIDENT_FOLDER):

        for filename in os.listdir(INCIDENT_FOLDER):

            if filename.endswith(".json"):

                filepath = os.path.join(
                    INCIDENT_FOLDER,
                    filename
                )

                try:
                    with open(filepath, "r") as file:
                        data = json.load(file)
                        incidents.append(data)

                except Exception:
                    pass

    incidents.sort(
        key=lambda x: x.get("timestamp", ""),
        reverse=True
    )

    latest = incidents[0] if incidents else None

    return render_template(
        "index.html",
        latest=latest,
        incidents=incidents
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )