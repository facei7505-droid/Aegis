"""Protect a Flask app with one line.

    pip install aegis-selfheal flask
    export AEGIS_TELEGRAM_TOKEN=...  AEGIS_TELEGRAM_CHAT=...   # optional alerts
    export ANTHROPIC_API_KEY=...                               # optional Claude patches
    python examples/flask_app.py
"""
from flask import Flask, request

from aegis.integrations import protect

app = Flask(__name__)


@app.route("/hello")
def hello():
    return {"hello": request.args.get("name", "world")}


# Blocks attacks, alerts you, and writes verified patches to .aegis/patches/ for review.
protect(app, mode="block", heal="propose")

if __name__ == "__main__":
    app.run(port=8000)
