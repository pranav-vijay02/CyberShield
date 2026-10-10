"""Flask application for the PhishGuard educational message analyzer."""

from __future__ import annotations

import logging
import os

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from analyzer import MAX_MESSAGE_LENGTH, MessageInputError, analyze_message

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = MAX_MESSAGE_LENGTH + 2_048
logging.basicConfig(level=logging.INFO)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@app.get("/")
def index():
    return render_template("index.html", max_message_length=MAX_MESSAGE_LENGTH)


@app.get("/favicon.ico")
def favicon():
    return app.response_class(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        '<path fill="none" stroke="#55c8b2" stroke-width="2" '
        'd="M16 3.5 27 8v7.6c0 6.6-4.6 10.8-11 13.2C9.6 26.4 5 22.2 5 15.6V8l11-4.5Z"/>'
        '<path fill="none" stroke="#55c8b2" stroke-width="2" '
        'stroke-linecap="round" stroke-linejoin="round" d="m11.7 16.1 2.8 2.8 6-6.2"/>'
        "</svg>",
        mimetype="image/svg+xml",
    )


@app.post("/analyze")
def analyze():
    if not request.is_json:
        return jsonify(error="Send the message as JSON with a message field."), 415

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="The request body must be a JSON object."), 400

    try:
        result = analyze_message(body.get("message"))
    except MessageInputError as error:
        return jsonify(error=str(error)), 400
    except Exception:
        app.logger.exception("Unexpected error while analyzing a message")
        return jsonify(error="The message could not be analyzed. Please try again."), 500
    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    return jsonify(error=f"Request is too large. Messages must be {MAX_MESSAGE_LENGTH:,} characters or fewer."), 413


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
