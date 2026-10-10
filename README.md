# PhishGuard

PhishGuard is an educational phishing and scam message analyzer. It applies a
small set of explainable rules to pasted text; it does not open URLs or save
submitted messages.

## Project structure

- `app.py` — Flask page and JSON API, request-size limits, and safe error handling.
- `analyzer.py` — independent rule-based message and URL analysis.
- `templates/index.html` — the accessible application page.
- `static/css/style.css` — responsive dashboard styling.
- `static/js/app.js` — page interactions and API requests.
- `tests/test_analyzer.py` — automated analyzer and API tests.
- `requirements.txt` — Python runtime dependencies.

## Run locally

From this directory, install the dependency and start Flask:

```sh
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. To choose another port, set `PORT` before running
the app.

In a Replit environment, Flask is installed from `requirements.txt` and the
preview runs `python app.py`.

## Run tests

```sh
python -m unittest discover -s tests -v
```

The analyzer is a heuristic educational aid, not a security scanner. Its result
is an estimate and cannot prove that a message is safe or malicious.
