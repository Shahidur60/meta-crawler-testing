from flask import Flask, request, jsonify
from datetime import datetime, timezone
import json

app = Flask(__name__)
LOG_FILE = "events.jsonl"
MAX_BODY = 200_000  # bytes

def now():
    return datetime.now(timezone.utc).isoformat()

def best_ip(req):
    xff = req.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return req.remote_addr or ""

def log_event(event):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

@app.route("/", methods=["GET"])
def home():
    return "OK. POST to /post with JSON {'msg':'Hello'}", 200

@app.route("/post", methods=["POST", "GET"])
def post_endpoint():
    raw = request.get_data(cache=False) or b""
    raw_trunc = raw[:MAX_BODY]
    body_text = raw_trunc.decode("utf-8", errors="replace")

    event = {
        "ts_utc": now(),
        "method": request.method,
        "path": request.path,
        "ip": best_ip(request),
        "user_agent": request.headers.get("User-Agent", ""),
        "content_type": request.headers.get("Content-Type", ""),
        "headers_subset": {
            "X-Forwarded-For": request.headers.get("X-Forwarded-For", ""),
            "X-Forwarded-Proto": request.headers.get("X-Forwarded-Proto", ""),
            "X-Forwarded-Host": request.headers.get("X-Forwarded-Host", ""),
        },
        "query": request.args.to_dict(flat=False),
        "body_len": len(raw),
        "body_preview": body_text,
    }

    # try JSON parse
    try:
        event["json"] = request.get_json(silent=True)
    except Exception:
        event["json"] = None

    log_event(event)

    # ALSO print to server logs (so you can see it instantly in Render logs)
    print("=== INCOMING REQUEST ===")
    print(json.dumps(event, indent=2, ensure_ascii=False))

    return jsonify({"ok": True})
