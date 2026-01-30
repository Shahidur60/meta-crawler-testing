from flask import Flask, request, jsonify, Response
from datetime import datetime, timezone
import json
import os

app = Flask(__name__)

LOG_FILE = os.environ.get("LOG_FILE", "events.jsonl")
MAX_BODY_BYTES = 200_000  # cap body capture to avoid abuse


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def best_effort_ip(req: request) -> str:
    # Render/Proxies typically set X-Forwarded-For with a chain
    xff = req.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return req.remote_addr or ""


def forwarded_chain(req: request):
    xff = req.headers.get("X-Forwarded-For", "")
    return [x.strip() for x in xff.split(",") if x.strip()] if xff else []


def safe_body(req: request) -> dict:
    raw = req.get_data(cache=False) or b""
    raw_trunc = raw[:MAX_BODY_BYTES]
    text_preview = raw_trunc.decode("utf-8", errors="replace")

    out = {
        "content_type": req.headers.get("Content-Type", ""),
        "content_length_bytes": len(raw),
        "truncated_to_bytes": len(raw_trunc),
        "body_preview_utf8": text_preview,
        "json": None,
    }

    if "application/json" in (out["content_type"] or "").lower():
        try:
            out["json"] = json.loads(text_preview)
        except Exception:
            out["json"] = None

    return out


def log_event(event: dict):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def build_event(req: request, event_type: str) -> dict:
    return {
        "ts_utc": now_utc(),
        "type": event_type,
        "request": {
            "method": req.method,
            "path": req.path,
            "full_path": req.full_path,
            "url": req.url,
        },
        "client": {
            "ip_best_effort": best_effort_ip(req),
            "x_forwarded_for_chain": forwarded_chain(req),
            "remote_addr": req.remote_addr or "",
            "user_agent": req.headers.get("User-Agent", ""),
            "accept_language": req.headers.get("Accept-Language", ""),
            "referer": req.headers.get("Referer", ""),
        },
        "headers_subset": {
            "X-Forwarded-For": req.headers.get("X-Forwarded-For", ""),
            "X-Forwarded-Proto": req.headers.get("X-Forwarded-Proto", ""),
            "X-Forwarded-Host": req.headers.get("X-Forwarded-Host", ""),
            "Host": req.headers.get("Host", ""),
        },
        "query_args": req.args.to_dict(flat=False),
    }


@app.before_request
def log_every_request():
    """
    Log the request *as it arrives* (even if it later results in 405/404).
    For POST/PUT/PATCH, also log body preview.
    """
    event = build_event(request, "incoming_request")

    if request.method in ("POST", "PUT", "PATCH"):
        event["body"] = safe_body(request)
    else:
        event["body"] = {
            "content_type": request.headers.get("Content-Type", ""),
            "content_length_bytes": 0,
            "truncated_to_bytes": 0,
            "body_preview_utf8": "",
            "json": None,
        }

    log_event(event)

    # Print to server logs so you see it instantly in Render logs
    print("=== INCOMING ===")
    print(json.dumps(event, indent=2, ensure_ascii=False))


@app.errorhandler(405)
def method_not_allowed(e):
    # Log explicitly that a method was not allowed (helps interpretation)
    event = build_event(request, "method_not_allowed_405")
    log_event(event)
    print("=== 405 METHOD NOT ALLOWED ===")
    print(json.dumps(event, indent=2, ensure_ascii=False))
    return jsonify({"ok": False, "error": "Method Not Allowed"}), 405


@app.route("/", methods=["GET"])
def home():
    return (
        "OK.\n"
        "This service is for testing whether a client can send POST.\n\n"
        "POST-only endpoint: /post\n"
        "Example: POST JSON {\"msg\":\"HELLO\"} to /post\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.route("/robots.txt", methods=["GET"])
def robots():
    # Reduce crawler noise a bit
    return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")


@app.route("/post", methods=["POST"])
def post_only():
    body_info = safe_body(request)

    # Build a dedicated post-received event too (separate from before_request log)
    event = build_event(request, "post_received")
    event["body"] = body_info
    log_event(event)

    print("=== POST RECEIVED ===")
    print(json.dumps(event, indent=2, ensure_ascii=False))

    # Return a response that makes it obvious we received a POST
    return jsonify({"ok": True, "received": body_info.get("json") or body_info.get("body_preview_utf8", "")})


@app.route("/logs/last", methods=["GET"])
def logs_last():
    """
    Convenience endpoint: returns last N lines from events.jsonl.
    Usage: /logs/last?n=20
    """
    n = request.args.get("n", "20")
    try:
        n = max(1, min(int(n), 200))
    except Exception:
        n = 20

    if not os.path.exists(LOG_FILE):
        return jsonify({"ok": True, "events": [], "note": "No log file yet."})

    # Read last N lines safely
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    last_lines = lines[-n:]
    events = []
    for line in last_lines:
        try:
            events.append(json.loads(line))
        except Exception:
            pass

    return jsonify({"ok": True, "count": len(events), "events": events})


if __name__ == "__main__":
    # For local dev only. On Render, gunicorn will run the app.
    app.run(host="0.0.0.0", port=8080, debug=False)
