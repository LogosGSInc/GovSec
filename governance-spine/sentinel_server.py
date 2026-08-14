"""
sentinel_server.py  — Sprint 5 patch
Adds /session/start and /session/end endpoints.
StrategicMemory is forwarded to the Rust spine via HTTP;
Python holds no strategic state itself.
"""

from flask import Flask, request, jsonify
import requests
import logging
import os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sentinel_server")

SPINE_URL = os.environ.get("GOVERNANCE_SPINE_URL", "http://governance-spine:8080")

# ── Existing evaluate endpoint (preserved) ────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return {"ok": True}, 200


@app.route("/evaluate", methods=["POST"])
def evaluate():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        resp = requests.post(f"{SPINE_URL}/evaluate", json=payload, timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        log.error("evaluate proxy error: %s", e)
        return jsonify({"ok": False, "error": "spine_unavailable"}), 503


# ── Sprint 5: /session/start ──────────────────────────────────────────────────
@app.route("/session/start", methods=["POST"])
def session_start():
    """
    Called by Abigail when a new actor session begins.
    Forwards actor_id to the Rust spine, which returns Tier 2 advice:
      - starting_state: "Clean" | "Watching" | "Elevated" | "Locked"
      - threshold_modifier: float (e.g. 0.85 = tighten by 15%)
      - prior_escalations: int

    Public-safe response — no internal tier language returned to callers.
    """
    payload = request.get_json(force=True, silent=True) or {}
    actor_id = payload.get("actor_id", "anonymous")

    try:
        resp = requests.post(
            f"{SPINE_URL}/session/start",
            json={"actor_id": actor_id},
            timeout=5,
        )
        data = resp.json()
        log.info("session/start actor=%s state=%s", actor_id, data.get("starting_state"))
        return jsonify(data), resp.status_code

    except requests.exceptions.ConnectionError:
        # Spine not yet reachable — safe default: start Clean
        log.warning("spine unreachable on session/start, defaulting Clean")
        return jsonify({
            "ok": True,
            "starting_state": "Clean",
            "threshold_modifier": 1.0,
            "prior_escalations": 0,
            "source": "fallback",
        }), 200

    except Exception as e:
        log.error("session/start error: %s", e)
        return jsonify({"ok": False, "error": str(e)}), 503


# ── Sprint 5: /session/end ────────────────────────────────────────────────────
@app.route("/session/end", methods=["POST"])
def session_end():
    """
    Called by Abigail when a session closes.
    Forwards actor_id + behavior summary to Rust spine for Tier 2 fingerprinting.
    The spine writes the ActorProfile to disk (persistent volume).
    """
    payload = request.get_json(force=True, silent=True) or {}
    actor_id = payload.get("actor_id", "anonymous")
    behavior = {
        "turn_count": payload.get("turn_count", 0),
        "escalated": payload.get("escalated", False),
        "drs_peak": payload.get("drs_peak", 0),
        "boundary_probes": payload.get("boundary_probes", 0),
        "authority_claims": payload.get("authority_claims", 0),
        "extraction_attempts": payload.get("extraction_attempts", 0),
    }

    try:
        resp = requests.post(
            f"{SPINE_URL}/session/end",
            json={"actor_id": actor_id, "behavior": behavior},
            timeout=5,
        )
        log.info("session/end actor=%s escalated=%s", actor_id, behavior["escalated"])
        return jsonify(resp.json()), resp.status_code

    except requests.exceptions.ConnectionError:
        log.warning("spine unreachable on session/end, fingerprint not persisted")
        return jsonify({"ok": True, "persisted": False, "source": "fallback"}), 200

    except Exception as e:
        log.error("session/end error: %s", e)
        return jsonify({"ok": False, "error": str(e)}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9090)
