"""
WDTT Panel — веб-интерфейс управления VK-звонков трафиком
"""

import os
import sys
import json
import hashlib
import logging
import secrets
import time
import subprocess
from functools import wraps

from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, Response, stream_with_context
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("wdtt.app")

# ── Конфиг ──────────────────────────────────────────────────────────────────

DATA_DIR    = os.environ.get("WDTT_DATA_DIR",    "/opt/wdtt-panel/data")
PANEL_HOST  = os.environ.get("WDTT_PANEL_HOST",  "0.0.0.0")
PANEL_PORT  = int(os.environ.get("WDTT_PANEL_PORT", "8080"))
SECRET_KEY  = os.environ.get("WDTT_SECRET_KEY",  secrets.token_hex(32))

os.makedirs(DATA_DIR, exist_ok=True)
CONFIG_FILE = os.path.join(DATA_DIR, "panel_config.json")


def _load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def _save_config(cfg: dict):
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CONFIG_FILE)


panel_config = _load_config()

# ── Flask ────────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 86400 * 7


def hash_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()


def check_password(pwd: str) -> bool:
    stored = panel_config.get("password_hash", "")
    return stored == hash_password(pwd)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            if request.is_json:
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return wrapper


# ── Менеджер (импортируем после Flask, чтобы не было циклов) ────────────────
from manager import manager, normalize_vk_hash  # noqa: E402


# ── Страницы ─────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET"])
def login_page():
    if session.get("logged_in"):
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    pwd = request.form.get("password", "")
    if check_password(pwd):
        session.permanent = True
        session["logged_in"] = True
        return redirect(url_for("index"))
    return render_template("login.html", error="Неверный пароль")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


# ── API: профили ─────────────────────────────────────────────────────────────

@app.route("/api/profiles", methods=["GET"])
@login_required
def api_list():
    return jsonify(manager.list_profiles())


@app.route("/api/profiles", methods=["POST"])
@login_required
def api_add():
    data = request.json or {}
    if not data.get("server"):
        return jsonify({"error": "Укажите адрес WDTT-сервера (IP:PORT)"}), 400
    if not data.get("hashes") and not data.get("hash"):
        return jsonify({"error": "Добавьте хотя бы одну VK-ссылку"}), 400
    if "hash" in data and "hashes" not in data:
        data["hashes"] = data["hash"]
    p = manager.add_profile(data)
    return jsonify(p.to_dict()), 201


@app.route("/api/profiles/<pid>", methods=["PUT"])
@login_required
def api_update(pid):
    data = request.json or {}
    p = manager.update_profile(pid, data)
    if not p:
        return jsonify({"error": "Профиль не найден"}), 404
    return jsonify(p.to_dict())


@app.route("/api/profiles/<pid>", methods=["DELETE"])
@login_required
def api_delete(pid):
    if manager.delete_profile(pid):
        return jsonify({"ok": True})
    return jsonify({"error": "Профиль не найден"}), 404


# ── API: управление ──────────────────────────────────────────────────────────

@app.route("/api/profiles/<pid>/start", methods=["POST"])
@login_required
def api_start(pid):
    ok = manager.start(pid)
    profiles = manager.list_profiles()
    p = next((x for x in profiles if x["id"] == pid), None)
    if ok:
        return jsonify({"ok": True, "profile": p})
    err = p["last_error"] if p else "Ошибка запуска"
    return jsonify({"ok": False, "error": err}), 400


@app.route("/api/profiles/<pid>/stop", methods=["POST"])
@login_required
def api_stop(pid):
    manager.stop(pid)
    return jsonify({"ok": True})


@app.route("/api/profiles/<pid>/restart", methods=["POST"])
@login_required
def api_restart(pid):
    manager.stop(pid)
    time.sleep(1)
    ok = manager.start(pid)
    profiles = manager.list_profiles()
    p = next((x for x in profiles if x["id"] == pid), None)
    return jsonify({"ok": ok, "profile": p})


# ── API: логи (SSE) ───────────────────────────────────────────────────────────

@app.route("/api/profiles/<pid>/logs")
@login_required
def api_logs(pid):
    def generate():
        sent = 0
        while True:
            lines = manager.get_logs(pid)
            if lines[sent:]:
                for line in lines[sent:]:
                    yield f"data: {json.dumps(line)}\n\n"
                sent = len(lines)
            time.sleep(0.5)

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── API: статус ───────────────────────────────────────────────────────────────

@app.route("/api/status")
@login_required
def api_status():
    profiles = manager.list_profiles()
    return jsonify({
        "profiles": profiles,
        "connected": sum(1 for p in profiles if p["status"] == "connected"),
        "total": len(profiles),
    })


# ── API: смена пароля ─────────────────────────────────────────────────────────

@app.route("/api/change-password", methods=["POST"])
@login_required
def api_change_password():
    data = request.json or {}
    old = data.get("old_password", "")
    new = data.get("new_password", "")
    if not check_password(old):
        return jsonify({"error": "Неверный текущий пароль"}), 400
    if len(new) < 6:
        return jsonify({"error": "Новый пароль должен быть минимум 6 символов"}), 400
    panel_config["password_hash"] = hash_password(new)
    _save_config(panel_config)
    return jsonify({"ok": True})


# ── API: инфо о системе ───────────────────────────────────────────────────────

@app.route("/api/sysinfo")
@login_required
def api_sysinfo():
    try:
        import psutil
        mem = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=0.2)
        info = {
            "cpu_percent": cpu,
            "mem_total_mb": round(mem.total / 1024 / 1024),
            "mem_used_mb":  round(mem.used  / 1024 / 1024),
            "mem_percent":  mem.percent,
        }
    except ImportError:
        info = {}

    # WireGuard status is profile-scoped. The old implementation checked one
    # shared device, which could report a false state and could never represent
    # multiple independent profiles.
    try:
        profiles = manager.list_profiles()
        info["wg_active"] = any(
            p.get("status") == "connected" for p in profiles
        )
        info["wg_profiles"] = [
            {
                "id": p.get("id"),
                "interface": p.get("wg_iface"),
                "status": p.get("status"),
            }
            for p in profiles
        ]
    except Exception:
        info["wg_active"] = False
        info["wg_profiles"] = []

    return jsonify(info)


# ── Точка входа ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Проверяем что пароль установлен
    if not panel_config.get("password_hash"):
        default_pwd = os.environ.get("WDTT_DEFAULT_PASSWORD", "admin")
        panel_config["password_hash"] = hash_password(default_pwd)
        _save_config(panel_config)
        print(f"\n[!] Пароль панели: {default_pwd}")
        print(f"[!] Панель запускается на {PANEL_HOST}:{PANEL_PORT}\n")

    app.run(host=PANEL_HOST, port=PANEL_PORT, debug=False, threaded=True)
