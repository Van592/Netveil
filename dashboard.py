from flask import Flask, jsonify, render_template, request, redirect, session, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import json, os, subprocess

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET"
login = LoginManager(app)
login.login_view = "login"

# Hardcoded single admin user (for now)
USERS = {"admin": {"password": "secretpassword"}}

class User(UserMixin):
    def __init__(self, username): self.id = username

@login.user_loader
def load_user(uid):
    return User(uid) if uid in USERS else None

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = USERS.get(request.form["username"])
        if user and user["password"] == request.form["password"]:
            login_user(User(request.form["username"]))
            return redirect(url_for("home"))
        return render_template("login.html", error="Invalid login")
    return render_template("login.html")

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    return render_template("index.html")

@app.route("/fingerprints", methods=["GET", "POST"])
@login_required
def fingerprints():
    path = "/var/log/netveil_fingerprint.jsonl"
    if not os.path.exists(path): return jsonify([])
    with open(path) as f:
        data = [json.loads(line) for line in f]
    return jsonify(data)

@app.route("/fingerprint/<ip>", methods=["GET", "POST"])
@login_required
def fingerprint_detail(ip):
    data = []
    with open("/var/log/netveil_fingerprint.jsonl") as f:
        for line in f:
            obj = json.loads(line)
            if obj.get("ip") == ip:
                data.append(obj)
    return jsonify(data)

@app.route("/run", methods=["GET", "POST"])
@login_required
def run():
    output = None
    if request.method == "POST":
        cmd_map = {
            "scan": "/usr/share/netveil/scripts/scan_lan.sh",
            "stealth": "/usr/share/netveil/scripts/arp_stealth.sh",
            "monitor": "/usr/share/netveil/scripts/arp_monitor.sh",
            "devices": "/usr/share/netveil/scripts/device_scan.sh",
            "triangulate": "/usr/share/netveil/scripts/triangulate.sh",
        }

        selected = request.form.get("predef_command")
        script = cmd_map.get(selected)

        if script:
            try:
                result = subprocess.check_output([script], stderr=subprocess.STDOUT)
                output = result.decode("utf-8")
            except subprocess.CalledProcessError as e:
                output = f"Error:\n{e.output.decode('utf-8')}"
        else:
            output = "Invalid command selected."

    return render_template("run.html", output=output)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
