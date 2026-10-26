import os
import time
import hashlib
import base64
import urllib.parse
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import pymysql
from pymysql.cursors import DictCursor

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "super-secret-cyber-key-2026")

DB_HOST = os.getenv("DB_HOST", "database")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_USER", "cyberuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "cyberpass123")
DB_NAME = os.getenv("DB_NAME", "vulntrack_db")


def get_db_connection():
    """Create a MySQL connection with dictionary cursor."""
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=DictCursor,
        autocommit=True,
    )


def init_database(max_retries=15, delay=3):
    """Wait for MySQL and ensure database & tables exist."""
    print(f"[*] Connecting to database at {DB_HOST}:{DB_PORT} as {DB_USER}...")
    for attempt in range(1, max_retries + 1):
        try:
            conn = get_db_connection()
            with conn.cursor() as cur:
                # Create table
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS findings (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        title VARCHAR(255) NOT NULL,
                        category VARCHAR(50) NOT NULL,
                        target VARCHAR(255) NOT NULL,
                        severity ENUM('Critical', 'High', 'Medium', 'Low') NOT NULL,
                        description TEXT,
                        remediation TEXT,
                        status ENUM('Open', 'In Progress', 'Resolved') DEFAULT 'Open',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """
                )

                # Check if table is empty, seed initial security data if needed
                cur.execute("SELECT COUNT(*) AS total FROM findings;")
                count = cur.fetchone()["total"]
                if count == 0:
                    seed_data = [
                        (
                            "SQL Injection in /api/v1/user/auth",
                            "Vulnerability",
                            "auth.target-corp.id",
                            "Critical",
                            "Unsanitized parameter 'id' allows full authentication bypass and data extraction via UNION-based payload.",
                            "Use parameterized queries / Prepared Statements with ORM. Validate and cast input types.",
                            "Open",
                        ),
                        (
                            "Public S3 Bucket Exposure Containing Candidate PII",
                            "Cloud Security",
                            "storage.target-corp.id",
                            "High",
                            "Anonymous read permission enabled on bucket template-files-prod. Sensitive documents accessible publicly.",
                            "Enable S3 Block Public Access and review IAM bucket policies.",
                            "In Progress",
                        ),
                        (
                            "Malicious C2 IP Traffic Detected (Cobalt Strike Beacon)",
                            "IOC",
                            "185.220.101.5",
                            "Critical",
                            "Host in DMZ communicating periodically every 60s via HTTPS POST beaconing to known malicious C2 IP.",
                            "Isolate affected endpoint, block IP on perimeter firewall, and initiate memory forensics.",
                            "Open",
                        ),
                        (
                            "Missing HTTP Security Headers (HSTS & CSP)",
                            "Audit",
                            "portal.target-corp.id",
                            "Low",
                            "Web application is missing Strict-Transport-Security, Content-Security-Policy, and X-Frame-Options headers.",
                            "Configure Nginx to inject secure headers on all responses.",
                            "Resolved",
                        ),
                    ]
                    cur.executemany(
                        """
                        INSERT INTO findings (title, category, target, severity, description, remediation, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s);
                        """,
                        seed_data,
                    )
                    print(f"[+] Database initialized and seeded with {len(seed_data)} findings.")
            conn.close()
            print("[+] Database connection established successfully.")
            return True
        except Exception as e:
            print(f"[-] Attempt {attempt}/{max_retries} failed: {e}. Retrying in {delay}s...")
            time.sleep(delay)

    print("[!] Warning: Could not connect to database after maximum retries.")
    return False


@app.route("/")
def index():
    query_search = request.args.get("q", "").strip()
    filter_severity = request.args.get("severity", "").strip()
    filter_status = request.args.get("status", "").strip()

    findings = []
    stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "open": 0, "resolved": 0}

    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            # Get stats
            cur.execute("SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity;")
            for row in cur.fetchall():
                sev = row["severity"].lower()
                if sev in stats:
                    stats[sev] = row["count"]

            cur.execute("SELECT status, COUNT(*) AS count FROM findings GROUP BY status;")
            for row in cur.fetchall():
                st = row["status"].lower().replace(" ", "_")
                if st in stats:
                    stats[st] = row["count"]

            cur.execute("SELECT COUNT(*) AS total FROM findings;")
            stats["total"] = cur.fetchone()["total"]

            # Filtered findings query
            sql = "SELECT * FROM findings WHERE 1=1"
            params = []

            if query_search:
                sql += " AND (title LIKE %s OR target LIKE %s OR description LIKE %s)"
                term = f"%{query_search}%"
                params.extend([term, term, term])

            if filter_severity:
                sql += " AND severity = %s"
                params.append(filter_severity)

            if filter_status:
                sql += " AND status = %s"
                params.append(filter_status)

            sql += " ORDER BY id DESC"
            cur.execute(sql, params)
            findings = cur.fetchall()

        conn.close()
    except Exception as e:
        flash(f"Database Error: {e}", "danger")

    return render_template(
        "index.html",
        findings=findings,
        stats=stats,
        q=query_search,
        selected_severity=filter_severity,
        selected_status=filter_status,
        db_host=DB_HOST,
        db_name=DB_NAME,
    )


@app.route("/findings/create", methods=["POST"])
def create_finding():
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "Vulnerability").strip()
    target = request.form.get("target", "").strip()
    severity = request.form.get("severity", "Medium").strip()
    description = request.form.get("description", "").strip()
    remediation = request.form.get("remediation", "").strip()

    if not title or not target:
        flash("Title dan Target wajib diisi!", "warning")
        return redirect(url_for("index"))

    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO findings (title, category, target, severity, description, remediation, status)
                VALUES (%s, %s, %s, %s, %s, %s, 'Open')
                """,
                (title, category, target, severity, description, remediation),
            )
        conn.close()
        flash("Temuan keamanan berhasil ditambahkan!", "success")
    except Exception as e:
        flash(f"Gagal menyimpan data: {e}", "danger")

    return redirect(url_for("index"))


@app.route("/findings/<int:finding_id>/status", methods=["POST"])
def update_status(finding_id):
    new_status = request.form.get("status", "Open")
    if new_status in ["Open", "In Progress", "Resolved"]:
        try:
            conn = get_db_connection()
            with conn.cursor() as cur:
                cur.execute("UPDATE findings SET status = %s WHERE id = %s", (new_status, finding_id))
            conn.close()
            flash(f"Status temuan #{finding_id} diubah menjadi {new_status}.", "info")
        except Exception as e:
            flash(f"Gagal update status: {e}", "danger")
    return redirect(url_for("index"))


@app.route("/findings/<int:finding_id>/delete", methods=["POST"])
def delete_finding(finding_id):
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM findings WHERE id = %s", (finding_id,))
        conn.close()
        flash(f"Temuan #{finding_id} berhasil dihapus.", "success")
    except Exception as e:
        flash(f"Gagal menghapus data: {e}", "danger")
    return redirect(url_for("index"))


@app.route("/api/tools/hash", methods=["POST"])
def tool_hash():
    data = request.json or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "Empty text"}), 400

    encoded = text.encode("utf-8")
    return jsonify(
        {
            "input": text,
            "md5": hashlib.md5(encoded).hexdigest(),
            "sha1": hashlib.sha1(encoded).hexdigest(),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    )


@app.route("/api/tools/codec", methods=["POST"])
def tool_codec():
    data = request.json or {}
    text = data.get("text", "")
    action = data.get("action", "b64_encode")

    result = ""
    try:
        if action == "b64_encode":
            result = base64.b64encode(text.encode("utf-8")).decode("utf-8")
        elif action == "b64_decode":
            result = base64.b64decode(text.encode("utf-8")).decode("utf-8", errors="replace")
        elif action == "url_encode":
            result = urllib.parse.quote(text)
        elif action == "url_decode":
            result = urllib.parse.unquote(text)
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/health")
def health():
    db_status = "ok"
    try:
        conn = get_db_connection()
        conn.ping()
        conn.close()
    except Exception as e:
        db_status = f"unhealthy: {e}"

    return jsonify(
        {
            "status": "healthy" if db_status == "ok" else "degraded",
            "service": "CyberVulnVault",
            "database": db_status,
        }
    )


# Automatically initialize database when the script is loaded or run
with app.app_context():
    init_database()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
