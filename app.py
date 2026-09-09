from flask import Flask, request, jsonify, render_template, send_file, session, redirect
from werkzeug.utils import secure_filename

import re
import os
import time

from analyzer.pcap_analyzer import analyze_pcap

from scanner.nmap_scanner import (
    scan_target,
    scan_multiple_targets
)

from database.database import (
    create_tables,
    save_scan,
    save_multiple_scan,
    get_scan_history,
    create_user,
    verify_user,
    supabase
)

from analyzer.recommendations import generate_recommendations
from analyzer.cve_lookup import lookup_cves

from reports.report_generator import generate_pdf
from email_sender import send_report_email


# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "port-scanner-secret-key-change-this"
)

UPLOAD_FOLDER = "uploads/pcap"

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

create_tables()


# ============================================================
# TARGET VALIDATION
# ============================================================

def is_valid_target(target):

    if not isinstance(target, str):
        return False

    if len(target) > 253:
        return False

    pattern = r"^[a-zA-Z0-9.-]+$"

    if not re.match(pattern, target):
        return False

    if target.startswith((".", "-")):
        return False

    if target.endswith((".", "-")):
        return False

    return True


# ============================================================
# GET SCAN DATE FROM SUPABASE
# ============================================================

def get_scan_date(scan_id):

    try:

        response = (
            supabase
            .table("scans")
            .select("scan_date")
            .eq("id", scan_id)
            .limit(1)
            .execute()
        )

        if response.data:
            return response.data[0].get(
                "scan_date",
                ""
            )

        return ""

    except Exception as e:

        print(
            "Get scan date error:",
            repr(e)
        )

        return ""


# ============================================================
# CVE INFORMATION
# ============================================================

def add_cve_information(results):

    updated_results = []

    for result in results:

        service = result.get(
            "service",
            ""
        )

        version = result.get(
            "version",
            ""
        )

        cves = []

        if service:

            try:

                cves = lookup_cves(
                    service,
                    version
                )

            except Exception as e:

                print(
                    "CVE lookup error:",
                    repr(e)
                )

                cves = []

        result_copy = dict(result)

        result_copy["cves"] = cves

        updated_results.append(
            result_copy
        )

    return updated_results


# ============================================================
# PAGES
# ============================================================

@app.route("/login-page")
def login_page():

    return render_template(
        "login.html"
    )


@app.route("/register-page")
def register_page():

    return render_template(
        "register.html"
    )


@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=["POST"]
)
def register():

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "error": "Invalid or missing JSON data"
        }), 400

    username = data.get(
        "username",
        ""
    ).strip()

    password = data.get(
        "password",
        ""
    )

    if not username:

        return jsonify({
            "error": "Username is required"
        }), 400

    if not password:

        return jsonify({
            "error": "Password is required"
        }), 400

    if len(username) < 3:

        return jsonify({
            "error":
                "Username must contain at least 3 characters"
        }), 400

    if len(password) < 6:

        return jsonify({
            "error":
                "Password must contain at least 6 characters"
        }), 400

    try:

        created = create_user(
            username,
            password
        )

        if not created:

            return jsonify({
                "error":
                    "Username already exists"
            }), 409

        return jsonify({
            "status": "success",
            "message":
                "User registered successfully"
        }), 201

    except Exception as e:

        print(
            "Registration error:",
            repr(e)
        )

        return jsonify({
            "error":
                f"Registration failed: {str(e)}"
        }), 500


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["POST"]
)
def login():

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "error":
                "Invalid or missing JSON data"
        }), 400

    username = data.get(
        "username",
        ""
    ).strip()

    password = data.get(
        "password",
        ""
    )

    if not username or not password:

        return jsonify({
            "error":
                "Username and password are required"
        }), 400

    try:

        user = verify_user(
            username,
            password
        )

        if not user:

            return jsonify({
                "error":
                    "Invalid username or password"
            }), 401

        session["user_id"] = user["id"]

        session["username"] = user["username"]

        return jsonify({
            "status": "success",
            "message":
                "Login successful",
            "username":
                user["username"]
        })

    except Exception as e:

        print(
            "Login error:",
            repr(e)
        )

        return jsonify({
            "error":
                str(e)
        }), 500


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/logout",
    methods=["POST"]
)
def logout():

    session.clear()

    return jsonify({
        "status": "success",
        "message":
            "Logged out successfully"
    })


# ============================================================
# CURRENT USER
# ============================================================

@app.route(
    "/me",
    methods=["GET"]
)
def current_user():

    if "user_id" not in session:

        return jsonify({
            "authenticated": False
        })

    return jsonify({
        "authenticated": True,
        "user_id":
            session["user_id"],
        "username":
            session["username"]
    })


# ============================================================
# SCAN
# ============================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    if "user_id" not in session:

        return jsonify({
            "error":
                "Please login before scanning"
        }), 401

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "error":
                "Invalid or missing JSON data"
        }), 400

    target = data.get(
        "target"
    )

    scan_type = data.get(
        "scan_type",
        "tcp"
    )

    scan_type = str(
        scan_type
    ).lower()

    if scan_type not in [
        "tcp",
        "udp"
    ]:

        return jsonify({
            "error":
                "Scan type must be TCP or UDP"
        }), 400

    if not target:

        return jsonify({
            "error":
                "Target is required"
        }), 400


    # ========================================================
    # MULTIPLE TARGET SCAN
    # ========================================================

    if isinstance(target, list):

        targets = []

        for item in target:

            if not isinstance(item, str):

                return jsonify({
                    "error":
                        "Each target must be a string"
                }), 400

            item = item.strip()

            if not item:
                continue

            if not is_valid_target(item):

                return jsonify({
                    "error":
                        f"Invalid target: {item}"
                }), 400

            targets.append(item)

        if not targets:

            return jsonify({
                "error":
                    "At least one valid target is required"
            }), 400

        try:

            start_time = time.perf_counter()

            all_results = scan_multiple_targets(
                targets,
                scan_type
            )

            # Convert grouped results into flat results
            flat_results = []

            for target_result in all_results:

                target_name = target_result.get(
                    "target"
                )

                target_ports = target_result.get(
                    "results",
                    []
                )

                for result in target_ports:

                    result_copy = dict(result)

                    result_copy["target"] = target_name

                    flat_results.append(
                        result_copy
                    )

            flat_results = add_cve_information(
                flat_results
            )

            recommendations = generate_recommendations(
                flat_results
            )

            scan_id = save_multiple_scan(
                targets,
                flat_results
            )

            scan_duration = round(
                time.perf_counter()
                - start_time,
                2
            )

            scan_date = get_scan_date(
                scan_id
            )

            pdf_path = generate_pdf(
                scan_id,
                ", ".join(targets),
                scan_date,
                flat_results,
                recommendations,
                scan_duration
            )

            return jsonify({

                "status": "success",

                "targets":
                    targets,

                "total_targets":
                    len(targets),

                "scan_id":
                    scan_id,

                "scan_type":
                    scan_type,

                "total_ports":
                    len(flat_results),

                "scan_duration":
                    scan_duration,

                "results":
                    flat_results,

                "recommendations":
                    recommendations,

                "report":
                    f"/report/{scan_id}"

            })

        except Exception as e:

            print(
                "Multiple scan error:",
                repr(e)
            )

            return jsonify({
                "error":
                    str(e)
            }), 500


    # ========================================================
    # SINGLE TARGET SCAN
    # ========================================================

    if not isinstance(target, str):

        return jsonify({
            "error":
                "Target must be a string or list"
        }), 400

    target = target.strip()

    if not target:

        return jsonify({
            "error":
                "Target is required"
        }), 400

    if not is_valid_target(target):

        return jsonify({
            "error":
                "Invalid target. Enter a valid IP address or domain."
        }), 400

    try:

        start_time = time.perf_counter()

        results = scan_target(
            target,
            scan_type
        )

        results = add_cve_information(
            results
        )

        scan_id = save_scan(
            target,
            results
        )

        recommendations = generate_recommendations(
            results
        )

        scan_duration = round(
            time.perf_counter()
            - start_time,
            2
        )

        scan_date = get_scan_date(
            scan_id
        )

        pdf_path = generate_pdf(
            scan_id,
            target,
            scan_date,
            results,
            recommendations,
            scan_duration
        )

        return jsonify({

            "status": "success",

            "target":
                target,

            "scan_id":
                scan_id,

            "scan_type":
                scan_type,

            "total_ports":
                len(results),

            "scan_duration":
                scan_duration,

            "results":
                results,

            "recommendations":
                recommendations,

            "report":
                f"/report/{scan_id}"

        })

    except Exception as e:

        print(
            "Scan error:",
            repr(e)
        )

        return jsonify({
            "error":
                str(e)
        }), 500


# ============================================================
# PCAP ANALYSIS
# ============================================================

@app.route(
    "/pcap/analyze",
    methods=["POST"]
)
def pcap_analyze():

    if "user_id" not in session:

        return jsonify({
            "error":
                "Please login before analyzing PCAP files"
        }), 401

    if "file" not in request.files:

        return jsonify({
            "error":
                "PCAP file is required"
        }), 400

    file = request.files["file"]

    if file.filename == "":

        return jsonify({
            "error":
                "No file selected"
        }), 400

    filename = secure_filename(
        file.filename
    )

    allowed_extensions = (
        ".pcap",
        ".pcapng",
        ".cap"
    )

    if not filename.lower().endswith(
        allowed_extensions
    ):

        return jsonify({
            "error":
                "Only PCAP, PCAPNG or CAP files are allowed"
        }), 400

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    try:

        file.save(
            file_path
        )

        analysis = analyze_pcap(
            file_path
        )

        return jsonify({
            "status": "success",
            "filename":
                filename,
            "analysis":
                analysis
        })

    except Exception as e:

        print(
            "PCAP error:",
            repr(e)
        )

        return jsonify({
            "error":
                str(e)
        }), 500

    finally:

        if os.path.exists(
            file_path
        ):

            os.remove(
                file_path
            )


# ============================================================
# HISTORY PAGE
# ============================================================

@app.route(
    "/history",
    methods=["GET"]
)
def history():

    if "user_id" not in session:
        return redirect("/login-page")

    try:

        scans = get_scan_history()

        return render_template(
            "history.html",
            history=scans
        )

    except Exception as e:

        print(
            "History error:",
            repr(e)
        )

        return render_template(
            "history.html",
            history=[],
            error=str(e)
        )


# ============================================================
# HISTORY API
# ============================================================

@app.route(
    "/api/history",
    methods=["GET"]
)
def api_history():

    if "user_id" not in session:

        return jsonify({
            "error":
                "Please login before viewing scan history"
        }), 401

    try:

        scans = get_scan_history()

        return jsonify({
            "status": "success",
            "history": scans
        })

    except Exception as e:

        print(
            "History API error:",
            repr(e)
        )

        return jsonify({
            "error":
                str(e)
        }), 500

# ============================================================
# EMAIL REPORT
# ============================================================

@app.route(
    "/email-report",
    methods=["POST"]
)
def email_report():

    if "user_id" not in session:

        return jsonify({
            "error":
                "Please login before sending reports"
        }), 401

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "error":
                "Invalid or missing JSON data"
        }), 400

    scan_id = data.get(
        "scan_id"
    )

    receiver_email = data.get(
        "email",
        ""
    ).strip()

    if not scan_id:

        return jsonify({
            "error":
                "Scan ID is required"
        }), 400

    if not receiver_email:

        return jsonify({
            "error":
                "Receiver email is required"
        }), 400

    if not re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        receiver_email
    ):

        return jsonify({
            "error":
                "Invalid email address"
        }), 400

    pdf_path = (
        f"reports/scan_report_{scan_id}.pdf"
    )

    if not os.path.exists(
        pdf_path
    ):

        return jsonify({
            "error":
                "PDF report not found"
        }), 404

    try:

        send_report_email(
            receiver_email,
            pdf_path
        )

        return jsonify({
            "status": "success",
            "message":
                "PDF report sent successfully"
        })

    except Exception as e:

        print(
            "Email error:",
            repr(e)
        )

        return jsonify({
            "error":
                str(e)
        }), 500


# ============================================================
# PDF REPORT
# ============================================================

@app.route(
    "/report/<int:scan_id>",
    methods=["GET"]
)
def report(scan_id):

    if "user_id" not in session:

        return jsonify({
            "error":
                "Please login before downloading reports"
        }), 401

    try:

        pdf_path = (
            f"reports/scan_report_{scan_id}.pdf"
        )

        if not os.path.exists(
            pdf_path
        ):

            return jsonify({
                "error":
                    "Report not found"
            }), 404

        return send_file(

            pdf_path,

            as_attachment=True,

            download_name=(
                f"scan_report_{scan_id}.pdf"
            )
        )

    except Exception as e:

        print(
            "Report error:",
            repr(e)
        )

        return jsonify({
            "error":
                str(e)
        }), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    port = int(
        os.getenv(
            "PORT",
            "5000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )