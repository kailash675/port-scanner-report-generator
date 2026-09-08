from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    send_file,
    session,
    redirect
)

from werkzeug.utils import secure_filename

from analyzer.pcap_analyzer import analyze_pcap

import re
import os
import time

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
# FLASK APP
# ============================================================

app = Flask(__name__)


UPLOAD_FOLDER = "uploads/pcap"

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ============================================================
# SESSION SECURITY
# ============================================================

app.secret_key = "port-scanner-secret-key-change-this"


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

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

        print("Get scan date error:", e)

        return ""


# ============================================================
# UPDATE SCAN METADATA
# ============================================================

def update_scan_metadata(
    scan_id,
    scan_type,
    duration
):

    try:

        (
            supabase
            .table("scans")
            .update({
                "scan_type": scan_type,
                "duration": duration
            })
            .eq("id", scan_id)
            .execute()
        )

    except Exception as e:

        print(
            "Update scan metadata error:",
            e
        )


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

            cves = lookup_cves(
                service,
                version
            )

        result_copy = dict(result)

        result_copy["cves"] = cves

        updated_results.append(
            result_copy
        )

    return updated_results


# ============================================================
# LOGIN PAGE
# ============================================================

@app.route("/login-page")
def login_page():

    return render_template(
        "login.html"
    )


# ============================================================
# REGISTER PAGE
# ============================================================

@app.route("/register-page")
def register_page():

    return render_template(
        "register.html"
    )


# ============================================================
# HOME
# ============================================================

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
            "error": "Username must contain at least 3 characters"
        }), 400

    if len(password) < 6:

        return jsonify({
            "error": "Password must contain at least 6 characters"
        }), 400

    try:

        created = create_user(
            username,
            password
        )

        if not created:

            return jsonify({
                "error": "Username already exists"
            }), 409

        return jsonify({

            "status": "success",

            "message": "User registered successfully"

        }), 201

    except Exception as e:

        return jsonify({
            "error": str(e)
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

    if not username or not password:

        return jsonify({
            "error": "Username and password are required"
        }), 400

    try:

        user = verify_user(
            username,
            password
        )

        if not user:

            return jsonify({
                "error": "Invalid username or password"
            }), 401

        session["user_id"] = user["id"]

        session["username"] = user["username"]

        return jsonify({

            "status": "success",

            "message": "Login successful",

            "username": user["username"]

        })

    except Exception as e:

        return jsonify({
            "error": str(e)
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

        "message": "Logged out successfully"

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

        "user_id": session["user_id"],

        "username": session["username"]

    })


# ============================================================
# SCAN
# ============================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    # --------------------------------------------------------
    # LOGIN REQUIRED
    # --------------------------------------------------------

    if "user_id" not in session:

        return jsonify({
            "error": "Please login before scanning"
        }), 401

    # --------------------------------------------------------
    # READ JSON
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "error": "Invalid or missing JSON data"
        }), 400

    target = data.get(
        "target"
    )

    # --------------------------------------------------------
    # SCAN TYPE
    # --------------------------------------------------------

    scan_type = data.get(
        "scan_type",
        "tcp"
    ).lower()

    if scan_type not in [
        "tcp",
        "udp"
    ]:

        return jsonify({
            "error": "Invalid scan type. Choose TCP or UDP."
        }), 400

    # --------------------------------------------------------
    # TARGET REQUIRED
    # --------------------------------------------------------

    if not target:

        return jsonify({
            "error": "Target is required"
        }), 400

    # ========================================================
    # MULTIPLE TARGET SCAN
    # ========================================================

    if isinstance(target, list):

        targets = []

        for item in target:

            if not isinstance(item, str):

                return jsonify({
                    "error": "Each target must be a string"
                }), 400

            item = item.strip()

            if not item:
                continue

            if not is_valid_target(item):

                return jsonify({
                    "error": f"Invalid target: {item}"
                }), 400

            targets.append(item)

        if not targets:

            return jsonify({
                "error": "At least one valid target is required"
            }), 400

        try:

            # ------------------------------------------------
            # START TIMER
            # ------------------------------------------------

            start_time = time.perf_counter()

            # ------------------------------------------------
            # NMAP SCAN
            # ------------------------------------------------

            raw_results = scan_multiple_targets(
                targets,
                scan_type
            )

            # ------------------------------------------------
            # FLATTEN RESULTS
            # ------------------------------------------------

            all_results = []

            for target_data in raw_results:

                target_name = target_data.get(
                    "target"
                )

                target_results = target_data.get(
                    "results",
                    []
                )

                for result in target_results:

                    result_copy = dict(result)

                    result_copy["target"] = target_name

                    all_results.append(
                        result_copy
                    )

            # ------------------------------------------------
            # CVE
            # ------------------------------------------------

            all_results = add_cve_information(
                all_results
            )

            # ------------------------------------------------
            # RECOMMENDATIONS
            # ------------------------------------------------

            recommendations = []

            for target_name in targets:

                target_results = [

                    result

                    for result in all_results

                    if result.get(
                        "target"
                    ) == target_name

                ]

                target_recommendations = (
                    generate_recommendations(
                        target_results
                    )
                )

                for recommendation in target_recommendations:

                    if recommendation not in recommendations:

                        recommendations.append(
                            recommendation
                        )

            # ------------------------------------------------
            # SAVE SCAN TO SUPABASE
            # ------------------------------------------------

            scan_id = save_multiple_scan(
                targets,
                all_results
            )

            # ------------------------------------------------
            # CALCULATE DURATION
            # ------------------------------------------------

            scan_duration = round(
                time.perf_counter()
                - start_time,
                2
            )

            # ------------------------------------------------
            # SAVE TCP / UDP + DURATION ONLINE
            # ------------------------------------------------

            update_scan_metadata(
                scan_id,
                scan_type.upper(),
                scan_duration
            )

            # ------------------------------------------------
            # GET DATE FROM SUPABASE
            # ------------------------------------------------

            scan_date = get_scan_date(
                scan_id
            )

            # ------------------------------------------------
            # PDF
            # ------------------------------------------------

            pdf_path = generate_pdf(
                scan_id,
                ", ".join(targets),
                scan_date,
                all_results,
                recommendations,
                scan_duration
            )

            # ------------------------------------------------
            # RESPONSE
            # ------------------------------------------------

            return jsonify({

                "status": "success",

                "targets": targets,

                "total_targets": len(targets),

                "scan_type": scan_type.upper(),

                "scan_id": scan_id,

                "total_ports": len(all_results),

                "scan_duration": scan_duration,

                "results": all_results,

                "recommendations": recommendations,

                "report": f"/report/{scan_id}"

            })

        except Exception as e:

            print(
                "Multiple scan error:",
                e
            )

            return jsonify({
                "error": str(e)
            }), 500

    # ========================================================
    # SINGLE TARGET SCAN
    # ========================================================

    if not isinstance(target, str):

        return jsonify({
            "error": "Target must be a string or list"
        }), 400

    target = target.strip()

    if not target:

        return jsonify({
            "error": "Target is required"
        }), 400

    if not is_valid_target(target):

        return jsonify({
            "error": "Invalid target. Enter a valid IP address or domain."
        }), 400

    try:

        # ----------------------------------------------------
        # START TIMER
        # ----------------------------------------------------

        start_time = time.perf_counter()

        # ----------------------------------------------------
        # NMAP SCAN
        # ----------------------------------------------------

        results = scan_target(
            target,
            scan_type
        )

        # ----------------------------------------------------
        # CVE
        # ----------------------------------------------------

        results = add_cve_information(
            results
        )

        # ----------------------------------------------------
        # RECOMMENDATIONS
        # ----------------------------------------------------

        recommendations = generate_recommendations(
            results
        )

        # ----------------------------------------------------
        # CALCULATE DURATION
        # ----------------------------------------------------

        scan_duration = round(
            time.perf_counter()
            - start_time,
            2
        )

        # ----------------------------------------------------
        # SAVE TO SUPABASE
        # ----------------------------------------------------

        scan_id = save_scan(
            target,
            results
        )

        # ----------------------------------------------------
        # SAVE TCP / UDP + DURATION
        # ----------------------------------------------------

        update_scan_metadata(
            scan_id,
            scan_type.upper(),
            scan_duration
        )

        # ----------------------------------------------------
        # GET DATE FROM SUPABASE
        # ----------------------------------------------------

        scan_date = get_scan_date(
            scan_id
        )

        # ----------------------------------------------------
        # PDF
        # ----------------------------------------------------

        pdf_path = generate_pdf(
            scan_id,
            target,
            scan_date,
            results,
            recommendations,
            scan_duration
        )

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return jsonify({

            "status": "success",

            "target": target,

            "scan_type": scan_type.upper(),

            "scan_id": scan_id,

            "total_ports": len(results),

            "scan_duration": scan_duration,

            "results": results,

            "recommendations": recommendations,

            "report": f"/report/{scan_id}"

        })

    except Exception as e:

        print(
            "Single scan error:",
            e
        )

        return jsonify({
            "error": str(e)
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
            "error": "Please login before analyzing PCAP files"
        }), 401

    if "file" not in request.files:

        return jsonify({
            "error": "PCAP file is required"
        }), 400

    file = request.files["file"]

    if file.filename == "":

        return jsonify({
            "error": "No file selected"
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
            "error": "Only PCAP, PCAPNG or CAP files are allowed"
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

            "filename": filename,

            "analysis": analysis

        })

    except Exception as e:

        return jsonify({

            "error": str(e)

        }), 500

    finally:

        if os.path.exists(
            file_path
        ):

            os.remove(
                file_path
            )


# ============================================================
# HISTORY
# ============================================================

@app.route(
    "/history",
    methods=["GET"]
)
def history():

    if "user_id" not in session:

        return redirect(
            "/login-page"
        )

    try:

        scans = get_scan_history()

        # ----------------------------------------------------
        # Convert Supabase dictionaries into the tuple format
        # expected by the existing history.html
        # ----------------------------------------------------

        history_rows = []

        for scan_data in scans:

            history_rows.append((

                scan_data.get("id"),

                scan_data.get("target"),

                scan_data.get("scan_date"),

                scan_data.get("total_ports"),

                scan_data.get("scan_type"),

                scan_data.get("duration")

            ))

        return render_template(
            "history.html",
            history=history_rows
        )

    except Exception as e:

        return (
            f"Error loading scan history: {e}",
            500
        )


# ============================================================
# PDF REPORT
# ============================================================

@app.route(
    "/report/<int:scan_id>",
    methods=["GET"]
)
def report(scan_id):

    if "user_id" not in session:

        return redirect(
            "/login-page"
        )

    pdf_path = os.path.join(
        "reports",
        f"scan_report_{scan_id}.pdf"
    )

    if not os.path.exists(
        pdf_path
    ):

        return jsonify({
            "error": "PDF report not found"
        }), 404

    return send_file(
        pdf_path,
        as_attachment=False
    )


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
            "error": "Please login before sending email"
        }), 401

    try:

        data = request.get_json(
            silent=True
        )

        if not data:

            return jsonify({
                "error": "Invalid or missing JSON data"
            }), 400

        scan_id = data.get(
            "scan_id"
        )

        receiver_email = data.get(
            "email"
        )

        if not scan_id:

            return jsonify({
                "error": "Scan ID is required"
            }), 400

        if not receiver_email:

            return jsonify({
                "error": "Receiver email is required"
            }), 400

        if not re.match(
            r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$",
            receiver_email
        ):

            return jsonify({
                "error": "Invalid email address"
            }), 400

        pdf_path = os.path.join(
            "reports",
            f"scan_report_{scan_id}.pdf"
        )

        if not os.path.exists(
            pdf_path
        ):

            return jsonify({
                "error": "PDF report not found"
            }), 404

        print(
            "========================================"
        )

        print(
            "EMAIL REPORT"
        )

        print(
            "Receiver:",
            receiver_email
        )

        print(
            "PDF:",
            pdf_path
        )

        print(
            "========================================"
        )

        send_report_email(
            receiver_email,
            pdf_path
        )

        print(
            "EMAIL SENT SUCCESSFULLY"
        )

        return jsonify({

            "status": "success",

            "message": "Report sent successfully"

        }), 200

    except Exception as e:

        print(
            "========================================"
        )

        print(
            "EMAIL REPORT ERROR"
        )

        print(
            type(e).__name__
        )

        print(
            str(e)
        )

        print(
            "========================================"
        )

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )