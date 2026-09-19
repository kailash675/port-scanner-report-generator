from flask import (

    Flask,

    request,

    jsonify,

    render_template,

    send_file,

    session,

    redirect,

    Response

)


from werkzeug.utils import secure_filename


import re

import os

import time

import html

import xml.etree.ElementTree as ET

from io import BytesIO


from analyzer.pcap_analyzer import analyze_pcap


from scanner.nmap_scanner import (

    scan_target,

    scan_multiple_targets

)


from database.database import (

    create_tables,

    create_user,

    verify_user,

    save_scan,

    save_multiple_scan,

    get_scan_history,

    supabase

)


from analyzer.recommendations import (

    generate_recommendations

)


from analyzer.cve_lookup import (

    lookup_cves

)


from reports.report_generator import (

    generate_pdf

)


from email_sender import (

    send_report_email

)



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

# GET SCAN DATE

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

            repr(e)

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

# REPORT DOWNLOAD HELPERS

# ============================================================


def get_user_scan_data(scan_id):


    if "user_id" not in session:

        return None, None


    scan_response = (

        supabase

        .table("scans")

        .select(

            "id, target, scan_date, total_ports, scan_type, duration"

        )

        .eq("id", scan_id)

        .eq("user_id", session["user_id"])

        .limit(1)

        .execute()

    )


    if not scan_response.data:

        return None, None


    scan_data = scan_response.data[0]


    results_response = (

        supabase

        .table("scan_results")

        .select(

            "port, protocol, state, service, version"

        )

        .eq("scan_id", scan_id)

        .order("port")

        .execute()

    )


    results = results_response.data or []


    return scan_data, results



def build_xml_report(scan_data, results):


    root = ET.Element(

        "securescan_report",

        {

            "scan_id": str(scan_data.get("id", "")),

            "scan_type": str(

                scan_data.get("scan_type") or "TCP"

            )

        }

    )


    target = ET.SubElement(root, "target")

    target.text = str(scan_data.get("target") or "")


    scan_date = ET.SubElement(root, "scan_date")

    scan_date.text = str(scan_data.get("scan_date") or "")


    duration = ET.SubElement(root, "duration")

    duration.text = str(

        scan_data.get("duration")

        if scan_data.get("duration") is not None

        else ""

    )


    total_ports = ET.SubElement(root, "total_ports")

    total_ports.text = str(scan_data.get("total_ports") or 0)


    ports_element = ET.SubElement(root, "ports")


    for item in results:


        port_element = ET.SubElement(

            ports_element,

            "port",

            {

                "number": str(item.get("port") or ""),

                "protocol": str(item.get("protocol") or "")

            }

        )


        state = ET.SubElement(port_element, "state")

        state.text = str(item.get("state") or "")


        service = ET.SubElement(port_element, "service")

        service.text = str(item.get("service") or "")


        version = ET.SubElement(port_element, "version")

        version.text = str(item.get("version") or "")


    output = BytesIO()


    ET.ElementTree(root).write(

        output,

        encoding="utf-8",

        xml_declaration=True

    )


    output.seek(0)


    return output



def build_html_report(scan_data, results):


    scan_id = html.escape(

        str(scan_data.get("id") or "")

    )


    target = html.escape(

        str(scan_data.get("target") or "N/A")

    )


    scan_date = html.escape(

        str(scan_data.get("scan_date") or "N/A")

    )


    scan_type = html.escape(

        str(scan_data.get("scan_type") or "TCP").upper()

    )


    duration = html.escape(

        str(

            scan_data.get("duration")

            if scan_data.get("duration") is not None

            else "N/A"

        )

    )


    rows = []


    for item in results:


        rows.append(

            "<tr>"

            f"<td>{html.escape(str(item.get('port') or ''))}</td>"

            f"<td>{html.escape(str(item.get('protocol') or ''))}</td>"

            f"<td>{html.escape(str(item.get('state') or ''))}</td>"

            f"<td>{html.escape(str(item.get('service') or 'Unknown'))}</td>"

            f"<td>{html.escape(str(item.get('version') or '-'))}</td>"

            "</tr>"

        )


    if not rows:

        rows.append(

            '<tr><td colspan="5">No stored port results.</td></tr>'

        )


    rows_html = "".join(rows)


    return f"""<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>SecureScan Report #{scan_id}</title>

<style>

* {{ box-sizing: border-box; }}

body {{

    margin: 0;

    padding: 35px;

    background: #070b14;

    color: #e5e7eb;

    font-family: Arial, Helvetica, sans-serif;

}}

.container {{ max-width: 1100px; margin: 0 auto; }}

.header {{

    background: #0d1421;

    border: 1px solid #1e293b;

    border-radius: 12px;

    padding: 28px;

    margin-bottom: 20px;

}}

.logo {{

    color: #7dd3fc;

    font-size: 12px;

    letter-spacing: 2px;

    font-weight: bold;

}}

h1 {{ margin: 8px 0; font-size: 30px; color: #f8fafc; }}

.subtitle {{ color: #94a3b8; font-size: 13px; }}

.summary {{

    display: grid;

    grid-template-columns: repeat(5, 1fr);

    gap: 12px;

    margin-bottom: 20px;

}}

.card {{

    background: #0d1421;

    border: 1px solid #1e293b;

    border-radius: 10px;

    padding: 17px;

}}

.card span {{

    display: block;

    color: #64748b;

    font-size: 10px;

    text-transform: uppercase;

}}

.card strong {{

    display: block;

    margin-top: 8px;

    color: #e2e8f0;

    font-size: 15px;

    word-break: break-word;

}}

.table-card {{

    background: #0d1421;

    border: 1px solid #1e293b;

    border-radius: 10px;

    overflow: hidden;

}}

.table-title {{

    padding: 18px 20px;

    border-bottom: 1px solid #1e293b;

    color: #e2e8f0;

    font-weight: bold;

}}

.table-wrap {{ overflow-x: auto; }}

table {{

    width: 100%;

    border-collapse: collapse;

    min-width: 700px;

}}

th {{

    text-align: left;

    padding: 13px;

    background: #080d17;

    color: #64748b;

    font-size: 10px;

    text-transform: uppercase;

}}

td {{

    padding: 13px;

    border-top: 1px solid #151f2e;

    color: #94a3b8;

    font-size: 12px;

}}

.footer {{

    margin-top: 18px;

    color: #475569;

    font-size: 11px;

    text-align: center;

}}

@media (max-width: 800px) {{

    body {{ padding: 15px; }}

    .summary {{ grid-template-columns: 1fr 1fr; }}

}}

</style>

</head>

<body>

<div class="container">

    <div class="header">

        <div class="logo">SECURESCAN • NETWORK SECURITY ASSESSMENT</div>

        <h1>Security Scan Report</h1>

        <div class="subtitle">

            Downloadable HTML report generated from stored SecureScan scan results.

        </div>

    </div>


    <div class="summary">

        <div class="card"><span>Scan ID</span><strong>#{scan_id}</strong></div>

        <div class="card"><span>Target</span><strong>{target}</strong></div>

        <div class="card"><span>Scan Type</span><strong>{scan_type}</strong></div>

        <div class="card"><span>Total Ports</span><strong>{len(results)}</strong></div>

        <div class="card"><span>Duration</span><strong>{duration} sec</strong></div>

    </div>


    <div class="table-card">

        <div class="table-title">Port Scan Results</div>

        <div class="table-wrap">

            <table>

                <thead>

                    <tr>

                        <th>Port</th>

                        <th>Protocol</th>

                        <th>State</th>

                        <th>Service</th>

                        <th>Version</th>

                    </tr>

                </thead>

                <tbody>

                    {rows_html}

                </tbody>

            </table>

        </div>

    </div>


    <div class="footer">

        SecureScan • Scan #{scan_id} • {scan_date}

    </div>

</div>

</body>

</html>"""


# ============================================================

# HOME

# ============================================================


@app.route("/")

def home():


    return render_template(

        "index.html"

    )



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


    if not username:


        return jsonify({

            "error":

                "Username is required"

        }), 400


    if not password:


        return jsonify({

            "error":

                "Password is required"

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

            "status":

                "success",

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

            "status":

                "success",

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

        "status":

            "success",

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

            "authenticated":

                False

        })


    return jsonify({

        "authenticated":

            True,

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

    ).lower().strip()


    # ========================================================

    # ALLOWED SCAN TYPES

    # ========================================================


    allowed_scan_types = [

        "tcp",

        "udp",

        "syn",

        "service",

        "service_detection",

        "version",

        "version_detection",

        "os",

        "os_scan",

        "os_detection",

        "aggressive",

        "aggressive_scan",

        "full",

        "full_scan"

    ]


    if scan_type not in allowed_scan_types:


        return jsonify({

            "error":

                "Invalid scan type"

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


            if not isinstance(

                item,

                str

            ):


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


            # ------------------------------------------------

            # FLATTEN RESULTS

            # ------------------------------------------------


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


            recommendations = (

                generate_recommendations(

                    flat_results

                )

            )


            # ------------------------------------------------

            # USER-SPECIFIC SAVE

            # ------------------------------------------------


            scan_id = save_multiple_scan(

                session["user_id"],

                targets,

                flat_results

            )


            scan_duration = round(

                time.perf_counter()

                - start_time,

                2

            )


            # ------------------------------------------------

            # SAVE CORRECT SCAN TYPE + DURATION

            # ------------------------------------------------


            update_scan_metadata(

                scan_id,

                scan_type,

                scan_duration

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


                "status":

                    "success",


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

                    f"/report/{scan_id}",


                "report_xml":

                    f"/report/{scan_id}/xml",


                "report_html":

                    f"/report/{scan_id}/html"

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


    if not isinstance(

        target,

        str

    ):


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


        # ----------------------------------------------------

        # USER-SPECIFIC SAVE

        # ----------------------------------------------------


        scan_id = save_scan(

            session["user_id"],

            target,

            results

        )


        recommendations = (

            generate_recommendations(

                results

            )

        )


        scan_duration = round(

            time.perf_counter()

            - start_time,

            2

        )


        # ----------------------------------------------------

        # SAVE CORRECT SCAN TYPE + DURATION

        # ----------------------------------------------------


        update_scan_metadata(

            scan_id,

            scan_type,

            scan_duration

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


            "status":

                "success",


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

                f"/report/{scan_id}",


            "report_xml":

                f"/report/{scan_id}/xml",


            "report_html":

                f"/report/{scan_id}/html"

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

            "status":

                "success",

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

# SCAN HISTORY PAGE

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


        scans = get_scan_history(

            session["user_id"]

        )


        return render_template(

            "history.html",

            history=scans,

            username=session.get(

                "username"

            )

        )


    except Exception as e:


        print(

            "History error:",

            repr(e)

        )


        return render_template(

            "history.html",

            history=[],

            username=session.get(

                "username"

            ),

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


        scans = get_scan_history(

            session["user_id"]

        )


        return jsonify({

            "status":

                "success",

            "history":

                scans

        })


    except Exception as e:


        print(

            "API history error:",

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

            "status":

                "success",

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


        # ----------------------------------------------------

        # SECURITY CHECK

        # Only allow the logged-in user's report

        # ----------------------------------------------------


        scan_response = (

            supabase

            .table("scans")

            .select("id")

            .eq("id", scan_id)

            .eq("user_id", session["user_id"])

            .limit(1)

            .execute()

        )


        if not scan_response.data:


            return jsonify({

                "error":

                    "Report does not belong to the current user"

            }), 403


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

# XML REPORT DOWNLOAD

# ============================================================


@app.route(

    "/report/<int:scan_id>/xml",

    methods=["GET"]

)

def report_xml(scan_id):


    if "user_id" not in session:


        return jsonify({

            "error":

                "Please login before downloading reports"

        }), 401


    try:


        scan_data, results = get_user_scan_data(

            scan_id

        )


        if not scan_data:


            return jsonify({

                "error":

                    "Report does not belong to the current user"

            }), 403


        xml_file = build_xml_report(

            scan_data,

            results

        )


        return send_file(

            xml_file,

            as_attachment=True,

            download_name=(

                f"scan_report_{scan_id}.xml"

            ),

            mimetype="application/xml"

        )


    except Exception as e:


        print(

            "XML report error:",

            repr(e)

        )


        return jsonify({

            "error":

                str(e)

        }), 500



# ============================================================

# HTML REPORT DOWNLOAD

# ============================================================


@app.route(

    "/report/<int:scan_id>/html",

    methods=["GET"]

)

def report_html(scan_id):


    if "user_id" not in session:


        return jsonify({

            "error":

                "Please login before downloading reports"

        }), 401


    try:


        scan_data, results = get_user_scan_data(

            scan_id

        )


        if not scan_data:


            return jsonify({

                "error":

                    "Report does not belong to the current user"

            }), 403


        html_report = build_html_report(

            scan_data,

            results

        )


        return Response(

            html_report,

            mimetype="text/html",

            headers={

                "Content-Disposition":

                    f'attachment; filename="scan_report_{scan_id}.html"'

            }

        )


    except Exception as e:


        print(

            "HTML report error:",

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

