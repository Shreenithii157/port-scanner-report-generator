import os
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    redirect,
    url_for,
    session
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from scanner.nmap_scanner import scan_target
from scanner.risk import get_port_risk
from scanner.recommendations import generate_recommendations
from scanner.cve_lookup import lookup_cves
from scanner.pdf_report import generate_pdf_report
from scanner.xml_report import generate_xml_report
from scanner.pentest import run_pentest
from scanner.pentest_pdf import generate_pentest_pdf


from database.database import (
    init_db,
    save_scan,
    get_scan_history,
    get_dashboard_data,
    get_scan_by_id,
    get_ports_by_scan_id,
    create_user,
    get_user_by_username,
    get_user_by_email
)


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "sentinel-development-secret-key-change-this"
)


# =========================================================
# PROJECT PATHS
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

EXPORTS_DIR = os.path.join(
    BASE_DIR,
    "exports"
)

PDF_PATH = os.path.join(
    EXPORTS_DIR,
    "security_report.pdf"
)

XML_PATH = os.path.join(
    EXPORTS_DIR,
    "security_report.xml"
)

os.makedirs(
    EXPORTS_DIR,
    exist_ok=True
)


# =========================================================
# LOGIN REQUIRED
# =========================================================

def login_required(route_function):

    @wraps(route_function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            return redirect(
                url_for("login")
            )

        return route_function(
            *args,
            **kwargs
        )

    return wrapper


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    error = None
    success = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not username or not email or not password:

            error = (
                "Please fill in all required fields."
            )

        elif len(username) < 3:

            error = (
                "Username must contain at least 3 characters."
            )

        elif "@" not in email or "." not in email:

            error = (
                "Please enter a valid email address."
            )

        elif len(password) < 8:

            error = (
                "Password must contain at least 8 characters."
            )

        elif password != confirm_password:

            error = (
                "Passwords do not match."
            )

        elif get_user_by_username(username):

            error = (
                "Username is already registered."
            )

        elif get_user_by_email(email):

            error = (
                "Email is already registered."
            )

        else:

            password_hash = (
                generate_password_hash(
                    password
                )
            )

            user_id = create_user(
                username,
                email,
                password_hash
            )

            if user_id is None:

                error = (
                    "Unable to create account."
                )

            else:

                success = (
                    "Account created successfully. "
                    "You can now sign in."
                )

    return render_template(
        "register.html",
        error=error,
        success=success
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        user = get_user_by_username(
            username
        )

        if (
            user is None
            or not check_password_hash(
                user["password_hash"],
                password
            )
        ):

            error = (
                "Invalid username or password."
            )

        else:

            session.clear()

            session["user_id"] = user["id"]

            session["username"] = user["username"]

            session["email"] = user["email"]

            return redirect(
                url_for("dashboard")
            )

    return render_template(
        "login.html",
        error=error
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
@login_required
def home():

    return render_template(
        "index.html"
    )


# =========================================================
# SCAN
# =========================================================

@app.route(
    "/scan",
    methods=["POST"]
)
@login_required
def scan():

    target_input = request.form.get(
        "target",
        ""
    ).strip()

    scan_type = request.form.get(
        "scan_type",
        "service"
    ).strip().lower()

    allowed_scan_types = {

        "tcp",
        "syn",
        "udp",
        "tcp_udp",
        "service",
        "os",
        "aggressive",
        "ping"

    }

    if scan_type not in allowed_scan_types:

        scan_type = "service"

    if not target_input:

        return (
            "Please enter at least one target.",
            400
        )

    targets = [

        target.strip()

        for target in target_input.splitlines()

        if target.strip()

    ]

    all_results = []

    total_duration = 0

    scanned_targets = []

    all_cves = []


    # =====================================================
    # SCAN EACH TARGET
    # =====================================================

    for target in targets:

        try:

            results, duration = scan_target(
                target,
                scan_type
            )


            for result in results:

                result["target"] = target

                result["scan_type"] = scan_type


                # -----------------------------------------
                # RISK
                # -----------------------------------------

                result["risk"] = get_port_risk(
                    result["port"],
                    result["service"]
                )


                # -----------------------------------------
                # CVE LOOKUP
                # -----------------------------------------

                product = result.get(
                    "product",
                    ""
                )

                version = result.get(
                    "version",
                    ""
                )

                if product and version:

                    cves = lookup_cves(
                        product,
                        version
                    )

                    for cve in cves:

                        cve["product"] = product

                        cve["version"] = version

                    all_cves.extend(
                        cves
                    )


            all_results.extend(
                results
            )


            # -----------------------------------------
            # SAVE SCAN
            # -----------------------------------------

            save_scan(
                target,
                duration,
                results
            )


            total_duration += duration

            scanned_targets.append(
                target
            )


        except Exception as error:

            print(
                f"Error scanning {target}: {error}"
            )


    # =====================================================
    # RECOMMENDATIONS
    # =====================================================

    recommendations = generate_recommendations(
        all_results
    )


    # =====================================================
    # RISK COUNTS
    # =====================================================

    high_count = 0

    medium_count = 0

    low_count = 0


    for result in all_results:

        risk = result.get(
            "risk",
            "Low"
        )

        if risk == "High":

            high_count += 1

        elif risk == "Medium":

            medium_count += 1

        else:

            low_count += 1


    # =====================================================
    # SECURITY SUMMARY
    # =====================================================

    summary = {

        "high": high_count,

        "medium": medium_count,

        "low": low_count,

        "ports": len(
            all_results
        ),

        "cves": len(
            all_cves
        )

    }


    report_target = ", ".join(
        scanned_targets
    )

    report_duration = round(
        total_duration,
        2
    )


    # =====================================================
    # GENERATE PDF
    # =====================================================

    try:

        generate_pdf_report(

            target=report_target,

            results=all_results,

            duration=report_duration,

            recommendations=recommendations,

            cves=all_cves

        )

        print(
            "PDF generated successfully:"
        )

        print(
            PDF_PATH
        )

    except Exception as error:

        print(
            "PDF generation error:",
            error
        )


    # =====================================================
    # GENERATE XML
    # =====================================================

    try:

        generate_xml_report(

            target=report_target,

            duration=report_duration,

            results=all_results,

            recommendations=recommendations,

            cves=all_cves,

            scan_type=scan_type

        )

        print(
            "XML generated successfully:"
        )

        print(
            XML_PATH
        )

    except Exception as error:

        print(
            "XML generation error:",
            error
        )


    # =====================================================
    # REPORT PAGE
    # =====================================================

    return render_template(

        "report.html",

        target=report_target,

        results=all_results,

        duration=report_duration,

        recommendations=recommendations,

        cves=all_cves,

        summary=summary,

        scan_type=scan_type

    )


# =========================================================
# DOWNLOAD PDF
# =========================================================

@app.route(
    "/download-pdf"
)
@login_required
def download_pdf():

    if not os.path.exists(
        PDF_PATH
    ):

        return (
            "PDF report not found. "
            "Please run a new scan first.",
            404
        )

    return send_file(

        PDF_PATH,

        as_attachment=True,

        download_name="security_report.pdf"

    )


# =========================================================
# DOWNLOAD XML
# =========================================================

@app.route(
    "/download-xml"
)
@login_required
def download_xml():

    if not os.path.exists(
        XML_PATH
    ):

        return (
            "XML report not found. "
            "Please run a new scan first.",
            404
        )

    return send_file(

        XML_PATH,

        as_attachment=True,

        download_name="security_report.xml",

        mimetype="application/xml"

    )


# =========================================================
# SCAN HISTORY
# =========================================================

# --------------------------------
# PENTEST
# --------------------------------

@app.route(
    "/pentest",
    methods=["GET", "POST"]
)
@login_required
def pentest():

    findings = None
    target = ""

    summary = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    if request.method == "POST":

        target = request.form.get(
            "target",
            ""
        ).strip()

        if target:

            findings = run_pentest(
                target
            )

            for finding in findings:

                severity = finding.get(
                    "severity",
                    "Info"
                )

                if severity == "High":

                    summary["high"] += 1

                elif severity == "Medium":

                    summary["medium"] += 1

                elif severity == "Low":

                    summary["low"] += 1

                else:

                    summary["info"] += 1

                if findings is not None:
                    generate_pentest_pdf(
                        target,
                    findings,
                    {
                        "high": summary["high"],
                        "medium": summary["medium"],
                        "low": summary["low"],
                        "informational": summary["info"]
                    }
                )      

    return render_template(
        "pentest.html",
        target=target,
        findings=findings,
        summary=summary
    )


# ================================
# SCAN HISTORY
# ================================

@app.route("/history")
@login_required
def history():

    scans = get_scan_history()

    return render_template(

        "history.html",

        scans=scans

    )


# =========================================================
# PREVIOUS REPORT
# =========================================================

@app.route(
    "/report/<int:scan_id>"
)
@login_required
def previous_report(
    scan_id
):

    scan = get_scan_by_id(
        scan_id
    )

    if scan is None:

        return (
            "Scan not found",
            404
        )

    ports = get_ports_by_scan_id(
        scan_id
    )

    results = []


    for port in ports:

        result = {

            "port": port["port"],

            "protocol": port["protocol"],

            "state": port["state"],

            "service": port["service"],

            "product": port["product"],

            "version": port["version"]

        }


        result["risk"] = get_port_risk(

            result["port"],

            result["service"]

        )


        result["target"] = scan["target"]

        results.append(
            result
        )


    # -----------------------------------------
    # RECOMMENDATIONS
    # -----------------------------------------

    recommendations = generate_recommendations(
        results
    )


    # -----------------------------------------
    # CVE LOOKUP
    # -----------------------------------------

    all_cves = []


    for result in results:

        product = result.get(
            "product",
            ""
        )

        version = result.get(
            "version",
            ""
        )


        if product and version:

            cves = lookup_cves(
                product,
                version
            )


            for cve in cves:

                cve["product"] = product

                cve["version"] = version


            all_cves.extend(
                cves
            )


    # -----------------------------------------
    # RISK COUNTS
    # -----------------------------------------

    high_count = 0

    medium_count = 0

    low_count = 0


    for result in results:

        risk = result.get(
            "risk",
            "Low"
        )

        if risk == "High":

            high_count += 1

        elif risk == "Medium":

            medium_count += 1

        else:

            low_count += 1


    summary = {

        "high": high_count,

        "medium": medium_count,

        "low": low_count,

        "ports": len(
            results
        ),

        "cves": len(
            all_cves
        )

    }


    return render_template(

        "report.html",

        target=scan["target"],

        results=results,

        duration=scan["duration"],

        recommendations=recommendations,

        cves=all_cves,

        summary=summary,

        scan_type="service"

    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route(
    "/dashboard"
)
@login_required
def dashboard():

    total_scans, total_ports, latest_target = (
        get_dashboard_data()
    )

    return render_template(

        "dashboard.html",

        total_scans=total_scans,

        total_ports=total_ports,

        latest_target=latest_target,

        username=session.get(
            "username",
            "User"
        )

    )


# =========================================================
# INITIALIZE DATABASE
# =========================================================

init_db()


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )