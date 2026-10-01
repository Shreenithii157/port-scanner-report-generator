from flask import (
    Flask,
    render_template,
    request,
    send_file
)

from datetime import datetime


from scanner.nmap_scanner import scan_target

from scanner.risk import get_port_risk

from scanner.recommendations import generate_recommendations

from scanner.cve_lookup import lookup_cves

from scanner.pdf_report import generate_pdf_report


from database.database import (
    init_db,
    save_scan,
    get_scan_history,
    get_dashboard_data,
    get_scan_by_id,
    get_ports_by_scan_id
)


app = Flask(__name__)


# --------------------------------
# HOME PAGE
# --------------------------------

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# --------------------------------
# START SCAN
# --------------------------------

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    target_input = request.form["target"]


    # --------------------------------
    # GET TARGETS
    # --------------------------------

    targets = [

        target.strip()

        for target in target_input.splitlines()

        if target.strip()

    ]


    all_results = []

    total_duration = 0

    scanned_targets = []

    all_cves = []


    # --------------------------------
    # SCAN DATE
    # --------------------------------

    scan_date = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    # --------------------------------
    # SCAN EACH TARGET
    # --------------------------------

    for target in targets:

        try:

            # Run Nmap

            results, duration = scan_target(
                target
            )


            # CVEs for this target

            target_cves = []


            # --------------------------------
            # PROCESS RESULTS
            # --------------------------------

            for result in results:

                result["target"] = target


                # --------------------------------
                # RISK
                # --------------------------------

                result["risk"] = get_port_risk(

                    result["port"],

                    result["service"]

                )


                # --------------------------------
                # CVE LOOKUP
                # --------------------------------

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


                    target_cves.extend(
                        cves
                    )


            # --------------------------------
            # ADD RESULTS
            # --------------------------------

            all_results.extend(
                results
            )


            # --------------------------------
            # ADD CVEs
            # --------------------------------

            all_cves.extend(
                target_cves
            )


            # --------------------------------
            # SAVE SCAN
            # --------------------------------

            save_scan(

                target,

                duration,

                results,

                cve_count=len(
                    target_cves
                )

            )


            # --------------------------------
            # TOTAL DURATION
            # --------------------------------

            total_duration += duration


            # --------------------------------
            # REMEMBER TARGET
            # --------------------------------

            scanned_targets.append(
                target
            )


        except Exception as error:

            print(
                f"Error scanning {target}: {error}"
            )


    # --------------------------------
    # RECOMMENDATIONS
    # --------------------------------

    recommendations = (

        generate_recommendations(
            all_results
        )

    )


    # --------------------------------
    # SECURITY SUMMARY
    # --------------------------------

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


    # --------------------------------
    # SUMMARY
    # --------------------------------

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


    # --------------------------------
    # GENERATE PDF
    # --------------------------------

    try:

        generate_pdf_report(

            target=", ".join(
                scanned_targets
            ),

            results=all_results,

            duration=round(
                total_duration,
                2
            ),

            recommendations=recommendations,

            cves=all_cves

        )

    except Exception as error:

        print(
            "PDF generation error:",
            error
        )


    # --------------------------------
    # DISPLAY REPORT
    # --------------------------------

    return render_template(

        "report.html",

        target=", ".join(
            scanned_targets
        ),

        results=all_results,

        duration=round(
            total_duration,
            2
        ),

        recommendations=recommendations,

        cves=all_cves,

        summary=summary,

        scan_date=scan_date

    )


# --------------------------------
# DOWNLOAD PDF
# --------------------------------

@app.route(
    "/download-pdf"
)
def download_pdf():

    return send_file(

        "exports/security_report.pdf",

        as_attachment=True

    )


# --------------------------------
# SCAN HISTORY
# --------------------------------

@app.route("/history")
def history():

    scans = get_scan_history()


    return render_template(

        "history.html",

        scans=scans

    )


# --------------------------------
# PREVIOUS SCAN REPORT
# --------------------------------

@app.route(
    "/report/<int:scan_id>"
)
def previous_report(scan_id):

    scan = get_scan_by_id(
        scan_id
    )


    # --------------------------------
    # CHECK SCAN
    # --------------------------------

    if scan is None:

        return (
            "Scan not found",
            404
        )


    # --------------------------------
    # GET PORTS
    # --------------------------------

    ports = get_ports_by_scan_id(
        scan_id
    )


    results = []


    # --------------------------------
    # REBUILD RESULTS
    # --------------------------------

    for port in ports:

        result = {

            "port": port["port"],

            "protocol": port["protocol"],

            "state": port["state"],

            "service": port["service"],

            "product": port["product"],

            "version": port["version"]

        }


        # --------------------------------
        # RISK
        # --------------------------------

        result["risk"] = get_port_risk(

            result["port"],

            result["service"]

        )


        result["target"] = scan["target"]


        results.append(
            result
        )


    # --------------------------------
    # RECOMMENDATIONS
    # --------------------------------

    recommendations = (

        generate_recommendations(
            results
        )

    )


    # --------------------------------
    # CVE LOOKUP
    # --------------------------------

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


    # --------------------------------
    # SECURITY SUMMARY
    # --------------------------------

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


    # --------------------------------
    # DISPLAY PREVIOUS REPORT
    # --------------------------------

    return render_template(

        "report.html",

        target=scan["target"],

        results=results,

        duration=scan["duration"],

        recommendations=recommendations,

        cves=all_cves,

        summary=summary,

        scan_date=scan["scan_date"]

    )


# --------------------------------
# DASHBOARD
# --------------------------------

@app.route("/dashboard")
def dashboard():

    (

        total_scans,

        total_ports,

        total_vulnerabilities,

        latest_target

    ) = get_dashboard_data()


    return render_template(

        "dashboard.html",

        total_scans=total_scans,

        total_ports=total_ports,

        total_vulnerabilities=total_vulnerabilities,

        latest_target=latest_target

    )


# --------------------------------
# INITIALIZE DATABASE
# --------------------------------

init_db()


# --------------------------------
# RUN APPLICATION
# --------------------------------

if __name__ == "__main__":

    app.run(
        debug=True
    )