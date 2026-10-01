from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from xml.sax.saxutils import escape


# --------------------------------
# GENERATE PDF REPORT
# --------------------------------

def generate_pdf_report(
    target,
    duration,
    results,
    recommendations,
    cves=None
):

    output_file = "exports/security_report.pdf"

    if cves is None:
        cves = []


    # --------------------------------
    # CALCULATE SECURITY SUMMARY
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


    total_ports = len(results)

    total_cves = len(cves)


    # --------------------------------
    # CREATE PDF
    # --------------------------------

    document = SimpleDocTemplate(

        output_file,

        pagesize=A4,

        rightMargin=35,

        leftMargin=35,

        topMargin=40,

        bottomMargin=40

    )


    styles = getSampleStyleSheet()

    title_style = styles["Title"]

    heading_style = styles["Heading2"]

    normal_style = styles["BodyText"]


    story = []


    # --------------------------------
    # TITLE
    # --------------------------------

    story.append(

        Paragraph(

            "Port Scanner Security Report",

            title_style

        )

    )

    story.append(

        Spacer(
            1,
            15
        )

    )


    # --------------------------------
    # BASIC INFORMATION
    # --------------------------------

    story.append(

        Paragraph(

            f"<b>Target:</b> "
            f"{escape(str(target))}",

            normal_style

        )

    )

    story.append(

        Paragraph(

            f"<b>Scan Duration:</b> "
            f"{duration} seconds",

            normal_style

        )

    )

    story.append(

        Spacer(
            1,
            20
        )

    )


    # --------------------------------
    # SECURITY SUMMARY
    # --------------------------------

    story.append(

        Paragraph(

            "Security Summary",

            heading_style

        )

    )

    story.append(

        Spacer(
            1,
            10
        )

    )


    summary_data = [

        [
            "High Risk",
            "Medium Risk",
            "Low Risk",
            "Open Ports",
            "CVE Matches"
        ],

        [
            str(high_count),
            str(medium_count),
            str(low_count),
            str(total_ports),
            str(total_cves)
        ]

    ]


    summary_table = Table(

        summary_data,

        colWidths=[

            1.0 * inch,

            1.0 * inch,

            1.0 * inch,

            1.0 * inch,

            1.0 * inch

        ]

    )


    summary_table.setStyle(

        TableStyle(

            [

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#eeeeee")
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "FONTNAME",
                    (0, 1),
                    (-1, 1),
                    "Helvetica-Bold"
                ),

                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER"
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                )

            ]

        )

    )


    story.append(

        summary_table

    )

    story.append(

        Spacer(
            1,
            25
        )

    )


    # --------------------------------
    # OPEN PORTS
    # --------------------------------

    story.append(

        Paragraph(

            "Open Ports",

            heading_style

        )

    )

    story.append(

        Spacer(
            1,
            10
        )

    )


    table_data = [

        [

            "Port",
            "Protocol",
            "State",
            "Service",
            "Product",
            "Version",
            "Risk"

        ]

    ]


    for result in results:

        table_data.append(

            [

                str(
                    result.get(
                        "port",
                        ""
                    )
                ),

                str(
                    result.get(
                        "protocol",
                        ""
                    )
                ),

                str(
                    result.get(
                        "state",
                        ""
                    )
                ),

                str(
                    result.get(
                        "service",
                        ""
                    )
                ),

                str(
                    result.get(
                        "product",
                        ""
                    )
                ),

                str(
                    result.get(
                        "version",
                        ""
                    )
                ),

                str(
                    result.get(
                        "risk",
                        ""
                    )
                )

            ]

        )


    port_table = Table(

        table_data,

        repeatRows=1,

        colWidths=[

            0.50 * inch,
            0.60 * inch,
            0.55 * inch,
            0.75 * inch,
            1.20 * inch,
            0.80 * inch,
            0.60 * inch

        ]

    )


    port_table.setStyle(

        TableStyle(

            [

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#eeeeee")
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.black
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                )

            ]

        )

    )


    story.append(

        port_table

    )

    story.append(

        Spacer(
            1,
            25
        )

    )


    # --------------------------------
    # CVE SECTION
    # --------------------------------

    story.append(

        Paragraph(

            "Vulnerability / CVE Lookup",

            heading_style

        )

    )

    story.append(

        Spacer(
            1,
            10
        )

    )


    if cves:

        for cve in cves:

            cve_id = cve.get(
                "id",
                "Unknown"
            )

            severity = cve.get(
                "severity",
                "Unknown"
            )

            score = cve.get(
                "score",
                "None"
            )

            product = cve.get(
                "product",
                "Unknown Product"
            )

            version = cve.get(
                "version",
                ""
            )

            description = cve.get(
                "description",
                ""
            )

            url = cve.get(
                "url",
                ""
            )


            story.append(

                Paragraph(

                    f"<b>{escape(str(product))} "
                    f"{escape(str(version))}</b>",

                    normal_style

                )

            )


            story.append(

                Spacer(
                    1,
                    5
                )

            )


            story.append(

                Paragraph(

                    f"<b>{escape(str(cve_id))}</b> "
                    f"| Severity: "
                    f"{escape(str(severity))} "
                    f"| CVSS: "
                    f"{escape(str(score))}",

                    normal_style

                )

            )


            story.append(

                Spacer(
                    1,
                    5
                )

            )


            if description:

                story.append(

                    Paragraph(

                        escape(
                            str(description)
                        ),

                        normal_style

                    )

                )


            if url:

                story.append(

                    Spacer(
                        1,
                        5
                    )

                )

                story.append(

                    Paragraph(

                        f'<link href="{escape(str(url))}" '
                        f'color="blue">'
                        f'View CVE on NVD'
                        f'</link>',

                        normal_style

                    )

                )


            story.append(

                Spacer(
                    1,
                    15
                )

            )


    else:

        story.append(

            Paragraph(

                "No matching CVEs found.",

                normal_style

            )

        )


    # --------------------------------
    # SECURITY RECOMMENDATIONS
    # --------------------------------

    story.append(

        Spacer(
            1,
            10
        )

    )

    story.append(

        Paragraph(

            "Security Recommendations",

            heading_style

        )

    )

    story.append(

        Spacer(
            1,
            10
        )

    )


    if recommendations:

        for recommendation in recommendations:

            story.append(

                Paragraph(

                    f"• "
                    f"{escape(str(recommendation))}",

                    normal_style

                )

            )

            story.append(

                Spacer(
                    1,
                    5
                )

            )


    else:

        story.append(

            Paragraph(

                "No specific recommendations "
                "were generated.",

                normal_style

            )

        )


    # --------------------------------
    # BUILD PDF
    # --------------------------------

    document.build(

        story

    )


    return output_file