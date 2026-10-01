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

    output_file = (
        "exports/security_report.pdf"
    )

    document = SimpleDocTemplate(
        output_file,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
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
            f"<b>Target:</b> {target}",
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
            str(len(results)),
            str(len(cves or []))
        ]

    ]


    summary_table = Table(
        summary_data,
        colWidths=[
            0.75 * inch,
            0.85 * inch,
            0.75 * inch,
            0.8 * inch,
            0.8 * inch
        ]
    )


    summary_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#eeeeee"
                    )
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
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER"
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7
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

            0.55 * inch,

            0.65 * inch,

            0.55 * inch,

            0.75 * inch,

            1.15 * inch,

            0.85 * inch,

            0.65 * inch

        ]

    )


    port_table.setStyle(

        TableStyle(

            [

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#eeeeee"
                    )
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

            story.append(
                Paragraph(
                    f"<b>{cve_id}</b>",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Product:</b> "
                    f"{product} {version}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Severity:</b> "
                    f"{severity} "
                    f"| <b>CVSS:</b> {score}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    description,
                    normal_style
                )
            )

            story.append(
                Spacer(
                    1,
                    10
                )
            )

    else:

        story.append(
            Paragraph(
                "No matching CVEs found.",
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
    # SECURITY RECOMMENDATIONS
    # --------------------------------

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
                    f"• {recommendation}",
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