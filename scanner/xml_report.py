import os
import xml.etree.ElementTree as ET
from xml.dom import minidom


def generate_xml_report(
    target,
    duration,
    results,
    recommendations,
    cves=None,
    scan_type="service"
):
    """
    Generate an XML security scan report.

    The XML report contains:
    - Target
    - Scan type
    - Scan duration
    - Security summary
    - Port/service information
    - Risk classification
    - CVE information
    - Security recommendations
    """

    # -----------------------------------------
    # PROJECT PATH
    # -----------------------------------------

    base_dir = os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )

    exports_dir = os.path.join(
        base_dir,
        "exports"
    )

    os.makedirs(
        exports_dir,
        exist_ok=True
    )

    output_file = os.path.join(
        exports_dir,
        "security_report.xml"
    )

    # -----------------------------------------
    # ROOT
    # -----------------------------------------

    root = ET.Element(
        "security_scan_report"
    )

    root.set(
        "application",
        "Sentinel Security"
    )

    root.set(
        "version",
        "1.0"
    )

    # -----------------------------------------
    # SCAN INFORMATION
    # -----------------------------------------

    scan_info = ET.SubElement(
        root,
        "scan_information"
    )

    target_element = ET.SubElement(
        scan_info,
        "target"
    )

    target_element.text = str(
        target
    )

    scan_type_element = ET.SubElement(
        scan_info,
        "scan_type"
    )

    scan_type_element.text = str(
        scan_type
    )

    duration_element = ET.SubElement(
        scan_info,
        "duration_seconds"
    )

    duration_element.text = str(
        duration
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

    summary = ET.SubElement(
        root,
        "security_summary"
    )

    high_element = ET.SubElement(
        summary,
        "high_risk"
    )

    high_element.text = str(
        high_count
    )

    medium_element = ET.SubElement(
        summary,
        "medium_risk"
    )

    medium_element.text = str(
        medium_count
    )

    low_element = ET.SubElement(
        summary,
        "low_risk"
    )

    low_element.text = str(
        low_count
    )

    ports_element = ET.SubElement(
        summary,
        "open_ports"
    )

    ports_element.text = str(
        len(results)
    )

    cve_element = ET.SubElement(
        summary,
        "cve_matches"
    )

    cve_element.text = str(
        len(cves or [])
    )

    # -----------------------------------------
    # OPEN PORTS
    # -----------------------------------------

    ports_section = ET.SubElement(
        root,
        "open_ports"
    )

    for result in results:

        port_element = ET.SubElement(
            ports_section,
            "port"
        )

        port_element.set(
            "number",
            str(
                result.get(
                    "port",
                    ""
                )
            )
        )

        protocol_element = ET.SubElement(
            port_element,
            "protocol"
        )

        protocol_element.text = str(
            result.get(
                "protocol",
                ""
            )
        )

        state_element = ET.SubElement(
            port_element,
            "state"
        )

        state_element.text = str(
            result.get(
                "state",
                ""
            )
        )

        service_element = ET.SubElement(
            port_element,
            "service"
        )

        service_element.text = str(
            result.get(
                "service",
                ""
            )
        )

        product_element = ET.SubElement(
            port_element,
            "product"
        )

        product_element.text = str(
            result.get(
                "product",
                ""
            )
        )

        version_element = ET.SubElement(
            port_element,
            "version"
        )

        version_element.text = str(
            result.get(
                "version",
                ""
            )
        )

        risk_element = ET.SubElement(
            port_element,
            "risk"
        )

        risk_element.text = str(
            result.get(
                "risk",
                "Low"
            )
        )

    # -----------------------------------------
    # CVE INFORMATION
    # -----------------------------------------

    vulnerabilities = ET.SubElement(
        root,
        "cve_intelligence"
    )

    for cve in cves or []:

        cve_element = ET.SubElement(
            vulnerabilities,
            "cve"
        )

        cve_id = ET.SubElement(
            cve_element,
            "id"
        )

        cve_id.text = str(
            cve.get(
                "id",
                "Unknown"
            )
        )

        product = ET.SubElement(
            cve_element,
            "product"
        )

        product.text = str(
            cve.get(
                "product",
                ""
            )
        )

        version = ET.SubElement(
            cve_element,
            "version"
        )

        version.text = str(
            cve.get(
                "version",
                ""
            )
        )

        severity = ET.SubElement(
            cve_element,
            "severity"
        )

        severity.text = str(
            cve.get(
                "severity",
                "Unknown"
            )
        )

        score = ET.SubElement(
            cve_element,
            "cvss_score"
        )

        score.text = str(
            cve.get(
                "score",
                ""
            )
        )

        published = ET.SubElement(
            cve_element,
            "published"
        )

        published.text = str(
            cve.get(
                "published",
                ""
            )
        )

        description = ET.SubElement(
            cve_element,
            "description"
        )

        description.text = str(
            cve.get(
                "description",
                ""
            )
        )

        url = ET.SubElement(
            cve_element,
            "url"
        )

        url.text = str(
            cve.get(
                "url",
                ""
            )
        )

    # -----------------------------------------
    # SECURITY RECOMMENDATIONS
    # -----------------------------------------

    recommendations_element = ET.SubElement(
        root,
        "security_recommendations"
    )

    for recommendation in recommendations or []:

        recommendation_element = ET.SubElement(
            recommendations_element,
            "recommendation"
        )

        recommendation_element.text = str(
            recommendation
        )

    # -----------------------------------------
    # PRETTY XML
    # -----------------------------------------

    rough_xml = ET.tostring(
        root,
        encoding="utf-8"
    )

    parsed_xml = minidom.parseString(
        rough_xml
    )

    pretty_xml = parsed_xml.toprettyxml(
        indent="    ",
        encoding="utf-8"
    )

    # -----------------------------------------
    # SAVE
    # -----------------------------------------

    with open(
        output_file,
        "wb"
    ) as file:

        file.write(
            pretty_xml
        )

    return output_file