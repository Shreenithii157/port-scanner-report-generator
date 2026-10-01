import requests


# --------------------------------
# NVD API
# --------------------------------

NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)


# --------------------------------
# LOOK UP CVEs
# --------------------------------

def lookup_cves(product, version):

    # --------------------------------
    # REQUIRE PRODUCT AND VERSION
    # --------------------------------

    if not product or not version:

        return []


    # --------------------------------
    # BUILD SEARCH KEYWORD
    # --------------------------------

    keyword = f"{product} {version}"


    try:

        response = requests.get(

            NVD_API_URL,

            params={

                "keywordSearch": keyword,

                "resultsPerPage": 5

            },

            timeout=10

        )


        # --------------------------------
        # CHECK API RESPONSE
        # --------------------------------

        if response.status_code != 200:

            print(
                "NVD API error:",
                response.status_code
            )

            return []


        data = response.json()


        vulnerabilities = []


        # --------------------------------
        # READ CVE RESULTS
        # --------------------------------

        for item in data.get(
            "vulnerabilities",
            []
        ):


            cve = item.get(
                "cve",
                {}
            )


            # --------------------------------
            # CVE ID
            # --------------------------------

            cve_id = cve.get(
                "id",
                "Unknown"
            )


            # --------------------------------
            # DESCRIPTION
            # --------------------------------

            descriptions = cve.get(
                "descriptions",
                []
            )


            description = ""


            for desc in descriptions:

                if desc.get("lang") == "en":

                    description = desc.get(
                        "value",
                        ""
                    )

                    break


            # --------------------------------
            # CVSS INFORMATION
            # --------------------------------

            metrics = cve.get(
                "metrics",
                {}
            )


            score = None

            severity = "Unknown"


            # --------------------------------
            # CVSS 4.0
            # --------------------------------

            if metrics.get("cvssMetricV40"):

                cvss = metrics[
                    "cvssMetricV40"
                ][0].get(
                    "cvssData",
                    {}
                )


                score = cvss.get(
                    "baseScore"
                )


                severity = cvss.get(
                    "baseSeverity",
                    "Unknown"
                )


            # --------------------------------
            # CVSS 3.1
            # --------------------------------

            elif metrics.get("cvssMetricV31"):

                cvss = metrics[
                    "cvssMetricV31"
                ][0].get(
                    "cvssData",
                    {}
                )


                score = cvss.get(
                    "baseScore"
                )


                severity = cvss.get(
                    "baseSeverity",
                    "Unknown"
                )


            # --------------------------------
            # CVSS 3.0
            # --------------------------------

            elif metrics.get("cvssMetricV30"):

                cvss = metrics[
                    "cvssMetricV30"
                ][0].get(
                    "cvssData",
                    {}
                )


                score = cvss.get(
                    "baseScore"
                )


                severity = cvss.get(
                    "baseSeverity",
                    "Unknown"
                )


            # --------------------------------
            # PUBLISHED DATE
            # --------------------------------

            published = cve.get(
                "published",
                ""
            )


            # --------------------------------
            # ADD VULNERABILITY
            # --------------------------------

            vulnerabilities.append({

                "id": cve_id,

                "score": score,

                "severity": severity,

                "description": description,

                "product": product,

                "version": version,

                "published": published,

                "url":
                    f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            })


        return vulnerabilities


    # --------------------------------
    # REQUEST ERROR
    # --------------------------------

    except requests.RequestException as error:

        print(
            "CVE lookup error:",
            error
        )

        return []