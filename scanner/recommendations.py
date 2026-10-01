# --------------------------------
# SECURITY RECOMMENDATIONS
# --------------------------------

def generate_recommendations(results):

    recommendations = []


    # Check every detected port

    for result in results:

        port = result.get("port")

        service = result.get(
            "service",
            ""
        ).lower()


        # --------------------------------
        # FTP
        # --------------------------------

        if port == 21 or service == "ftp":

            recommendations.append(
                "FTP is open. Consider using SFTP or another "
                "encrypted file transfer protocol."
            )


        # --------------------------------
        # SSH
        # --------------------------------

        elif port == 22 or service == "ssh":

            recommendations.append(
                "SSH is open. Use strong passwords or SSH keys "
                "and restrict SSH access to trusted users."
            )


        # --------------------------------
        # TELNET
        # --------------------------------

        elif port == 23 or service == "telnet":

            recommendations.append(
                "Telnet is open. Telnet is insecure; "
                "use SSH instead."
            )


        # --------------------------------
        # HTTP
        # --------------------------------

        elif port == 80 or service == "http":

            recommendations.append(
                "HTTP is open. Consider using HTTPS "
                "to encrypt web traffic."
            )


        # --------------------------------
        # HTTPS
        # --------------------------------

        elif port == 443 or service == "https":

            recommendations.append(
                "HTTPS is open. Keep the web server and "
                "TLS configuration properly updated."
            )


        # --------------------------------
        # SMB
        # --------------------------------

        elif port == 445 or service == "microsoft-ds":

            recommendations.append(
                "SMB port 445 is open. Restrict SMB access "
                "to trusted networks and keep the system updated."
            )


        # --------------------------------
        # RDP
        # --------------------------------

        elif port == 3389 or service == "ms-wbt-server":

            recommendations.append(
                "RDP port 3389 is open. Restrict remote desktop "
                "access and use strong authentication."
            )


        # --------------------------------
        # MYSQL
        # --------------------------------

        elif port == 3306 or service == "mysql":

            recommendations.append(
                "MySQL port 3306 is open. Restrict database access "
                "to trusted hosts and avoid exposing it publicly."
            )


        # --------------------------------
        # POSTGRESQL
        # --------------------------------

        elif port == 5432 or service == "postgresql":

            recommendations.append(
                "PostgreSQL port 5432 is open. Restrict database "
                "access to trusted hosts."
            )


        # --------------------------------
        # OTHER PORTS
        # --------------------------------

        else:

            recommendations.append(
                f"Port {port} ({service or 'unknown service'}) "
                "is open. Verify that this service is required "
                "and keep it updated."
            )


    # --------------------------------
    # REMOVE DUPLICATE RECOMMENDATIONS
    # --------------------------------

    recommendations = list(
        dict.fromkeys(recommendations)
    )


    # --------------------------------
    # NO OPEN PORTS
    # --------------------------------

    if not recommendations:

        recommendations.append(
            "No open ports were detected. Continue monitoring "
            "the system and keep security updates enabled."
        )


    return recommendations