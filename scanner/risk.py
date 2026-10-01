# --------------------------------
# PORT RISK CLASSIFICATION
# --------------------------------

def get_port_risk(port, service):

    service = (service or "").lower()


    # High-risk ports/services

    high_risk_ports = {
        23,      # Telnet
        135,     # Microsoft RPC
        139,     # NetBIOS
        445,     # SMB
        3389     # RDP
    }


    if port in high_risk_ports:

        return "High"


    # Medium-risk ports/services

    medium_risk_ports = {
        21,      # FTP
        22,      # SSH
        25,      # SMTP
        53,      # DNS
        80,      # HTTP
        110,     # POP3
        143,     # IMAP
        3306,    # MySQL
        5432     # PostgreSQL
    }


    if port in medium_risk_ports:

        return "Medium"


    # Service-based classification

    if service == "telnet":

        return "High"


    if service in [
        "ftp",
        "http",
        "ssh",
        "smtp",
        "mysql",
        "postgresql"
    ]:

        return "Medium"


    # Unknown or uncommon ports

    return "Low"