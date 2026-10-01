import nmap
import time

from scanner.risk import get_port_risk


# --------------------------------
# NMAP SCAN
# --------------------------------

def scan_target(target):

    scanner = nmap.PortScanner()


    # Start timer

    start_time = time.time()


    # Run Nmap service detection

    scanner.scan(
        target,
        arguments="-sV"
    )


    # Calculate scan duration

    duration = round(
        time.time() - start_time,
        2
    )


    # Store results

    results = []


    # --------------------------------
    # PROCESS SCAN RESULTS
    # --------------------------------

    for host in scanner.all_hosts():

        for protocol in scanner[host].all_protocols():

            ports = scanner[host][protocol].keys()


            for port in sorted(ports):

                service = scanner[host][protocol][port]


                # Get service name

                service_name = service.get(
                    "name",
                    "unknown"
                )


                # Get risk level

                risk = get_port_risk(
                    port,
                    service_name
                )


                # Add result

                results.append({

                    "port": port,

                    "protocol": protocol,

                    "state": service.get(
                        "state",
                        ""
                    ),

                    "service": service_name,

                    "product": service.get(
                        "product",
                        ""
                    ),

                    "version": service.get(
                        "version",
                        ""
                    ),

                    "risk": risk

                })


    # Return scan results

    return results, duration