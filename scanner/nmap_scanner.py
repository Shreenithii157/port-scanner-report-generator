import nmap
import time


def scan_target(target, scan_type="service"):
    """
    Run an Nmap scan using the selected scan type.

    Supported scan types:
        tcp
        syn
        udp
        tcp_udp
        service
        os
        aggressive
        ping
    """

    scanner = nmap.PortScanner()

    scan_arguments = {
        "tcp": "-sT",
        "syn": "-sS",
        "udp": "-sU",
        "tcp_udp": "-sT -sU",
        "service": "-sT -sV",
        "os": "-sT -O",
        "aggressive": "-A",
        "ping": "-sn"
    }

    arguments = scan_arguments.get(
        scan_type,
        "-sT -sV"
    )

    start_time = time.time()

    scanner.scan(
        target,
        arguments=arguments
    )

    duration = round(
        time.time() - start_time,
        2
    )

    results = []

    for host in scanner.all_hosts():

        for protocol in scanner[host].all_protocols():

            ports = scanner[host][protocol].keys()

            for port in sorted(ports):

                service = scanner[host][protocol][port]

                results.append({
                    "port": port,
                    "protocol": protocol,
                    "state": service.get(
                        "state",
                        ""
                    ),
                    "service": service.get(
                        "name",
                        "unknown"
                    ),
                    "product": service.get(
                        "product",
                        ""
                    ),
                    "version": service.get(
                        "version",
                        ""
                    )
                })

    return results, duration