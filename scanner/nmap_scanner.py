import subprocess
import xml.etree.ElementTree as ET


def scan_target(target, scan_type="tcp"):
    """
    Scan a target using either TCP or UDP.
    """

    scan_type = scan_type.lower()

    if scan_type == "tcp":

        command = [
            "nmap",
            "-sT",
            "-sV",
            "-T4",
            "-p",
            "1-10000",
            "-oX",
            "-",
            target
        ]

    elif scan_type == "udp":

        command = [
            "nmap",
            "-sU",
            "-sV",
            "-T4",
            "--top-ports",
            "100",
            "-oX",
            "-",
            target
        ]

    else:

        raise ValueError(
            "Scan type must be TCP or UDP"
        )

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:

            raise RuntimeError(
                result.stderr.strip()
                or "Nmap scan failed"
            )

        return parse_nmap_xml(
            result.stdout,
            scan_type.upper()
        )

    except subprocess.TimeoutExpired:

        raise RuntimeError(
            f"{scan_type.upper()} scan timed out"
        )


def parse_nmap_xml(xml_output, protocol):
    """
    Parse Nmap XML output and return open/open|filtered ports.
    """

    results = []

    if not xml_output.strip():

        return results

    try:

        root = ET.fromstring(xml_output)

        for host in root.findall("host"):

            ports_element = host.find("ports")

            if ports_element is None:

                continue

            for port in ports_element.findall("port"):

                state = port.find("state")

                if state is None:

                    continue

                port_state = state.get(
                    "state",
                    ""
                )

                if port_state not in [
                    "open",
                    "open|filtered"
                ]:

                    continue

                service = port.find("service")

                service_name = "unknown"
                product = ""
                version = ""

                if service is not None:

                    service_name = service.get(
                        "name",
                        "unknown"
                    )

                    product = service.get(
                        "product",
                        ""
                    )

                    version = service.get(
                        "version",
                        ""
                    )

                results.append({

                    "port": int(
                        port.get("portid")
                    ),

                    "protocol": protocol,

                    "service": service_name,

                    "product": product,

                    "version": version,

                    "state": port_state

                })

        return results

    except ET.ParseError:

        raise RuntimeError(
            "Unable to parse Nmap XML output"
        )


def scan_multiple_targets(
    targets,
    scan_type="tcp"
):
    """
    Scan multiple targets using the selected protocol.
    """

    all_results = []

    for target in targets:

        results = scan_target(
            target,
            scan_type
        )

        all_results.append({

            "target": target,

            "results": results

        })

    return all_results