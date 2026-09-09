import os
import subprocess
import xml.etree.ElementTree as ET


NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"


def get_nmap_path():

    if os.path.isfile(NMAP_PATH):
        return NMAP_PATH

    raise FileNotFoundError(
        f"Nmap not found at: {NMAP_PATH}"
    )


def scan_target(target, scan_type="tcp"):

    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty")

    scan_type = scan_type.lower()

    nmap = get_nmap_path()


    if scan_type == "tcp":

        command = [
            nmap,
            "-sT",
            "-Pn",
            "-T3",
            "-p",
            "1-10000",
            "-sV",
            "-oX",
            "-",
            target
        ]

    elif scan_type == "udp":

        command = [
            nmap,
            "-sU",
            "-Pn",
            "-T3",
            "--top-ports",
            "100",
            "-sV",
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

            error_message = (
                result.stderr.strip()
                or result.stdout.strip()
                or "Nmap scan failed"
            )

            raise RuntimeError(error_message)


        return parse_nmap_xml(
            result.stdout,
            scan_type.upper()
        )


    except subprocess.TimeoutExpired:

        raise RuntimeError(
            f"{scan_type.upper()} scan timed out after 5 minutes"
        )


def parse_nmap_xml(xml_output, protocol):

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

    all_results = []


    for target in targets:

        target = target.strip()

        if not target:
            continue


        results = scan_target(
            target,
            scan_type
        )


        all_results.append({

            "target": target,

            "results": results

        })


    return all_results