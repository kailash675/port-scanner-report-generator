import os
import shutil
import subprocess
import xml.etree.ElementTree as ET


def get_nmap_path():
    """
    Find Nmap automatically on Windows, Linux and Docker.
    """

    # First try PATH
    nmap_path = shutil.which("nmap")

    if nmap_path:
        return nmap_path

    # Windows fallback
    windows_paths = [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
    ]

    for path in windows_paths:
        if os.path.isfile(path):
            return path

    raise RuntimeError(
        "Nmap is not installed or cannot be found. "
        "Install Nmap or make sure it is available in PATH."
    )


def scan_target(target, scan_type="tcp"):

    scan_type = scan_type.lower()

    nmap_path = get_nmap_path()

    if scan_type == "tcp":

        command = [
            nmap_path,
            "-sT",
            "-sV",
            "-Pn",
            "-T3",
            "-p",
            "1-10000",
            "-oX",
            "-",
            target
        ]

    elif scan_type == "udp":

        command = [
            nmap_path,
            "-sU",
            "-sV",
            "-Pn",
            "-T3",
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

            error_message = (
                result.stderr.strip()
                or "Nmap scan failed"
            )

            raise RuntimeError(
                error_message
            )

        return parse_nmap_xml(
            result.stdout,
            scan_type.upper()
        )

    except subprocess.TimeoutExpired:

        raise RuntimeError(
            f"{scan_type.upper()} scan timed out after 5 minutes"
        )

    except FileNotFoundError:

        raise RuntimeError(
            "Nmap executable was not found. "
            "Please check the Nmap installation."
        )


def parse_nmap_xml(
    xml_output,
    protocol
):

    results = []

    if not xml_output.strip():
        return results

    try:

        root = ET.fromstring(
            xml_output
        )

        for host in root.findall("host"):

            ports_element = host.find(
                "ports"
            )

            if ports_element is None:
                continue

            for port in ports_element.findall(
                "port"
            ):

                state = port.find(
                    "state"
                )

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

                service = port.find(
                    "service"
                )

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

                    "port":
                        int(
                            port.get("portid")
                        ),

                    "protocol":
                        protocol,

                    "service":
                        service_name,

                    "product":
                        product,

                    "version":
                        version,

                    "state":
                        port_state
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

        results = scan_target(
            target,
            scan_type
        )

        all_results.append({

            "target":
                target,

            "results":
                results

        })

    return all_results