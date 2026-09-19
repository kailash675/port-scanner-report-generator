import os
import shutil
import subprocess
import xml.etree.ElementTree as ET


def find_nmap():
    """
    Find Nmap executable.
    """

    nmap_path = shutil.which("nmap")

    if nmap_path:
        return nmap_path

    windows_path = r"C:\Program Files (x86)\Nmap\nmap.exe"

    if os.path.exists(windows_path):
        return windows_path

    windows_path_2 = r"C:\Program Files\Nmap\nmap.exe"

    if os.path.exists(windows_path_2):
        return windows_path_2

    raise FileNotFoundError(
        "Nmap executable was not found. "
        "Please install Nmap and add it to PATH."
    )


def parse_nmap_xml(xml_output):
    """
    Parse Nmap XML output into a simple list of port results.
    """

    results = []

    try:

        root = ET.fromstring(xml_output)

    except ET.ParseError as e:

        raise RuntimeError(
            f"Unable to parse Nmap XML output: {e}"
        )

    for host in root.findall("host"):

        # -----------------------------
        # OS DETECTION
        # -----------------------------

        os_detection = None

        os_element = host.find("os")

        if os_element is not None:

            osmatch = os_element.find("osmatch")

            if osmatch is not None:

                os_detection = osmatch.get(
                    "name"
                )

        # -----------------------------
        # PORTS
        # -----------------------------

        ports_element = host.find("ports")

        if ports_element is None:
            continue

        for port in ports_element.findall("port"):

            port_number = port.get(
                "portid"
            )

            protocol = port.get(
                "protocol"
            )

            state_element = port.find(
                "state"
            )

            service_element = port.find(
                "service"
            )

            state = "unknown"

            if state_element is not None:

                state = state_element.get(
                    "state",
                    "unknown"
                )

            service = "unknown"
            version = "unknown"

            if service_element is not None:

                service = service_element.get(
                    "name",
                    "unknown"
                )

                product = service_element.get(
                    "product"
                )

                version_value = service_element.get(
                    "version"
                )

                if product and version_value:

                    version = (
                        f"{product} "
                        f"{version_value}"
                    )

                elif product:

                    version = product

                elif version_value:

                    version = version_value

            # Keep open and open|filtered results
            if state in (
                "open",
                "open|filtered"
            ):

                results.append({

                    "port":
                        int(port_number),

                    "protocol":
                        protocol,

                    "state":
                        state,

                    "service":
                        service,

                    "version":
                        version,

                    "os_detection":
                        os_detection
                })

    return results


def run_nmap(
    nmap_path,
    target,
    arguments
):
    """
    Execute Nmap and return XML output.
    """

    command = [
        nmap_path,
        *arguments,
        target
    ]

    process = subprocess.run(

        command,

        capture_output=True,

        text=True,

        timeout=600
    )

    stdout = process.stdout or ""
    stderr = process.stderr or ""

    if process.returncode != 0:

        error_text = (
            stderr.strip()
            or stdout.strip()
            or "Nmap scan failed."
        )

        raise RuntimeError(
            error_text
        )

    return stdout


def scan_target(
    target,
    scan_type="tcp"
):
    """
    Scan a single target using Nmap.

    Supported scan types:

    tcp
    udp
    syn
    service_detection
    os_detection
    aggressive_scan
    full_scan
    """

    nmap_path = find_nmap()

    scan_type = (
        scan_type
        or "tcp"
    ).lower().strip()

    # --------------------------------
    # TCP CONNECT SCAN
    # --------------------------------

    if scan_type == "tcp":

        arguments = [
            "-sT",
            "-sV",
            "-Pn",
            "-T3",
            "-p",
            "1-10000",
            "-oX",
            "-"
        ]

    # --------------------------------
    # UDP SCAN
    # --------------------------------

    elif scan_type == "udp":

        arguments = [
            "-sU",
            "-sV",
            "-Pn",
            "-T3",
            "--top-ports",
            "100",
            "-oX",
            "-"
        ]

    # --------------------------------
    # SYN SCAN
    # --------------------------------

    elif scan_type == "syn":

        arguments = [
            "-sS",
            "-sV",
            "-Pn",
            "-T3",
            "-p",
            "1-10000",
            "-oX",
            "-"
        ]

    # --------------------------------
    # SERVICE DETECTION
    # --------------------------------

    elif scan_type in (
        "service",
        "service_detection",
        "version",
        "version_detection"
    ):

        arguments = [
            "-sV",
            "-Pn",
            "-T3",
            "-p",
            "1-10000",
            "-oX",
            "-"
        ]

    # --------------------------------
    # OS DETECTION
    # --------------------------------

    elif scan_type in (
        "os",
        "os_scan",
        "os_detection"
    ):

        arguments = [
            "-O",
            "-sV",
            "-Pn",
            "-T3",
            "-p",
            "1-1000",
            "-oX",
            "-"
        ]

    # --------------------------------
    # AGGRESSIVE SCAN
    # --------------------------------

    elif scan_type in (
        "aggressive",
        "aggressive_scan"
    ):

        arguments = [
            "-A",
            "-Pn",
            "-T3",
            "-p",
            "1-10000",
            "-oX",
            "-"
        ]

    # --------------------------------
    # FULL SCAN
    # --------------------------------

    elif scan_type in (
        "full",
        "full_scan"
    ):

        arguments = [
            "-sT",
            "-sV",
            "-Pn",
            "-T3",
            "-p-",
            "-oX",
            "-"
        ]

    else:

        raise ValueError(
            f"Unsupported scan type: {scan_type}"
        )

    # --------------------------------
    # RUN SCAN
    # --------------------------------

    try:

        xml_output = run_nmap(
            nmap_path,
            target,
            arguments
        )

        results = parse_nmap_xml(
            xml_output
        )

        return results

    except RuntimeError as e:

        error_message = str(e).lower()

        # --------------------------------
        # SYN RAW SOCKET FALLBACK
        # --------------------------------

        if (
            scan_type == "syn"
            and (
                "raw socket" in error_message
                or "operation not permitted"
                in error_message
                or "permission denied"
                in error_message
                or "requires root" in error_message
            )
        ):

            print(
                "SYN scan requires raw socket "
                "privileges. Falling back to "
                "TCP Connect Scan (-sT)."
            )

            fallback_arguments = [
                "-sT",
                "-sV",
                "-Pn",
                "-T3",
                "-p",
                "1-10000",
                "-oX",
                "-"
            ]

            xml_output = run_nmap(
                nmap_path,
                target,
                fallback_arguments
            )

            results = parse_nmap_xml(
                xml_output
            )

            # Add information for UI/report
            for result in results:

                result[
                    "scan_note"
                ] = (
                    "SYN scan was unavailable "
                    "because raw socket privileges "
                    "were not available. "
                    "TCP Connect Scan was used "
                    "as a fallback."
                )

            return results

        raise


def scan_multiple_targets(
    targets,
    scan_type="tcp"
):
    """
    Scan multiple authorized targets.
    """

    all_results = []

    for target in targets:

        target = target.strip()

        if not target:
            continue

        results = scan_target(
            target,
            scan_type
        )

        for result in results:

            result[
                "target"
            ] = target

        all_results.extend(
            results
        )

    return all_results