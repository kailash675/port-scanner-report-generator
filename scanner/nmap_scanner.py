import os
import shutil
import subprocess
import xml.etree.ElementTree as ET


def get_nmap_path():
    """Find Nmap executable."""

    nmap_path = shutil.which("nmap")

    if nmap_path:
        return nmap_path

    windows_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe"
    ]

    for path in windows_paths:
        if os.path.exists(path):
            return path

    raise FileNotFoundError(
        "Nmap executable not found."
    )


def raw_socket_error(error):
    """Check whether error is caused by privileged/raw socket restrictions."""

    if not error:
        return False

    error = error.lower()

    keywords = [
        "couldn't open a raw socket",
        "couldn't open raw socket",
        "operation not permitted",
        "permission denied",
        "requires root",
        "requires privileged",
        "raw socket",
        "you need to be root"
    ]

    return any(word in error for word in keywords)


def get_scan_arguments(scan_type):

    scan_type = (scan_type or "tcp").lower().strip()

    # TCP CONNECT
    if scan_type == "tcp":
        return [
            "-sT",
            "-Pn",
            "-T3",
            "-p",
            "1-10000"
        ]

    # UDP
    if scan_type == "udp":
        return [
            "-sU",
            "-Pn",
            "-T3",
            "--top-ports",
            "100"
        ]

    # SYN
    if scan_type == "syn":
        return [
            "-sS",
            "-Pn",
            "-T3",
            "-p",
            "1-10000"
        ]

    # SERVICE / VERSION
    if scan_type in [
        "service",
        "service_detection",
        "version",
        "version_detection"
    ]:
        return [
            "-sT",
            "-sV",
            "-Pn",
            "-T3",
            "-p",
            "1-10000"
        ]

    # OS
    if scan_type in [
        "os",
        "os_scan",
        "os_detection"
    ]:
        return [
            "-O",
            "-sV",
            "-Pn",
            "-T3",
            "-p",
            "1-1000"
        ]

    # AGGRESSIVE
    if scan_type in [
        "aggressive",
        "aggressive_scan"
    ]:
        return [
            "-A",
            "-Pn",
            "-T3",
            "-p",
            "1-10000"
        ]

    # FULL
    if scan_type in [
        "full",
        "full_scan"
    ]:
        return [
            "-sT",
            "-sV",
            "-Pn",
            "-T3",
            "-p-"
        ]

    # DEFAULT
    return [
        "-sT",
        "-Pn",
        "-T3",
        "-p",
        "1-10000"
    ]


def get_fallback_arguments(scan_type):

    scan_type = (scan_type or "tcp").lower().strip()

    # UDP fallback
    if scan_type == "udp":
        return [
            "-sT",
            "-Pn",
            "-T3",
            "--top-ports",
            "100"
        ]

    # SYN fallback
    if scan_type == "syn":
        return [
            "-sT",
            "-Pn",
            "-T3",
            "-p",
            "1-10000"
        ]

    # OS fallback
    if scan_type in [
        "os",
        "os_scan",
        "os_detection"
    ]:
        return [
            "-sT",
            "-sV",
            "-Pn",
            "-T3",
            "-p",
            "1-1000"
        ]

    # Aggressive fallback
    if scan_type in [
        "aggressive",
        "aggressive_scan"
    ]:
        return [
            "-sT",
            "-sV",
            "-Pn",
            "-T3",
            "-p",
            "1-10000"
        ]

    # Service / version
    if scan_type in [
        "service",
        "service_detection",
        "version",
        "version_detection"
    ]:
        return [
            "-sT",
            "-sV",
            "-Pn",
            "-T3",
            "-p",
            "1-10000"
        ]

    return [
        "-sT",
        "-Pn",
        "-T3",
        "-p",
        "1-10000"
    ]


def run_nmap(target, scan_type="tcp"):
    """
    Run Nmap and return XML string.

    IMPORTANT:
    This function returns ONLY XML string.
    This keeps compatibility with the existing application.
    """

    nmap_path = get_nmap_path()

    arguments = get_scan_arguments(scan_type)

    command = [
        nmap_path,
        *arguments,
        "-oX",
        "-",
        target
    ]

    try:

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600
        )

        stdout = process.stdout or ""
        stderr = process.stderr or ""

        if process.returncode == 0 and stdout.strip():
            return stdout

        error_message = stderr.strip() or stdout.strip()

        # ----------------------------------------
        # RENDER RAW SOCKET FALLBACK
        # ----------------------------------------

        if raw_socket_error(error_message):

            fallback_arguments = get_fallback_arguments(
                scan_type
            )

            fallback_command = [
                nmap_path,
                *fallback_arguments,
                "-oX",
                "-",
                target
            ]

            fallback_process = subprocess.run(
                fallback_command,
                capture_output=True,
                text=True,
                timeout=600
            )

            fallback_stdout = (
                fallback_process.stdout or ""
            )

            fallback_stderr = (
                fallback_process.stderr or ""
            )

            if (
                fallback_process.returncode == 0
                and fallback_stdout.strip()
            ):
                return fallback_stdout

            raise RuntimeError(
                fallback_stderr.strip()
                or "Nmap fallback scan failed."
            )

        raise RuntimeError(
            error_message or "Nmap scan failed."
        )

    except subprocess.TimeoutExpired:

        raise RuntimeError(
            "Nmap scan timed out after 600 seconds."
        )


def parse_nmap_xml(xml_data):
    """
    Parse Nmap XML.

    IMPORTANT:
    Returns a LIST of port dictionaries.
    This is the format expected by the existing
    recommendations/database/report code.
    """

    results = []

    try:

        root = ET.fromstring(xml_data)

    except ET.ParseError as e:

        raise RuntimeError(
            f"Invalid Nmap XML: {str(e)}"
        )

    for host in root.findall("host"):

        ports = host.find("ports")

        if ports is None:
            continue

        for port in ports.findall("port"):

            state = port.find("state")

            if state is None:
                continue

            state_value = state.get("state")

            # Only return open ports
            if state_value != "open":
                continue

            service = port.find("service")

            service_name = ""
            product = ""
            version = ""

            if service is not None:

                service_name = (
                    service.get("name") or ""
                )

                product = (
                    service.get("product") or ""
                )

                version = (
                    service.get("version") or ""
                )

            results.append({

                "port": int(
                    port.get("portid", 0)
                ),

                "protocol": (
                    port.get("protocol") or ""
                ),

                "state": state_value,

                "service": service_name,

                "product": product,

                "version": version
            })

    return results


def scan_target(target, scan_type="tcp"):
    """
    Scan one target.

    Returns:
        list[dict]
    """

    xml_data = run_nmap(
        target,
        scan_type
    )

    results = parse_nmap_xml(
        xml_data
    )

    return results


def scan_multiple_targets(
    targets,
    scan_type="tcp"
):
    """
    Scan multiple targets.
    """

    all_results = []

    for target in targets:

        target = target.strip()

        if not target:
            continue

        try:

            results = scan_target(
                target,
                scan_type
            )

            all_results.append({
                "target": target,
                "results": results
            })

        except Exception as e:

            all_results.append({
                "target": target,
                "results": [],
                "error": str(e)
            })

    return all_results