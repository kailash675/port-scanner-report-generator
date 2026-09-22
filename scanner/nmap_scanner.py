import os
import shutil
import subprocess
import xml.etree.ElementTree as ET


def get_nmap_path():
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
        "Nmap executable not found. Please install Nmap."
    )


def is_raw_socket_error(error_message):
    """
    Detect errors caused by missing raw socket/root privileges.
    """

    error = error_message.lower()

    keywords = [
        "couldn't open a raw socket",
        "couldn't open raw socket",
        "operation not permitted",
        "permission denied",
        "requires root",
        "requires privileged",
        "raw socket",
        "you need to be root",
        "failed to open a raw socket"
    ]

    return any(keyword in error for keyword in keywords)


def get_scan_arguments(scan_type):
    """
    Return Nmap arguments for each scan type.
    """

    scan_type = (scan_type or "tcp").lower().strip()

    # Normal TCP Connect Scan
    if scan_type == "tcp":
        return [
            "-sT",
            "-Pn",
            "-T3",
            "-p",
            "1-10000"
        ]

    # UDP Scan
    if scan_type == "udp":
        return [
            "-sU",
            "-Pn",
            "-T3",
            "--top-ports",
            "100"
        ]

    # SYN Scan
    if scan_type == "syn":
        return [
            "-sS",
            "-Pn",
            "-T3",
            "-p",
            "1-10000"
        ]

    # Service / Version Detection
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

    # OS Detection
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

    # Aggressive Scan
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

    # Full Scan
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

    # Default
    return [
        "-sT",
        "-Pn",
        "-T3",
        "-p",
        "1-10000"
    ]


def get_fallback_arguments(scan_type):
    """
    Render-safe fallback scans.
    These avoid raw socket operations.
    """

    scan_type = (scan_type or "tcp").lower().strip()

    # UDP cannot be performed as a true UDP scan
    # without the required privileges on this Render environment.
    if scan_type == "udp":
        return [
            "-sT",
            "-Pn",
            "-T3",
            "--top-ports",
            "100"
        ]

    # SYN -> TCP Connect fallback
    if scan_type == "syn":
        return [
            "-sT",
            "-Pn",
            "-T3",
            "-p",
            "1-10000"
        ]

    # OS detection -> service/version detection fallback
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

    # Aggressive -> service/version detection fallback
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

    # Service/version already uses TCP Connect
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
    Execute Nmap scan.

    Automatically falls back to unprivileged TCP Connect
    scanning when Render/container restrictions prevent
    raw socket operations.
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
            return {
                "xml": stdout,
                "scan_note": None,
                "fallback_used": False
            }

        error_message = stderr.strip() or stdout.strip()

        # -----------------------------------------
        # RAW SOCKET FALLBACK
        # -----------------------------------------
        if is_raw_socket_error(error_message):

            fallback_arguments = get_fallback_arguments(scan_type)

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

            fallback_stdout = fallback_process.stdout or ""
            fallback_stderr = fallback_process.stderr or ""

            if (
                fallback_process.returncode == 0
                and fallback_stdout.strip()
            ):

                if scan_type == "udp":
                    note = (
                        "True UDP scanning requires raw socket privileges "
                        "which are unavailable on this server. "
                        "TCP Connect scanning was used as a fallback."
                    )

                elif scan_type == "syn":
                    note = (
                        "SYN scanning requires raw socket privileges "
                        "which are unavailable on this server. "
                        "TCP Connect scanning was used as a fallback."
                    )

                elif scan_type in [
                    "os",
                    "os_scan",
                    "os_detection"
                ]:
                    note = (
                        "OS detection requires raw socket privileges "
                        "which are unavailable on this server. "
                        "Service/version detection was used as a fallback."
                    )

                elif scan_type in [
                    "aggressive",
                    "aggressive_scan"
                ]:
                    note = (
                        "Aggressive scanning requires privileged "
                        "network operations which are unavailable "
                        "on this server. "
                        "Service/version detection was used as a fallback."
                    )

                else:
                    note = (
                        "The requested scan required privileged "
                        "network operations. "
                        "TCP Connect scanning was used as a fallback."
                    )

                return {
                    "xml": fallback_stdout,
                    "scan_note": note,
                    "fallback_used": True
                }

            fallback_error = (
                fallback_stderr.strip()
                or fallback_stdout.strip()
                or "Fallback Nmap scan failed."
            )

            raise RuntimeError(fallback_error)

        raise RuntimeError(
            error_message or "Nmap scan failed."
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "Nmap scan timed out after 600 seconds."
        )


def parse_nmap_xml(xml_data):
    """
    Parse Nmap XML output.
    """

    results = []

    os_detection = None

    try:
        root = ET.fromstring(xml_data)

    except ET.ParseError as e:
        raise RuntimeError(
            f"Invalid Nmap XML output: {str(e)}"
        )

    # -----------------------------------------
    # HOST INFORMATION
    # -----------------------------------------

    for host in root.findall("host"):

        # OS Detection
        osmatch = host.find(
            "./os/osmatch"
        )

        if osmatch is not None:

            os_name = osmatch.get("name")

            if os_name:
                os_detection = os_name

        # -----------------------------------------
        # PORTS
        # -----------------------------------------

        ports = host.find("ports")

        if ports is None:
            continue

        for port in ports.findall("port"):

            state = port.find("state")

            if state is None:
                continue

            state_value = state.get("state")

            # Include open / open|filtered
            if state_value not in [
                "open",
                "open|filtered"
            ]:
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

    return {
        "ports": results,
        "open_ports": results,
        "total_ports": len(results),
        "os_detection": os_detection
    }


def scan_target(target, scan_type="tcp"):
    """
    Scan a single target.
    """

    scan_output = run_nmap(
        target,
        scan_type
    )

    parsed = parse_nmap_xml(
        scan_output["xml"]
    )

    parsed["target"] = target
    parsed["scan_type"] = scan_type

    parsed["scan_note"] = scan_output.get(
        "scan_note"
    )

    parsed["fallback_used"] = scan_output.get(
        "fallback_used",
        False
    )

    return parsed


def scan_multiple_targets(targets, scan_type="tcp"):
    """
    Scan multiple targets.
    """

    results = []

    for target in targets:

        target = target.strip()

        if not target:
            continue

        try:

            result = scan_target(
                target,
                scan_type
            )

            results.append(result)

        except Exception as e:

            results.append({
                "target": target,
                "scan_type": scan_type,
                "ports": [],
                "open_ports": [],
                "total_ports": 0,
                "os_detection": None,
                "scan_note": str(e),
                "fallback_used": False,
                "error": str(e)
            })

    return results