import subprocess
import shutil
import xml.etree.ElementTree as ET


# ============================================================
# NMAP PATH
# ============================================================

def find_nmap():
    """
    Find Nmap executable automatically.
    """

    nmap_path = shutil.which("nmap")

    if nmap_path:
        return nmap_path

    # Windows default installation path
    windows_paths = [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe"
    ]

    for path in windows_paths:
        try:
            with open(path, "r"):
                pass
            return path
        except Exception:
            continue

    raise FileNotFoundError(
        "Nmap was not found. Please install Nmap."
    )


# ============================================================
# NMAP COMMAND BUILDER
# ============================================================

def build_command(target, scan_type):
    """
    Build Nmap command according to selected scan mode.
    """

    nmap = find_nmap()

    scan_type = str(scan_type or "tcp").lower().strip()

    base = [
        nmap,
        "-Pn",
        "-T3"
    ]

    # --------------------------------------------------------
    # TCP SCAN
    # --------------------------------------------------------

    if scan_type == "tcp":
        return base + [
            "-sT",
            "-sV",
            "-p",
            "1-10000",
            target
        ]

    # --------------------------------------------------------
    # UDP SCAN
    # --------------------------------------------------------

    elif scan_type == "udp":
        return base + [
            "-sU",
            "-sV",
            "--top-ports",
            "100",
            target
        ]

    # --------------------------------------------------------
    # SYN SCAN
    # --------------------------------------------------------

    elif scan_type == "syn":
        return base + [
            "-sS",
            "-sV",
            "-p",
            "1-10000",
            target
        ]

    # --------------------------------------------------------
    # SERVICE VERSION DETECTION
    # --------------------------------------------------------

    elif scan_type in [
        "service",
        "service_detection",
        "version",
        "version_detection"
    ]:
        return base + [
            "-sV",
            "-p",
            "1-10000",
            target
        ]

    # --------------------------------------------------------
    # OS DETECTION
    # --------------------------------------------------------

    elif scan_type in [
        "os",
        "os_scan",
        "os_detection"
    ]:
        return base + [
            "-O",
            "-sV",
            "-p",
            "1-1000",
            target
        ]

    # --------------------------------------------------------
    # AGGRESSIVE SCAN
    # --------------------------------------------------------

    elif scan_type in [
        "aggressive",
        "aggressive_scan"
    ]:
        return base + [
            "-A",
            "-p",
            "1-10000",
            target
        ]

    # --------------------------------------------------------
    # FULL PORT SCAN
    # --------------------------------------------------------

    elif scan_type in [
        "full",
        "full_scan"
    ]:
        return base + [
            "-sT",
            "-sV",
            "-p-",
            target
        ]

    # --------------------------------------------------------
    # INVALID SCAN TYPE
    # --------------------------------------------------------

    else:
        raise ValueError(
            f"Unsupported scan type: {scan_type}"
        )


# ============================================================
# XML PARSER
# ============================================================

def parse_nmap_xml(xml_data):
    """
    Parse Nmap XML output.
    """

    results = []

    try:
        root = ET.fromstring(xml_data)

    except ET.ParseError as e:
        raise RuntimeError(
            f"Unable to parse Nmap XML output: {e}"
        )

    # --------------------------------------------------------
    # PORT RESULTS
    # --------------------------------------------------------

    for host in root.findall("host"):

        ports = host.find("ports")

        if ports is not None:

            for port in ports.findall("port"):

                state = port.find("state")

                if state is None:
                    continue

                state_value = state.get(
                    "state",
                    ""
                )

                # Only show reachable/open states
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
                        service.get("name", "")
                    )

                    product = (
                        service.get("product", "")
                    )

                    version = (
                        service.get("version", "")
                    )

                # Build readable version
                version_text = version

                if product and version:
                    version_text = (
                        f"{product} {version}"
                    )

                elif product:
                    version_text = product

                results.append({
                    "port": int(
                        port.get("portid", 0)
                    ),
                    "protocol": port.get(
                        "protocol",
                        ""
                    ),
                    "state": state_value,
                    "service": service_name,
                    "version": version_text
                })

        # ----------------------------------------------------
        # OS DETECTION
        # ----------------------------------------------------

        os_section = host.find("os")

        if os_section is not None:

            os_matches = os_section.findall(
                "osmatch"
            )

            if os_matches:

                os_match = os_matches[0]

                os_name = os_match.get(
                    "name",
                    "Unknown"
                )

                accuracy = os_match.get(
                    "accuracy",
                    ""
                )

                # Attach OS information to first result
                # if a port result exists.
                if results:

                    results[0][
                        "os_detection"
                    ] = {
                        "name": os_name,
                        "accuracy": accuracy
                    }

    return results


# ============================================================
# SINGLE TARGET SCAN
# ============================================================

def scan_target(
    target,
    scan_type="tcp"
):
    """
    Scan one target using selected Nmap scan mode.
    """

    if not target:
        raise ValueError(
            "Target is required"
        )

    command = build_command(
        target,
        scan_type
    )

    # IMPORTANT:
    # Force Nmap to return XML output to stdout.
    # Without this, Nmap returns normal text output
    # and XML parser will fail.
    command += [
        "-oX",
        "-"
    ]

    print(
        "\n[NMAP] Starting scan"
    )

    print(
        "[NMAP] Target:",
        target
    )

    print(
        "[NMAP] Scan type:",
        scan_type
    )

    print(
        "[NMAP] Command:",
        " ".join(command)
    )

    try:

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600
        )

    except subprocess.TimeoutExpired:

        raise RuntimeError(
            "Nmap scan timed out after 600 seconds."
        )

    except FileNotFoundError:

        raise RuntimeError(
            "Nmap executable was not found."
        )

    except Exception as e:

        raise RuntimeError(
            f"Failed to execute Nmap: {e}"
        )

    # --------------------------------------------------------
    # ERROR CHECK
    # --------------------------------------------------------

    if process.returncode != 0:

        error_message = (
            process.stderr.strip()
            or process.stdout.strip()
            or "Unknown Nmap error"
        )

        raise RuntimeError(
            f"Nmap scan failed: {error_message}"
        )

    # --------------------------------------------------------
    # PARSE XML
    # --------------------------------------------------------

    xml_output = process.stdout.strip()

    if not xml_output:

        raise RuntimeError(
            "Nmap returned empty XML output."
        )

    # Make sure Nmap actually returned XML
    if not xml_output.startswith("<?xml"):

        raise RuntimeError(
            "Nmap returned invalid XML output."
        )

    return parse_nmap_xml(
        xml_output
    )
    
    # --------------------------------------------------------
    # ERROR CHECK
    # --------------------------------------------------------

    if process.returncode != 0:

        error_message = (
            process.stderr.strip()
            or process.stdout.strip()
            or "Unknown Nmap error"
        )

        raise RuntimeError(
            f"Nmap scan failed: {error_message}"
        )

    # --------------------------------------------------------
    # PARSE XML
    # --------------------------------------------------------

    xml_output = process.stdout.strip()

    if not xml_output:

        return []

    return parse_nmap_xml(
        xml_output
    )


# ============================================================
# MULTIPLE TARGET SCAN
# ============================================================

def scan_multiple_targets(
    targets,
    scan_type="tcp"
):
    """
    Scan multiple authorized targets.
    """

    if not isinstance(
        targets,
        list
    ):

        raise ValueError(
            "Targets must be a list."
        )

    all_results = []

    for target in targets:

        target = str(
            target
        ).strip()

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