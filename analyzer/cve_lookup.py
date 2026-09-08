import requests
import re


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Common Nmap service names -> likely software keywords
SERVICE_KEYWORDS = {
    "ssh": ["openssh"],
    "http": ["apache", "http_server", "nginx", "iis"],
    "https": ["apache", "http_server", "nginx", "iis"],
    "ftp": ["vsftpd", "proftpd", "filezilla", "pure-ftpd"],
    "smtp": ["postfix", "sendmail", "exim"],
    "mysql": ["mysql"],
    "mariadb": ["mariadb"],
    "postgresql": ["postgresql"],
    "rdp": ["rdp", "terminal_services"],
    "telnet": ["telnet"],
}


def clean_text(value):
    if not value:
        return ""

    return str(value).lower().strip()


def version_matches(version, cpe_version):
    """
    Check whether the detected version matches
    the version specified in a CPE.
    """

    if not version or not cpe_version:
        return False

    version = clean_text(version)
    cpe_version = clean_text(cpe_version)

    # Exact match
    if version == cpe_version:
        return True

    # Sometimes Nmap version contains extra information
    # Example:
    # 2.4.7 Ubuntu
    # 2.4.7p1
    detected = re.match(
        r"^[0-9]+(?:\.[0-9]+)*",
        version
    )

    cpe_detected = re.match(
        r"^[0-9]+(?:\.[0-9]+)*",
        cpe_version
    )

    if detected and cpe_detected:
        return detected.group(0) == cpe_detected.group(0)

    return False


def service_matches(service, cpe_product, cpe_vendor=""):
    """
    Check whether the CPE appears related to the
    detected Nmap service.
    """

    service = clean_text(service)
    cpe_product = clean_text(cpe_product)
    cpe_vendor = clean_text(cpe_vendor)

    keywords = SERVICE_KEYWORDS.get(
        service,
        [service]
    )

    for keyword in keywords:

        if keyword in cpe_product:
            return True

        if keyword in cpe_vendor:
            return True

    return False


def extract_cpe_matches(node):
    """
    Recursively extract CPE match information
    from NVD configuration nodes.
    """

    matches = []

    if not isinstance(node, dict):
        return matches

    for match in node.get("cpeMatch", []):

        criteria = match.get(
            "criteria",
            ""
        )

        vulnerable = match.get(
            "vulnerable",
            True
        )

        matches.append({
            "criteria": criteria,
            "vulnerable": vulnerable,
            "versionStartIncluding":
                match.get("versionStartIncluding"),
            "versionStartExcluding":
                match.get("versionStartExcluding"),
            "versionEndIncluding":
                match.get("versionEndIncluding"),
            "versionEndExcluding":
                match.get("versionEndExcluding")
        })

    for child in node.get("children", []):

        matches.extend(
            extract_cpe_matches(child)
        )

    return matches


def parse_cpe(cpe):
    """
    Parse a CPE 2.3 string.

    Example:
    cpe:2.3:a:apache:http_server:2.4.7:...
    """

    parts = cpe.split(":")

    if len(parts) < 6:
        return "", "", ""

    vendor = parts[3]
    product = parts[4]
    version = parts[5]

    return vendor, product, version


def version_in_range(
    version,
    start_including=None,
    start_excluding=None,
    end_including=None,
    end_excluding=None
):
    """
    Basic numeric version-range comparison.
    """

    def normalize(value):

        if not value:
            return ()

        numbers = re.findall(
            r"\d+",
            str(value)
        )

        return tuple(
            int(number)
            for number in numbers
        )

    detected = normalize(version)

    if not detected:
        return False

    if start_including:
        if detected < normalize(start_including):
            return False

    if start_excluding:
        if detected <= normalize(start_excluding):
            return False

    if end_including:
        if detected > normalize(end_including):
            return False

    if end_excluding:
        if detected >= normalize(end_excluding):
            return False

    return True


def lookup_cves(service, version="", limit=5):

    if not service:
        return []

    service = service.strip()

    if not service:
        return []

    version = version.strip()


    # -----------------------------------------------------
    # Without a detected version, don't make broad CVE
    # claims.
    # -----------------------------------------------------

    if not version:
        return []


    keyword = service

    if version:
        keyword = f"{service} {version}"


    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20
    }


    try:

        response = requests.get(
            NVD_API_URL,
            params=params,
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = []


        for item in data.get(
            "vulnerabilities",
            []
        ):

            cve = item.get(
                "cve",
                {}
            )


            # -------------------------------------------------
            # Extract CPE configurations
            # -------------------------------------------------

            configurations = cve.get(
                "configurations",
                []
            )


            matched = False


            for configuration in configurations:

                nodes = configuration.get(
                    "nodes",
                    []
                )


                for node in nodes:

                    cpe_matches = (
                        extract_cpe_matches(node)
                    )


                    for cpe_match in cpe_matches:

                        criteria = cpe_match[
                            "criteria"
                        ]


                        if not cpe_match[
                            "vulnerable"
                        ]:
                            continue


                        vendor, product, cpe_version = (
                            parse_cpe(criteria)
                        )


                        # Service must resemble
                        # the CPE product/vendor.
                        if not service_matches(
                            service,
                            product,
                            vendor
                        ):
                            continue


                        # Exact detected version
                        if cpe_version not in (
                            "",
                            "*",
                            "-"
                        ):

                            if version_matches(
                                version,
                                cpe_version
                            ):

                                matched = True
                                break


                        # Version range
                        if cpe_version in (
                            "*",
                            "-"
                        ):

                            if version_in_range(
                                version,
                                cpe_match[
                                    "versionStartIncluding"
                                ],
                                cpe_match[
                                    "versionStartExcluding"
                                ],
                                cpe_match[
                                    "versionEndIncluding"
                                ],
                                cpe_match[
                                    "versionEndExcluding"
                                ]
                            ):

                                matched = True
                                break


                    if matched:
                        break

                if matched:
                    break


            # -------------------------------------------------
            # Ignore unrelated CVEs
            # -------------------------------------------------

            if not matched:
                continue


            # -------------------------------------------------
            # CVE ID
            # -------------------------------------------------

            cve_id = cve.get(
                "id",
                ""
            )


            # -------------------------------------------------
            # Description
            # -------------------------------------------------

            descriptions = cve.get(
                "descriptions",
                []
            )


            description = ""


            for desc in descriptions:

                if desc.get("lang") == "en":

                    description = desc.get(
                        "value",
                        ""
                    )

                    break


            # -------------------------------------------------
            # CVSS
            # -------------------------------------------------

            severity = "UNKNOWN"
            score = None


            metrics = cve.get(
                "metrics",
                {}
            )


            if metrics.get(
                "cvssMetricV40"
            ):

                metric = metrics[
                    "cvssMetricV40"
                ][0]


                cvss_data = metric.get(
                    "cvssData",
                    {}
                )


                score = cvss_data.get(
                    "baseScore"
                )


                severity = cvss_data.get(
                    "baseSeverity",
                    "UNKNOWN"
                )


            elif metrics.get(
                "cvssMetricV31"
            ):

                metric = metrics[
                    "cvssMetricV31"
                ][0]


                cvss_data = metric.get(
                    "cvssData",
                    {}
                )


                score = cvss_data.get(
                    "baseScore"
                )


                severity = cvss_data.get(
                    "baseSeverity",
                    "UNKNOWN"
                )


            elif metrics.get(
                "cvssMetricV30"
            ):

                metric = metrics[
                    "cvssMetricV30"
                ][0]


                cvss_data = metric.get(
                    "cvssData",
                    {}
                )


                score = cvss_data.get(
                    "baseScore"
                )


                severity = cvss_data.get(
                    "baseSeverity",
                    "UNKNOWN"
                )


            # -------------------------------------------------
            # Add result
            # -------------------------------------------------

            vulnerabilities.append({

                "cve_id": cve_id,

                "severity": severity,

                "score": score,

                "description": description

            })


            # Stop at requested limit
            if len(vulnerabilities) >= limit:
                break


        return vulnerabilities


    except requests.RequestException:

        return []


    except Exception:

        return []