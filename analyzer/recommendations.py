def generate_recommendations(results):
    recommendations = []

    for result in results:
        port = result["port"]
        service = result["service"]
        state = result["state"]

        if state != "open":
            continue

        if port == 21:
            recommendations.append(
                "FTP (Port 21) is open. Consider using SFTP or FTPS "
                "for secure file transfers."
            )

        elif port == 22:
            recommendations.append(
                "SSH (Port 22) is open. Use strong authentication, "
                "disable password login where possible, and restrict access."
            )

        elif port == 23:
            recommendations.append(
                "Telnet (Port 23) is open. Telnet is insecure; "
                "replace it with SSH."
            )

        elif port == 80:
            recommendations.append(
                "HTTP (Port 80) is open. Consider using HTTPS "
                "to protect web traffic."
            )

        elif port == 445:
            recommendations.append(
                "SMB (Port 445) is open. Restrict access to trusted "
                "networks and keep the service updated."
            )

        elif port == 3306:
            recommendations.append(
                "MySQL (Port 3306) is open. Avoid exposing database "
                "services directly to untrusted networks."
            )

        elif port == 3389:
            recommendations.append(
                "RDP (Port 3389) is open. Restrict access and use "
                "strong authentication."
            )

        else:
            recommendations.append(
                f"Port {port} ({service}) is open. Verify that this "
                "service is required and restrict access if unnecessary."
            )

    if not recommendations:
        recommendations.append(
            "No basic security recommendations were generated."
        )

    return recommendations