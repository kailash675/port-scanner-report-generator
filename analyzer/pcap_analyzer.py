from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP


def analyze_pcap(file_path):
    """
    Analyze a PCAP file using Scapy.

    Returns:
        total_packets
        protocols
        source_ips
        destination_ips
    """

    packets = rdpcap(file_path)

    protocols = {}
    source_ips = set()
    destination_ips = set()

    for packet in packets:

        # -----------------------------
        # IP INFORMATION
        # -----------------------------
        if packet.haslayer(IP):

            source_ips.add(
                packet[IP].src
            )

            destination_ips.add(
                packet[IP].dst
            )

        # -----------------------------
        # PROTOCOL DETECTION
        # -----------------------------
        if packet.haslayer(TCP):

            protocol = "TCP"

        elif packet.haslayer(UDP):

            protocol = "UDP"

        elif packet.haslayer(ICMP):

            protocol = "ICMP"

        elif packet.haslayer(ARP):

            protocol = "ARP"

        elif packet.haslayer(IP):

            protocol = "IP"

        else:

            protocol = "Other"

        protocols[protocol] = (
            protocols.get(protocol, 0) + 1
        )

    # -----------------------------
    # RETURN ANALYSIS RESULT
    # -----------------------------
    return {

        "total_packets": len(packets),

        "protocols": protocols,

        "source_ips": sorted(
            source_ips
        ),

        "destination_ips": sorted(
            destination_ips
        )
    }