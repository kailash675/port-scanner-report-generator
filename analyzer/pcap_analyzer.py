from scapy.all import rdpcap


def analyze_pcap(file_path):

    packets = rdpcap(file_path)

    protocols = {}
    source_ips = set()
    destination_ips = set()

    for packet in packets:

        # IP information
        if packet.haslayer("IP"):

            source_ips.add(
                packet["IP"].src
            )

            destination_ips.add(
                packet["IP"].dst
            )


        # Protocol detection
        if packet.haslayer("TCP"):

            protocol = "TCP"

        elif packet.haslayer("UDP"):

            protocol = "UDP"

        elif packet.haslayer("ICMP"):

            protocol = "ICMP"

        elif packet.haslayer("ARP"):

            protocol = "ARP"

        else:

            protocol = "Other"


        protocols[protocol] = (
            protocols.get(protocol, 0) + 1
        )


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