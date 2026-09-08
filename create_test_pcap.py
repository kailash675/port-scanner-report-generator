from scapy.all import IP, TCP, UDP, ICMP, wrpcap


packets = [

    IP(src="192.168.1.10", dst="192.168.1.20") /
    TCP(sport=1234, dport=80),

    IP(src="192.168.1.10", dst="192.168.1.20") /
    UDP(sport=5000, dport=53),

    IP(src="192.168.1.20", dst="192.168.1.10") /
    ICMP(),

]


wrpcap(
    "test_capture.pcap",
    packets
)

print("test_capture.pcap created successfully!")