from scapy.all import IP, TCP 
from SigAnomIDS import IDS


def train_model(ids):
    
    samples = []

    for i in range(70):
        samples.append([
            60 + (i % 20),
            10 + (i % 30),
            800 + (i %200)
        ])

    ids.detect_sys.train_AnomDet(samples)
    print("IDS model trained")


def Test():

    ids = IDS()

    train_model(ids)

    # Create test packets to simulate various scenarios 

    packets = [

        # Create Normal network traffic 
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=89, flags="A"),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="P"),


        # Create a syn flood attack
        IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="192.168.1.2") / TCP(sport=5679, dport=80, flags="S"),
        IP(src="10.0.0.3", dst="192.168.1.2") / TCP(sport=5680, dport=80, flags="S"),
        IP(src="10.0.0.4", dst="192.168.1.2") / TCP(sport=5681, dport=80, flags="S"),

        # Port scanning traffic
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S"),
    ]


    # Create simulation processing for packet sniffing and threat detection 

    print("Initializing IDS testing...")

    for i, packet in enumerate(packets, 1):
        print(f"\n\nPacket {i} is being processed: {packet.summary()}")

        packet_features = ids.traffic_analy.pack_analysis(packet)

        if packet_features:
            threats = ids.detect_sys.threat_detection(packet_features)

            if threats:
                print(f"Detecteed Threats: {threats}")
            else:
                print(f"No threates detected.")
        else:
            print("packet does not contain IP/TCP layers or is ignored.")

    print("\n\n Intrustion Detection System Completed")


if __name__ == "__main__":
    Test()

