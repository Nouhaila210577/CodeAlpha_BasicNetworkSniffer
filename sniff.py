from scapy.all import sniff, IP, TCP, UDP, Raw

def analyser_packet(packet):
    if IP in packet:
        print("======== New Packet ========")
        print("Source IP adress     :", packet[IP].src)
        print("Destination IP adress :", packet[IP].dst)

        if TCP in packet:
            print("Protocol : TCP")
            print("Source Port :", packet[TCP].sport)
            print("Destination Port :", packet[TCP].dport)

        elif UDP in packet:
            print("Protocol : UDP")
            print("Source Port      :", packet[UDP].sport)
            print("Destination Port :", packet[UDP].dport)

        else:
            print("Protocol : other")

        if Raw in packet:
            raw_data = packet[Raw].load
            print("Raw payload :", raw_data)
            try:
                text= raw_data.decode("utf-8")
                print("Decoded payload:", text)
            except UnicodeDecodeError:
                print("Payload not decodable as text")
            except Exception as e:
                print("There is another problem with the payload:", e)

        print("\n")

print("Start sniffing ... (Press CTRL+C to stop)")
sniff(prn=analyser_packet, count=10)
print("Capture complete ✅")




