import argparse

import pyshark as pyk




def get_pcap(pcap):
    capture = pyk.FileCapture(pcap)
    count = 1
    for packet in capture :
        if packet:
            print("Packet Number {} : {}".format(count,packet))
            count+=1
            print("----")

def filter_packets(file_path):
    # Charger le fichier de capture
    capture = pyk.FileCapture(file_path)
    
    for packet in capture:
        try:
            # Filtrer les paquets DNS
            if 'DNS' in packet:
                print(f"DNS Query: {packet.dns.qry_name} from {packet.ip.src} to {packet.ip.dst}")
            # Filtrer les paquets HTTP (inclut HTTP/2.0 comme h2)
            elif 'HTTP' in packet or 'h2' in packet:
                # Pour HTTP/1.x
                if 'HTTP' in packet:
                    http_layer = packet.http
                    print(f"HTTP {http_layer.request_method} {http_layer.request_full_uri}")
                # Pour HTTP/2, les détails peuvent varier
                elif 'h2' in packet:
                    print(f"HTTP/2 Traffic from {packet.ip.src} to {packet.ip.dst}")
        except AttributeError:
            # Certains paquets peuvent ne pas avoir les attributs attendus
            continue
def extract_dns_queries(file_path):
    try:
        # Charger le fichier de capture
        capture = pyk.FileCapture(file_path, display_filter="dns")

        domain_names = set()

        for packet in capture:
            if hasattr(packet.dns, 'qry_name'):
                domain_names.add(packet.dns.qry_name)

        return domain_names
    except Exception as e:
        print(f"An error occurred: {e}")
        return set()


def main():
    parser = argparse.ArgumentParser(description='process a pcap file')
    parser.add_argument('pcap_path', type=str, help='Path to the pcap file')
    args = parser.parse_args()
    #get_pcap(args.pcap_path)
    #filter_packets(args.pcap_path)
    print(extract_dns_queries(args.pcap_path)) # pour la 2.1.1.1  pour voir les domaines résolus


if __name__ == "__main__":
    main()