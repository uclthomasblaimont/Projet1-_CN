import argparse

import pyshark as pyk
import matplotlib.pyplot as plt




def get_pcap(pcap):
    capture = pyk.FileCapture(pcap)
    count = 1
    for packet in capture :
        if packet:
            print("Packet Number {} : {}".format(count,packet))
            count+=1
            print("----")

def filter_packets(file_path):
    # Charge le fichier de capture
    capture = pyk.FileCapture(file_path)
    
    for packet in capture:
        try:
       
            if 'DNS' in packet:
                print(f"DNS Query: {packet.dns.qry_name} from {packet.ip.src} to {packet.ip.dst}")
          
            elif 'HTTP' in packet or 'h2' in packet:
        
                if 'HTTP' in packet:
                    http_layer = packet.http
                    print(f"HTTP {http_layer.request_method} {http_layer.request_full_uri}")
            
                elif 'h2' in packet:
                    print(f"HTTP/2 Traffic from {packet.ip.src} to {packet.ip.dst}")
        except AttributeError:
            
            continue

#fonction pour les domaines résolus
def extract_dns_queries(file_path):
    try:
       
        capture = pyk.FileCapture(file_path, display_filter="dns")

        domain_names = set()

        for packet in capture:
            if hasattr(packet.dns, 'qry_name'):
                domain_names.add(packet.dns.qry_name)

        print("la longueur du set est de {}".format(len(domain_names)))

        return domain_names
    except Exception as e:
        print(f"An error occurred: {e}")
        return set()
    
#pour la question avec les requêtes dns
def extract_authoritative_servers(file_path):
    try:
     
        capture = pyk.FileCapture(file_path, display_filter="dns.flags.response == 1")

        authoritative_servers = set()

        for packet in capture:
            
            if int(packet.dns.count_auth_rr) > 0:
                for i in range(int(packet.dns.count_auth_rr)):
                
                    authoritative_server = packet.dns.get_field_value(f'auth_ns{i}_name')
                    authoritative_servers.add(authoritative_server)

        return authoritative_servers
    except Exception as e:
        print(f"An error occurred: {e}")
        return set()


def count_dns_query_types(file_path):
    capture = pyk.FileCapture(file_path, display_filter="dns")

    query_types = {
        1: "A (IPv4 address)",
        28: "AAAA (IPv6 address)",
        15: "MX (Mail Exchange)",
        2: "NS (Name Server)",
        16: "TXT (Text Record)"
    }

    count = {type: 0 for type in query_types.values()}

    for packet in capture:
        if hasattr(packet.dns, 'qry_type'):
            qry_type = int(packet.dns.qry_type)
            if qry_type in query_types:
                count[query_types[qry_type]] += 1

    return count

def check_additional_records(file_path):
    capture = pyk.FileCapture(file_path, display_filter="dns")
    count_additional_packets = 0
    for packet in capture:
        if "DNS" in packet:

            # si le paquet DNS a des enregistrements supplémentaires
            if int(packet.dns.count_add_rr) > 0:
                print(f"Paquet DNS avec enregistrements supplémentaires trouvé : {packet.number}")
                print(f"Nombre d'enregistrements supplémentaires : {packet.dns.count_add_rr}")
                # Affiche des informations sur chaque enregistrement supplémentaire
                for i in range(int(packet.dns.count_add_rr)):
                    count_additional_packets+=1
                    print(f"Enregistrement supplémentaire {i+1}: {packet.dns.get_field_value(f'add_rr{i}_name')}")
                print("----------")
    return  count_additional_packets






def plot_dns_query_types(query_type_counts):
        labels = list(query_type_counts.keys())
        values = list(query_type_counts.values())

        plt.figure(figsize=(10, 6))
        plt.bar(labels, values, color='skyblue')
        plt.xlabel('Type de Requête DNS')
        plt.ylabel('Nombre de Requêtes')
        plt.title('Nombre de Requêtes DNS par Type')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()



def main():
    parser = argparse.ArgumentParser(description='process a pcap file')
    parser.add_argument('pcap_path', type=str, help='Path to the pcap file')
    args = parser.parse_args()
    #get_pcap(args.pcap_path)
    filter_packets(args.pcap_path)
    print(extract_dns_queries(args.pcap_path)) # pour la 2.1.1.1  pour voir les domaines résolus
    #print(extract_authoritative_servers(args.pcap_path))
    #print(count_dns_query_types(args.pcap_path)) # pour la 2.1.1.3
    #plot_dns_query_types(count_dns_query_types(args.pcap_path))
    #print(check_additional_records(args.pcap_path))
    #print_dns_packet_details(args.pcap_path)



if __name__ == "__main__":
    main()