import argparse
import socket

import pyshark as pyk
import matplotlib.pyplot as plt
from collections import defaultdict


def get_pcap(pcap):
    capture = pyk.FileCapture(pcap)
    count = 1
    for packet in capture:
        if packet:
            print("Packet Number {} : {}".format(count, packet))
            count += 1
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


# fonction pour les domaines résolus
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


# pour la question avec les requêtes dns
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
                    count_additional_packets += 1
                    print(f"Enregistrement supplémentaire {i + 1}: {packet.dns.get_field_value(f'add_rr{i}_name')}")
                print("----------")
    return count_additional_packets


# pour la question 2.1.2.2:
def analyse_dns_requests(file_path):
    # Filtre pour capturer à la fois les requêtes et les réponses DNS avec les adresses IPV4 et IPV6
    filter_str = 'dns && (ip.addr == 192.168.1.61 || ipv6.addr == 2a02:a03f:c028:e00:75eb:339e:53dc:eb6) && (dns.flags.response == 1 || dns.flags.response == 0)'

    try:
        capture = pyk.FileCapture(file_path, display_filter=filter_str)

        for packet in capture:
            # Vérifie si le paquet est une requête DNS ou une réponse
            if 'DNS' in packet:
                is_response = packet.dns.flags_response.lower() == '1'
                request_or_response = "Response" if is_response else "Request"
                src_addr = packet.ip.src if 'IP' in packet else packet.ipv6.src
                dst_addr = packet.ip.dst if 'IP' in packet else packet.ipv6.dst
                print(f"DNS {request_or_response} from {src_addr} to {dst_addr}")

                if not is_response:
                    print(f"\tQueried Host: {packet.dns.qry_name}")
                else:
                    # Dans une réponse, il peut y avoir plusieurs réponses (answers)
                    count_answers = int(packet.dns.count_answers) if packet.dns.count_answers.isdigit() else 0
                    for i in range(1, count_answers + 1):
                        answer = getattr(packet.dns, f"resp_{i}", "N/A")
                        print(f"\tAnswer {i}: {answer}")

    except Exception as e:
        print(f"Error reading capture file: {e}")


# pour la question 2.1.2.2
def get_domain_names_from_pcap(file_path):
    capture = pyk.FileCapture(file_path)
    ip_addresses = set()

    # Extraire toutes les adresses IP uniques à partir des paquets
    for packet in capture:
        try:
            if 'IP' in packet:
                ip_addresses.add(packet.ip.src)
                ip_addresses.add(packet.ip.dst)
            elif 'IPv6' in packet:
                ip_addresses.add(packet.ipv6.src)
                ip_addresses.add(packet.ipv6.dst)
        except AttributeError:
            continue

    # Pour chaque adresse IP unique, effectuer une résolution DNS inverse
    for ip in ip_addresses:
        try:
            name, alias, addresslist = socket.gethostbyaddr(ip)
            print(f"{ip} résolu en {name}")
        except (socket.herror, socket.gaierror):
            print(f"Le nom de domaine pour {ip} n'a pas pu être trouvé")


def analyze_tls_versions(pcap_file):
    capture = pyk.FileCapture(pcap_file, display_filter="tls")

    tls_versions = {}

    for packet in capture:

        try:



            if hasattr(packet.tls, 'handshake_version'):

                version = packet.tls.handshake_version

            elif hasattr(packet.tls, 'record_version'):

                version = packet.tls.record_version

            elif hasattr(packet.tls, 'version'):

                version = packet.tls.version

            else:

                continue

            if version in tls_versions:

                tls_versions[version] += 1

            else:

                tls_versions[version] = 1

        except AttributeError:

            continue

    return tls_versions


def analyze_tls_certificates(pcap_file):
    try:
        capture = pyk.FileCapture(pcap_file, display_filter="tls.handshake.type == 11")
        for packet in capture:
            if hasattr(packet.tls, 'handshake_certificate'):
                cert_data = packet.tls.handshake_certificate
                # Ici, on tenterait d'extraire et de décoder les informations du certificat.
                # Cependant, pyshark ne fournit pas directement un accès facile aux données du certificat telles que l'émetteur ou les dates de validité.
                # Une analyse plus poussée et détaillée nécessiterait un accès aux données binaires du certificat et leur décodage avec une bibliothèque adaptée.
                print(f"Certificate data: {cert_data}")

                # Pour les dates de validité et l'émetteur, un traitement supplémentaire serait nécessaire,
                # possiblement en utilisant une autre bibliothèque pour lire et décoder les informations du certificat.

    except Exception as e:
        print(f"An error occurred: {e}")


def extract_cipher_suites(pcap_file):
    capture = pyk.FileCapture(pcap_file, display_filter="tls")
    cipher_suites = {}
    for packet in capture:
        try:
            # Vérifier si le paquet est un handshake TLS et contient la suite de chiffrement
            if 'TLS' in packet and hasattr(packet.tls, 'handshake_ciphersuite'):
                cipher_suite = packet.tls.handshake_ciphersuite
                if cipher_suite in cipher_suites:
                    cipher_suites[cipher_suite] += 1
                else:
                    cipher_suites[cipher_suite] = 1
        except AttributeError:
            # Gérer le cas où l'attribut n'est pas trouvé
            continue
    return cipher_suites


def analyze_connection_trace(pcap_file):
    capture = pyk.FileCapture(pcap_file)

    for packet in capture:
        # Analyser le flux de connexion et les protocoles utilisés
        if 'TLS' in packet or 'SSL' in packet:
            print(f"TLS/SSL Packet: {packet}")
        if 'HTTP' in packet:
            print(f"HTTP Packet: {packet.http.request_method} {packet.http.host} {packet.http.request_uri}")
        # Et ainsi de suite pour d'autres analyses...


def generate_domain_graph(pcap_path):
    #doit filtrer les domaines qui sont en lien avec Dropbox
    capture = pyk.FileCapture(pcap_path, display_filter="dns")

    # Dictionnaire pour stocker les noms de domaine et les adresses IP associées
    domain_addresses = defaultdict(set)

    for packet in capture:
        try:
            # Convertir la réponse DNS en booléen (True pour réponse, False pour requête)
            is_response = packet.dns.flags_response.lower() == '1' or packet.dns.flags_response.lower() == 'true'

            if not is_response:  # Si c'est une requête
                domain_name = packet.dns.qry_name
                if domain_name:
                    domain_addresses[domain_name].add(packet.ip.src)
            else:  # Si c'est une réponse
                for i in range(int(packet.dns.count_answers)):
                    answer = packet.dns.get_field_value(f"resp{i + 1}_name")
                    if answer:
                        domain_addresses[answer].add(packet.ip.dst)
        except AttributeError:
            continue

    # Préparation des données pour le graphe
    domains = list(domain_addresses.keys())
    counts = [len(addresses) for addresses in domain_addresses.values()]

    # Générer le graphe
    plt.figure(figsize=(10, 8))
    plt.barh(domains, counts, color='skyblue')
    plt.xlabel('Nombre d\'adresses IP uniques')
    plt.ylabel('Noms de domaine')
    plt.title('Nombre d\'adresses IP uniques par nom de domaine')
    plt.tight_layout()
    plt.show()


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


def plot_tls_usage(tls_versions):
    # Mapping the TLS versions to more understandable names
    tls_version_names = {'0x1301': 'TLSv1.3', '0xc02f': 'TLSv1.2 '}

    # Extracting the version names and counts
    labels = [tls_version_names.get(version, "Unknown") for version in tls_versions.keys()]
    values = list(tls_versions.values())

    # Creating the plot
    plt.figure(figsize=(8, 6))
    plt.bar(labels, values, color=['blue', 'orange'])

    # Adding the title and labels
    plt.title('Algo de chiffrement')
    plt.xlabel('TLS Versions et Cipher Suites')
    plt.ylabel('Count')

    # Showing the plot
    plt.show()

def main():
    parser = argparse.ArgumentParser(description='process a pcap file')
    parser.add_argument('pcap_path', type=str, help='Path to the pcap file')
    args = parser.parse_args()
    # print(get_pcap(args.pcap_path))
    # filter_packets(args.pcap_path)
    # (extract_dns_queries(args.pcap_path)) # pour la 2.1.1.1  pour voir les domaines résolus
    # print(extract_authoritative_servers(args.pcap_path))
    # print(count_dns_query_types(args.pcap_path)) # pour la 2.1.1.3
    # plot_dns_query_types(count_dns_query_types(args.pcap_path))
    # print(check_additional_records(args.pcap_path))
    # analyse_dns_requests(args.pcap_path)
    # get_domain_names_from_pcap(args.pcap_path)
    # generate_domain_graph(args.pcap_path)
    #(analyze_tls_versions(args.pcap_path)
    #analyze_tls_certificates(args.pcap_path)
    #print(extract_cipher_suites(args.pcap_path))
    #plot_tls_usage(extract_cipher_suites(args.pcap_path))
    analyze_connection_trace(args.pcap_path)

if __name__ == "__main__":
    main()
