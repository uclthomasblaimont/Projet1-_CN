import pyshark
import matplotlib.pyplot as plt
from datetime import datetime
import matplotlib.dates as mdates
import argparse


def analyze_doh_requests(file_path):
    # Charger le fichier de capture
    capture = pyshark.FileCapture(file_path, display_filter="tls")

    # Dictionnaire pour stocker le nombre de requêtes DoH par timestamp
    doh_requests = {}

    for packet in capture:
        try:
            # Identifier les paquets TLS qui sont des requêtes DNS sur HTTPS
            # Ceci est une approximation; une vérification plus approfondie pourrait être nécessaire
            # en fonction de la configuration du serveur DoH
            if int(packet.tcp.dstport) == 443 or int(packet.tcp.srcport) == 443:
                timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp))
                timestamp = timestamp.replace(second=0, microsecond=0)  # Arrondir à la minute la plus proche
                if timestamp in doh_requests:
                    doh_requests[timestamp] += 1
                else:
                    doh_requests[timestamp] = 1
        except AttributeError:
            continue

    return doh_requests

def plot_doh_requests(doh_requests):
    # Tri des timestamps
    timestamps = sorted(doh_requests.keys())
    counts = [doh_requests[timestamp] for timestamp in timestamps]

    # Création du graphe
    plt.figure(figsize=(10, 6))
    plt.plot(timestamps, counts, marker='o', linestyle='-', color='b')
    plt.title("Nombre de requêtes DNS sur HTTPS par minute")
    plt.xlabel("Temps")
    plt.ylabel("Nombre de requêtes DNS sur HTTPS")
    plt.xticks(rotation=45)
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
    plt.gca().xaxis.set_major_locator(mdates.MinuteLocator(interval=1))
    plt.gcf().autofmt_xdate()  # Rotation automatique des dates pour une meilleure lisibilité
    plt.tight_layout()
    plt.show()



def main():
    parser = argparse.ArgumentParser(description='process a pcap file')
    parser.add_argument('pcap_path', type=str, help='Path to the pcap file')
    args = parser.parse_args()
    plot_doh_requests(analyze_doh_requests(args.pcap_path))

if __name__ == '__main__':
    main()