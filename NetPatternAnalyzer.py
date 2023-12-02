import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from scapy.all import rdpcap
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.offsetbox import AnchoredText


# Create an empty DataFrame to store packet details
data = {
    'Source IP': [],
    'Destination IP': [],
    'Packet Size': [],
}

def parse_pcap_file(packets):
    for packet in packets:
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            length = packet['IP'].len

            data['Source IP'].append(src_ip)
            data['Destination IP'].append(dst_ip)
            data['Packet Size'].append(length)
        else:
            continue


def show_heatmap(heatmap_status):

    packet_list = []

    for i in range(len(data['Source IP'])):
        src_ip = data['Source IP'][i]
        dst_ip = data['Destination IP'][i]
        packet_size = data['Packet Size'][i]

        packet_list.append([src_ip, dst_ip, packet_size])

    df = pd.DataFrame(packet_list, columns=['src', 'dst', 'length'])

    res = df.pivot_table(index=['src', 'dst'], values='length', aggfunc='sum').reset_index()

    pivot = res.pivot(index='src', columns='dst', values='length')

    if (heatmap_status == True):
        plot_heatmap(pivot, res['src'].nunique(), res['dst'].nunique())


def plot_heatmap(data, unique_src, unique_dst):
    try:

        fig, ax = plt.subplots(figsize=(12, 8))

        sns.heatmap(data,
                    ax=ax,
                    linewidths=.2,
                    fmt="d",
                    square=True,
                    cmap=LinearSegmentedColormap.from_list('gr', ["g", "y", "r"], N=256),
                    cbar_kws={'pad': .02
                              }
                    )

        ax.set_title('Packet Transfer Graph')

        anc = AnchoredText("src = {}, dst = {}".format(unique_src, unique_dst), loc="lower right", frameon=True)
        ax.add_artist(anc)
        ax.set_facecolor('azure')
        bottom, top = plt.ylim()
        bottom += 0.5
        top -= 0.5
        plt.ylim(bottom, top)
        plt.xlabel('Destination')
        plt.ylabel('Source')
        plt.show()
        fig.savefig("packet-transfer-graph.png", bbox_inches="tight")

    except Exception as ex:
        print(ex)


def main():
    file_path = ('../NetPatternAnalyzer/pcap_file/tracefile.pcap')

    HEATMAP_PLOT = True

    # Read the pcap file
    packets = rdpcap(file_path)
    # filtered_packet_list = packets[:100]
    parse_pcap_file(packets)
    show_heatmap(HEATMAP_PLOT)

if __name__ == "__main__":
    main()