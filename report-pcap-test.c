#include <pcap.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "libnet-headers.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;

		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);

		struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet;
		if (ntohs(eth->ether_type) == 0x0800) {
			struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));

			if (ntohs(ip->ip_p) == 0x06) {
				struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(ip + sizeof(struct libnet_ipv4_hdr));

				char* data = (char *)(tcp + sizeof(struct libnet_tcp_hdr));
			}
		}

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//printf("%u bytes captured\n", header->caplen);
		printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
		printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
		printf("src ip: %s\n", inet_ntoa(ip->ip_src));
		printf("dst ip: %s\n", inet_ntoa(ip->ip_dst));
		printf("src port: %d\n", ntohs(tcp->th_sport));
		printf("dst port: %d\n", ntohs(tcp->th_dport));
		printf("data\n");
	}

	pcap_close(pcap);
}
