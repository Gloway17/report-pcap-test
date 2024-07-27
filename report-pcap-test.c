#include <pcap.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>

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

struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;        /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
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

		struct ethheader *eth = (struct ethheader *)packet;

		if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
			struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 

			if (ip->iph_protocol == IPPROTO_TCP) {
				struct tcpheader *tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + ip->iph_ihl);

				int tcp_header_len = TH_OFF(tcp) * 4;
				char *payload = (char *)(packet + sizeof(struct ethheader) + ip->iph_ihl + tcp_header_len);

				printf("==================================================\n");
				printf("src mac: %o2X:%o2X:%o2X:%o2X:%o2X:%o2X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
				printf("dst mac: %o2X:%o2X:%o2X:%o2X:%o2X:%o2X\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
				printf("\nsrc ip: %s\n", inet_ntoa(ip->iph_sourceip));
				printf("dst ip: %s\n", inet_ntoa(ip->iph_destip));
				printf("\nsrc port: %d\n", ntohs(tcp->tcp_sport));
				printf("dst port: %d\n", ntohs(tcp->tcp_dport));
				printf("\ndata\n");

				int payload_len = header->len - sizeof(struct ethheader) - ip->iph_ihl - tcp_header_len;
				int print_len = payload_len > 20 ? 20 : payload_len; // 출력길이 20byte로 제한

				printf("--------------------------------------------------\n");
            	for (int i = 0; i < print_len; i++) {
                	printf("%c", isprint(payload[i]) ? payload[i] : '.');
				}
				printf("\n");
			}
		}

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
