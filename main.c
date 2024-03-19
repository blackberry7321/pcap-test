#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define IP_HEADER_LEN 4
#define TCP_HEADER_OFFSET   4

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};
struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
        ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
        ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int8_t ip_src[IP_HEADER_LEN], ip_dst[IP_HEADER_LEN]; /* source and dest address */
};
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
        th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
        th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

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
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr *eth_hdr = packet;
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;
        printf("type = %04x\n", ntohs(eth_hdr->ether_type));
        uint8_t *smac = eth_hdr->ether_shost;
        uint8_t *dmac = eth_hdr->ether_dhost;
        printf("source mac : %02x:%02x:%02x:%02x:%02x:%02x\n", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
        printf("destination mac : %02x:%02x:%02x:%02x:%02x:%02x\n", dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]);

        struct libnet_ipv4_hdr *ip_hdr = packet + sizeof(struct libnet_ethernet_hdr);
        if (ip_hdr->ip_p != IPPROTO_TCP) continue;
        printf("proto = %d\n", ip_hdr->ip_p);
        u_int8_t *src_ip = ip_hdr->ip_src;
        u_int8_t *dst_ip = ip_hdr->ip_dst;
        printf("source ip : %d.%d.%d.%d\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        printf("destination ip : %d.%d.%d.%d\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);

        struct libnet_tcp_hdr *tcp_hdr = packet + sizeof(struct libnet_ethernet_hdr) + IP_HEADER_LEN * 5;
        uint16_t src_port = tcp_hdr->th_sport;
        uint16_t dst_port = tcp_hdr->th_dport;
        printf("source port : %d\n", ntohs(src_port));
        printf("destination port : %d\n", ntohs(dst_port));

        printf("Payload(Data) : ");
        uint32_t hsize = sizeof(struct libnet_ethernet_hdr) + IP_HEADER_LEN*4 + TCP_HEADER_OFFSET*4;
        uint32_t payload_len = header->caplen - hsize;
        for (int i = 0; i < (payload_len < 10 ? payload_len : 10); i++) {
            printf("0x%02X ", packet[hsize + i]);
        }
        for (int i = payload_len; i < 10; i++) {
            printf("0x00 ");
        }
        printf("\n");

        printf("\n");

    }

    pcap_close(pcap);
}
