#ifndef HOON_HEADER_H
#define HOON_HEADER_H

#include <pcap.h>
#include <netinet/ip.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>
#include <thread>

#define ETH_LEN 6
#define ETHERTYPE_ARP 0x0806
#define ETHTYPE 0x0001
#define IP_LEN 4
#define PROTOTYPE_IP 0x0800
#define REQUEST 0x0001
#define REPLY 0x0002

#pragma pack(push, 1)
typedef struct{
    uint8_t dst[ETH_LEN];
    uint8_t src[ETH_LEN];
    u_short type;

}eth_hdr;
#define SIZE_ETH (sizeof(eth_hdr))

typedef struct{
    uint16_t Htype;
    uint16_t Ptype;

    uint8_t H_add_len;
    uint8_t P_add_len;

    uint16_t Opcode;

    uint8_t Smac[6];
    uint8_t SIP[4];

    uint8_t Tmac[6];
    uint8_t TIP[4];
}arp_hdr;
#define SIZE_ARP (sizeof(arp_hdr))

typedef struct{
    eth_hdr eth;
    arp_hdr ath;
}arp_packet;
#define SIZE_ARP_PACKET (sizeof(arp_packet))

typedef struct{
    uint8_t My_mac[6];
    uint8_t My_IP[4];

    uint8_t Sender_mac[6];
    uint8_t Sender_IP[4];

    uint8_t Target_mac[6];
    uint8_t Target_IP[4];
}addr_info;
#pragma pack(pop)

arp_packet *Make_Arp_Packet(addr_info info, uint8_t *ip);
arp_packet *Make_Infected_Packet(eth_hdr *eth2, arp_hdr *ath2, addr_info info);
void myinfoset(char *dev, uint8_t *ipstr, uint8_t *macstr, uint8_t *netmask);
void divide(uint8_t *dst, char *ar);
void Get_Res(pcap_t* handle, addr_info info, uint8_t *ip);
void Relay(pcap_t* handle, arp_packet *Ipacket, addr_info info, int i);
void printPacket(arp_packet *packet);
void printInfo(addr_info info);
void ThreadF(char *dev, addr_info info, char **argv, int i);

char ip1[4];
char ip2[4];

#endif // HOON_HEADER_H
