#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

// A simplified IP header structure
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_id;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

unsigned short calculate_checksum(unsigned short *ptr, int nbytes){
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return(answer);
}

void send_raw_ip_packet(struct ipheader* ip) {
    struct sockaddr_in dest_info;
    int enable = 1;
    
    // create a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // set socket option
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // provide destination information
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // send the packet out
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

void main() {
    char buffer[1500];
    memset(buffer, 0, 1500);

    struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct ipheader));
    icmp->type = ICMP_ECHO; // Echo Request
    icmp->code = 0;
    icmp->un.echo.id = htons(12345);      // Set an arbitrary ID
    icmp->un.echo.sequence = htons(1);  // Set an arbitrary sequence number

    // Calculate the ICMP checksum
    icmp->checksum = 0; // Checksum is calculated with this field set to 0
    icmp->checksum = calculate_checksum((unsigned short *)icmp, sizeof(struct icmphdr));

    struct ipheader *ip = (struct ipheader *)buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 64;
    ip->iph_sourceip.s_addr = inet_addr("10.9.0.6");
    ip->iph_destip.s_addr = inet_addr("8.8.8.8");
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmphdr));

    // Calculate the IP checksum
    ip->iph_chksum = 0; // Checksum is calculated with this field set to 0
    ip->iph_chksum = calculate_checksum((unsigned short *)buffer, sizeof(struct ipheader));

    send_raw_ip_packet(ip);
    printf("Spoofed ICMP packet sent from 10.9.0.6 to 8.8.8.8\n");
}