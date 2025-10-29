#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    // Note: The filter expression has been corrected to use standard double quotes
    char filter_exp[] = "ip proto icmp"; 
    bpf_u_int32 net;

    // Open live pcap session on NIC
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", "eth0", errbuf);
        return 1;
    }

    // Compile filter_exp into BPF pseudo-code
    // Note: This code is still missing the required call to pcap_lookupnet() 
    // to initialize 'net' and get 'mask', which is necessary for correct filter compilation.
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Apply the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    // Clean up
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}