#include "function.h"

int main() {

    char* dev = "wlan0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
            fprintf(stderr, "couldn't open device %s: %s (handle)\n", dev, errbuf);
            return -1;
    }

    int size = sizeof(radiotap_header) + sizeof(Dot11);
    u_char beacon_packet[size+1]; //default SSID length = 4
    memset(beacon_packet, 0, size);

    make_beacon_packet(beacon_packet);

    while(1) {

        if(pcap_sendpacket(handle, beacon_packet, sizeof(beacon_packet)) != 0)
            printf("\nError sending the packet(pcap_sendpacket(packet~) \n");
        usleep(10000);

    }
}
