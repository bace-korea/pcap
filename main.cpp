#include <pcap.h>
#include <stdio.h>

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

class LAWS
{

public:

    int money;
    void print_mac(u_int8_t *mac)
    {
        printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        int ip=(packet[12]<<8)|packet[13];
        int ip_h=(((packet[14])&0x0F)*4);
        int port_t=packet[23];
        int tcp_h=((((packet[26+ip_h])&0xF0)>>4)*4);
        int http=(packet[16+ip_h]<<8)|packet[17+ip_h];

        if(ip == 0x0800){           
            if(port_t==0x06){
                if(http==80){
                    printf("Type : IPv4\n");
                    printf(" Type : TCP\n");
                    printf(" Port : %d\n", http);
                    printf("  Source MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
                    printf("  Destination MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
                    printf("  Source IP : %u.%u.%u.%u\n", packet[26],packet[27],packet[28],packet[29]);
                    printf("  Destination IP : %u.%u.%u.%u\n", packet[30],packet[31],packet[32],packet[33]);
                    printf("  Source Port : %d\n",(packet[14+ip_h]<<8)|packet[15+ip_h]);
                    printf("  Destination Port : %d\n",(packet[16+ip_h]<<8)|packet[17+ip_h]);
                    if((0x48545450==(packet[14+ip_h+tcp_h]<<24|packet[15+ip_h+tcp_h]<<16|packet[16+ip_h+tcp_h]<<8|packet[17+ip_h+tcp_h]))||
                            (0x474554==(packet[14+ip_h+tcp_h]<<16|packet[15+ip_h+tcp_h]<<8|packet[16+ip_h+tcp_h]))||
                            (0x504f5354==(packet[14+ip_h+tcp_h]<<24|packet[15+ip_h+tcp_h]<<16|packet[16+ip_h+tcp_h]<<8|packet[17+ip_h+tcp_h]))){
                        printf("  HTTP : ");
                        for(int i=(14+ip_h+tcp_h); i<(14+ip_h+tcp_h+10);i++){
                        printf("%02X",packet[i]);
                        }
                    }
                    else{
                        printf("  TCP : ");
                        for(int i=(14+ip_h+tcp_h); i<(14+ip_h+tcp_h+10);i++){
                            printf("%02X",packet[i]);
                        }
                    }
                    printf("\n");
                }
            }
        }
    }
    pcap_close(handle);
    return 0;
}
