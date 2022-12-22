
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "util.h"
#include "netdevice.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"

int main_proc(netdevice_t *p)
{
    char buf[MAX_LINEBUF];
    ipaddr_t ip;
    int key;

#if (FG_ARP_SEND_REQUEST == 1)
    arp_request(p, NULL);
#endif /* FG_ARP_REQUEST */
    uint8_t pingip[] = {140,127,208,185};

    myudp_param_t udp_param;
    COPY_IPV4_ADDR(udp_param.ip.dstip, pingip);
    udp_param.srcport = UDP_FILTER_PORT;
    udp_param.dstport = 80;

    udp_send(p, udp_param, NULL, 0);

    sleep(1);
    netdevice_add_proto(p,ETH_ARP,(ptype_handler)&arp_main);
    netdevice_rx(p);
    
    int i = 0;

    while (1)
    {

        int mill_seconds =100;
        clock_t start_time = clock();
        while (clock() < start_time + mill_seconds);

     
        uint8_t pingip[] = {140,127,208,185};
        // uint8_t pingip[]={10,1,208,104};

        // myipaddr[3]=i;
        myudp_param_t udp_param;
        COPY_IPV4_ADDR(udp_param.ip.dstip, pingip);
        udp_param.srcport = UDP_FILTER_PORT;
        udp_param.dstport = 80;

        udp_send(p, udp_param, NULL, 0);
       

        i++;

        /* key pressed? */
        if (!readready())
            continue;
    }
    return 0;
}

int main(int argc, char *argv[])
{

    char devname[MAX_LINEBUF], errbuf[PCAP_ERRBUF_SIZE];
    netdevice_t *p;

    if (argc == 2)
    {
        strcpy(devname, argv[1]);
    }
    else if (netdevice_getdevice(0, devname) == NETDEVICE_ERR)
    {
        return -1;
    }

    if ((p = netdevice_open(devname, errbuf)) == NULL)
    {
        fprintf(stderr, "Failed to open capture interface\n\t%s\n", errbuf);
        return -1;
    }
    printf("Capturing packets on interface %s\n", devname);

    // netdevice_add_proto(p,ETH_IP,(ptype_handler)&ip_main);

    main_proc(p);

    netdevice_close(p);
}
