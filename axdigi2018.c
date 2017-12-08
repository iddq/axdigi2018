/* 
 * axdigi: Cross and straight port digipeater program
 * Copyright (C) 1995 Craig Small VK2XLZ 
 *               2017 Gabor Mayer HG5OAP
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netax25/ax25.h>
#include <unistd.h>
#include <signal.h>

#include "hexdump.h"

#define VERSION "2017-DEC-06"

#define BEACON_INTERVAL 300
#define BEACON_DEST "BEACON"
#define BEACON_PATH "WIDE1-1", "RFONLY"
#define BEACON_TEXT "axdigi2018 || AX.25 packet radio digipeater || https://github.com/iddq/axdigi2018"

#define AXALEN 7
#define CALLSTRLEN AXALEN + 3 /* callsign + SSID including the terminating zero, "HG5OAP-11\0" */

/* Address extension bit The extension bit of each octet is set to zero, to indicate the next octet contains more address information */
#define E_BIT 0x01	/* Address extension */
#define RR_BIT 0x60	/* Reserved bits in SSID field */
#define C_BIT 0x80	/* C bit in destination and source SSID field */
#define REPEATED 0x80   /* Has-been-repeated bit in digipeater field */

#define MAX_PORTS 16

int skt;
struct sockaddr_ll saddr_ll2;

unsigned char beaconbuf[1000];
int beaconsize;

int port_count = 0;

typedef char callsign_t[CALLSTRLEN];

struct ax25port_s {
    int ifIndex;
    char ifName[IF_NAMESIZE];
    unsigned char addr[AXALEN];
    callsign_t callsign;
} ax25ports[MAX_PORTS];

struct ax25_header_s {
    callsign_t dst;
    callsign_t src;
    callsign_t digi[AX25_MAX_DIGIS];
    unsigned char control;
    unsigned char pid;
    unsigned char ndigi;
    unsigned char nrepeated;
    int repeated[AX25_MAX_DIGIS];
} ax25header;

void ax25_addr2call(unsigned char *bptr, char *callsign)
{

    unsigned char ssid = (bptr[6] >> 1) & 0xf;
    
    int i;
    
    memset(callsign, '\0', CALLSTRLEN);
    
    for (i=0; i<AXALEN-1; i++) {
        if (bptr[i] == ' ' << 1)
            break;
        callsign[i] = bptr[i] >> 1;
    }

    snprintf(callsign + i, 4, ssid ? "-%d" : "", ssid);

}

void ax25_call2addr(callsign_t *callsign, unsigned char bptr[]) {

    int i;
    
    memset(bptr, ' ' << 1, AXALEN-1);
    bptr[AXALEN-1] = 0; // ssid = 0
    
    for (i=0; i<AXALEN-1; i++) {
        if ((*callsign)[i] == '\0' ) {
            break;
        }
        
        if ((*callsign)[i] == '-') {
            break;
        }
        
        bptr[i] = (*callsign)[i] << 1;
    }
    
    if ((*callsign)[i] == '-') {
        i++;
        bptr[AXALEN-1] = atoi(&(*callsign)[i]) << 1;
    }
    
}
int parse_ax25_header(unsigned char *bptr, int size, struct ax25_header_s *pheader) {

    int prev_repeated, repeated;

    memset(pheader, 0, sizeof(struct ax25_header_s));
    
    size -= 2 * AXALEN;
    if (size<0)
        return -1;
        
    ax25_addr2call(bptr, (char *)&pheader->dst);
    bptr += AXALEN;
    ax25_addr2call(bptr, (char *)&pheader->src);
    bptr += AXALEN;
    
    //printf("parse_ax25_header: %s -> %s\n", pheader->src, pheader->dst);

    prev_repeated = 1;
    
    while (pheader->ndigi < AX25_MAX_DIGIS && !(bptr[-1] & E_BIT)) {
        size -= AXALEN;
        if (size<0)
            return -1;
        
        ax25_addr2call(bptr, (char *)&pheader->digi[pheader->ndigi]);
        
        repeated = ((bptr[6] & REPEATED) != 0);

        if (!prev_repeated && repeated)
            return -1;
        
        if (repeated) {
            pheader->repeated[pheader->ndigi] = repeated;
            pheader->nrepeated++;
        }
        
        prev_repeated = repeated;
        
        //printf("parse_ax25_header: digi #%02d: %s, repeated: %d\n", pheader->ndigi, pheader->digi[pheader->ndigi], repeated);

        pheader->ndigi++;
        bptr += AXALEN;
    }
    
    size -= 1;
    if (size<0)
        return -1;

    pheader->control = *bptr++;
    //printf("parse_ax25_header: control: 0x%02x\n", pheader->control);

    //size -= 1;
    //if (size<0)
    //    return -1;
    
    pheader->pid = *bptr++;
    //printf("parse_ax25_header: pid: 0x%02x\n", pheader->pid);
    
    return 0;
    
}

void add_port(int ifIndex, char *ifName, unsigned char *ax25_addr) {

    if (port_count < MAX_PORTS)
    {
        ax25ports[port_count].ifIndex = ifIndex;
        strncpy(ax25ports[port_count].ifName, ifName, IF_NAMESIZE);
        memcpy(ax25ports[port_count].addr, ax25_addr, AXALEN);
        
        ax25_addr2call(ax25ports[port_count].addr, ax25ports[port_count].callsign);
    
        printf("port[%d]: interface: %s, index: %d, callsign: %s\n", port_count, ax25ports[port_count].ifName,
            ax25ports[port_count].ifIndex, ax25ports[port_count].callsign);
        fflush(stdout);
        port_count++;
    }
}

unsigned char *get_addr_by_ifindex(int ifIndex)
{
    int i;

    for(i = 0; i < port_count; i++)
    {
        if (ax25ports[i].ifIndex == ifIndex) {
            return ax25ports[i].addr;
        }
    }

    return (unsigned char*)NULL;
}

int get_ifindex_by_addr(unsigned char *addr)
{
    int i;
    
    for(i = 0; i < port_count; i++)
    {
        if ((bcmp(addr, ax25ports[i].addr, AXALEN-1) == 0) && ((addr[6] & 0b00011110) == ax25ports[i].addr[6]))
            return ax25ports[i].ifIndex;
    }

    return -1;
}


int digipeat(unsigned char *bptr, struct ax25_header_s *pHeader, int ifIndex)
{
    unsigned char *in_interface_ax25_addr;
    int outIfIndex = -1;
    
    if ((in_interface_ax25_addr = get_addr_by_ifindex(ifIndex)) == NULL)
        return -1;

    bptr += 2 * AXALEN + (pHeader->nrepeated * AXALEN);

    if ( (outIfIndex = get_ifindex_by_addr(bptr)) > 0) {
        //printf("repeat: outIfIndex: %d\n", outIfIndex);
        memcpy(bptr, in_interface_ax25_addr, AXALEN-1);
        bptr[AXALEN-1] &= 0b11100001;
        bptr[AXALEN-1] |= in_interface_ax25_addr[AXALEN-1] & 0b00011110;
        bptr[AXALEN-1] |= REPEATED;
    }

    return outIfIndex;
}

void print_path(struct ax25_header_s *p)
{
    int i;
    
    if (p->ndigi == 0) {
        printf("%s -> %s\n", p->src, p->dst);
    } else {
        printf("%s -> %s via ", p->src, p->dst);
        for (i=0; i<p->ndigi; i++) {
            if (i==0)
                printf(p->repeated[i] ? "%s*" : "%s", p->digi[i]);
            else
                printf(p->repeated[i] ? ", %s*" : ", %s", p->digi[i]);
        }
    }
    printf("\n");
    fflush(stdout);
}

void get_interfaces(int skt)
{
    struct if_nameindex *if_ni, *i;
    struct ifreq sifreq;
    struct ifreq *ifr;

    ifr = &sifreq;
    
    if_ni = if_nameindex();
    if (if_ni == NULL) {
        perror("if_nameindex");
        exit(EXIT_FAILURE);
    }

   for (i = if_ni; ! (i->if_index == 0 && i->if_name == NULL); i++) {
       
       //printf("%u: %s\n", i->if_index, i->if_name);
   
       strncpy(ifr->ifr_name, i->if_name, IF_NAMESIZE);
       ioctl(skt, SIOCGIFHWADDR, ifr);
       
       //printf("sa_familiy: %d\n", sifreq.ifr_ifru.ifru_addr.sa_family);
       
       if (sifreq.ifr_ifru.ifru_addr.sa_family != ARPHRD_AX25)
           continue;
           
       add_port(i->if_index, i->if_name, (unsigned char*)ifr->ifr_hwaddr.sa_data);
   }
   
   if_freenameindex(if_ni);
   
}


void alarm_handler(int sig)
{
    unsigned char *p;
    int i;
    
    signal(SIGALRM, SIG_IGN);          /* ignore this signal       */

    for (i=0; i<1; i++) {
        p = beaconbuf + 1 + AXALEN;
        memcpy(p, ax25ports[i].addr, AXALEN);
        p[6] |= RR_BIT;
        
        //hexdump(beaconbuf, beaconsize);
        
        saddr_ll2.sll_ifindex = ax25ports[i].ifIndex;
        
        if (sendto(skt, beaconbuf, beaconsize, 0, (struct sockaddr *)&saddr_ll2, sizeof(saddr_ll2)) == -1)
            perror("sendto");
    }

    signal(SIGALRM, alarm_handler);     /* reinstall the handler    */
    alarm(BEACON_INTERVAL);
}


int beacon_init(unsigned char *buf) {

    struct ax25_header_s beacon = { BEACON_DEST, "" , { BEACON_PATH }, 0x03, 0xf0 } ;
    //struct ax25_header_s beacon2;

    const char text[] = BEACON_TEXT;
    int size = 0;
    int i;
    
    *buf = 0;
    size++;

    ax25_call2addr(&beacon.dst, buf + size);
    buf[size + 6] |= C_BIT | RR_BIT;
    size += AXALEN;

    ax25_call2addr(&beacon.src, buf + size);
    buf[size + 6] |= RR_BIT;
    size += AXALEN;
    
    for (i=0; i<AX25_MAX_DIGIS; i++) {
        if (beacon.digi[i][0] != '\0') {
            ax25_call2addr(&beacon.digi[i], buf + size);
            size += AXALEN;
            buf[size - 1] |= RR_BIT;
        }
    }
    
    buf[size - 1] |= E_BIT;
    
    buf[size++] = beacon.control;
    buf[size++] = beacon.pid;

    memcpy(buf + size, text, sizeof(text) - 1);
    size += sizeof(text) - 1;
    
    //parse_ax25_header(beaconbuf + 1, size, &beacon2);
    //print_path(&beacon2);
    
    parse_ax25_header(beaconbuf + 1, size, &beacon); // update ndigit in beacon
    printf("beacon: path: ");
    print_path(&beacon);
    printf("beacon: text: %s\n", text);
    printf("beacon: interval: %d\n", BEACON_INTERVAL);
    fflush(stdout);
        
    return size;
    
}


int main(int argc, char *argv[])
{
    int size;
    int outIfIndex;
    unsigned char buf[2000];
    socklen_t asize;
    struct sockaddr_ll saddr_ll;

    printf("axdigi2018 (%s). Copyright (C) 1995 Craig Small VK2XLZ, 2017 Gabor Mayer HG5OAP\n\n", VERSION);

    /* Check our huge range of flags */
    if (argc > 1)
    {
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "-h") ==0)
        {
            printf("axdigi comes with ABSOLUTELY NO WARRANTY.\n");
            printf("This is free software, and you are welcome to redistribute it\n");
            printf("under the terms of GNU General Public Licence as published\n");
            printf("by Free Software Foundation; either version 2 of the License, or\n");
            printf("(at your option) any later version.\n");
            return 0;
        }
    }

    if ((skt = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
        perror("socket");
        return(1);
    }

    get_interfaces(skt);
    
    if (port_count < 1)
    {
        printf("No ax25 interface found.\n");
        exit(EXIT_FAILURE);
    }

    beaconsize = beacon_init(beaconbuf);
    //hexdump(beaconbuf, beaconsize);
    signal(SIGALRM, alarm_handler);
    alarm(BEACON_INTERVAL);

    while(1)
    {
        asize=sizeof(saddr_ll);
        if ((size = recvfrom(skt, buf, sizeof(buf), 0, (struct sockaddr *)&saddr_ll, &asize)) == -1)
        {
            perror("recv");
            exit(EXIT_FAILURE);
        } else {
            if (saddr_ll.sll_protocol != htons(ETH_P_AX25))
                continue;
        }

        //hexdump(buf, size);

        if (parse_ax25_header(buf+1, size-1, &ax25header) < 0)
            continue;
            
        if (ax25header.ndigi == ax25header.nrepeated)
            continue;
            
#ifdef DO_NOT_FORWARD_APRS_PACKET
        if ((ax25header.control | 0x10) == 0x13 && ax25header.pid == 0xf0) // UI frame, PID = Text
            continue;
#endif

        //print_path(&ax25header);

        outIfIndex = digipeat(buf+1, &ax25header, saddr_ll.sll_ifindex);

        if (outIfIndex >= 0)
        {
            print_path(&ax25header);
            saddr_ll.sll_ifindex = outIfIndex;
            if (sendto(skt, buf, size, 0, (struct sockaddr *)&saddr_ll, sizeof(saddr_ll)) == -1)
                perror("sendto");
        }

    } /* while(1) */

}
