/*
 * Copyright 2016 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Include Standard Header Files */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

/* Macro Declaration */

#define TRUE     1
#define FALSE    0

/* TCP Port Number for ISIS communication between Java client and C Server*/
#define SPORT 3000
/* TCP Port Number for OSPF communication between Java client and C Server*/
#define OSPFPORT 7000
#define SHOST "127.0.0.1"

/* ISIS Packet Types */

#define L1_LAN 0x0f
#define L1_LSP 0x12
#define L1_CSNP 0x18
#define L1_PSNP 0x1a
#define ISIS_CONFIG_PACKET_TYPE   0xFF

#define err_info(...) {\
                        fprintf(stderr, __VA_ARGS__);\
                        if (csock > 0) close(csock);\
                        if (rawsock > 0) close(rawsock);\
                        exit(1);\
                        }    
/* Data structure for ISIS and OSPF to store Interface Information */
typedef struct {
    char type;
    char if_name[IFNAMSIZ + 1];
} ifdata;

/* multicast addresses */

static unsigned char * marray[] = {
	/* L1 Multicast Address */
    (unsigned char []){0x01, 0x80, 0xC2, 0x00, 0x00, 0x14},
    /* L2 Multicast Address */
    (unsigned char []){0x01, 0x80, 0xC2, 0x00, 0x00, 0x15},
    /* P2P Multicast Address */
    (unsigned char []){0x09, 0x00, 0x2b, 0x00, 0x00, 0x05},
    /* null entry */
    (unsigned char []){0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* ospf multicast addresses */
    (unsigned char []){0x01, 0x00, 0x5e, 0x00, 0x00, 0x05},
    (unsigned char []){0x01, 0x00, 0x5e, 0x00, 0x00, 0x06}
};

/* Static and Global Variables */

static int csock = -1, rawsock = -1;
static pthread_t wthrd;

/* Number of Interfaces currently supporting 255 */

static unsigned char nif = 0;
static unsigned char loop = TRUE;
static unsigned short pdu_length = 0; // actual pdu length
static unsigned protocol_flag = 0;

/* Pointer to array of MAC address corresponding to local interface index */
unsigned char *ifmacp = NULL;
ifdata *ifindexp = NULL;

/* Enum Declaration */

enum {L1, L2, P2P, L1NL2};

/* Structure Declaration */

/* Linux socket Filter to capture ISIS/OSPF packet */

struct sock_filter code[] =
{

{ 0x28, 0, 0, 0x0000000c },
{ 0x25, 6, 0, 0x000005dc },
{ 0x28, 0, 0, 0x0000000e },
{ 0x15, 0, 4, 0x0000fefe },
{ 0x30, 0, 0, 0x00000010 },
{ 0x15, 0, 2, 0x00000003 },
{ 0x30, 0, 0, 0x00000011 },
{ 0x15, 4, 0, 0x00000083 },
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 3, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 1, 0x00000059 },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },

};

/* Filter */
struct sock_fprog bpf = {
	.len = (sizeof(code) / sizeof(struct sock_filter)),
    .filter = code,
};

/*
   Thread to receive Complete Ethernet Frame which may contain ISIS / OSPF packet.
   In case of ISIS packet C program will pass to Java Client adding additional meta
   data local source mac id and local interface index at the end of isis packet. 
   
   ISISpacket (1521 fixed length) -- local mac id (6 bytes) - interface index (1 byte)
   
   In case of OSPF C program will pass to Java Client adding additional meta data 
   interface index and source ip address and this metadata will be prepended 
   before OSPF packet. 
   
   interface index (1 byte) - source ip address (4 bytes) - ospf packet (Actual length)
 */
 
static void *thread_callback(void *arg)
{
	void rip_me(int signo) {
		signal(SIGALRM, rip_me);   
    }
   
    signal(SIGALRM, rip_me);
   
    /* interface info */
    struct sockaddr_ll iinfo;
    unsigned short wBytes = 0, plen = ETH_FRAME_LEN + ETH_ALEN + 1;
    unsigned char ip_header_length = 0;
    socklen_t addrlen = sizeof(iinfo);
    int zn = 0;
       
    /* Ether Frame + Local Interface Mac + Local Interface Index */
    unsigned char pktbuff[ETH_FRAME_LEN + ETH_ALEN + 1] = {0x0};
	
	/* protocol_flag is set to 1 for IS-IS */
	if (protocol_flag) {
		while (loop) {
			/* Receive Ethernet Frame */
			zn = recvfrom(rawsock, pktbuff, ETH_FRAME_LEN, 0,
                      (struct sockaddr *)&iinfo, &addrlen);
       
			if (iinfo.sll_pkttype == PACKET_OUTGOING) continue;
    
			/* For ISIS packet */
			if (pktbuff[17] == 0x83) {
				if (ifindexp[iinfo.sll_ifindex - 1].type == L1NL2) {
					if (memcmp(pktbuff, marray[L1], ETH_ALEN) &&
						memcmp(pktbuff, marray[L2], ETH_ALEN)) {
						continue;   
					}
				}else if(ifindexp[iinfo.sll_ifindex - 1].type >= 0) {
					if (memcmp(pktbuff,
						marray[ifindexp[iinfo.sll_ifindex - 1].type], ETH_ALEN))
					{
						continue;
					}
				}else {
					continue;
				}
    
				/* Mac address of the interface on which pkt received */
				memcpy(pktbuff + ETH_FRAME_LEN,ifmacp + ((iinfo.sll_ifindex - 1)
                                                  * ETH_ALEN), ETH_ALEN);
				pktbuff[plen -1] = (unsigned char)iinfo.sll_ifindex;
       
				/* Pass Ether Frame + Local Interface Mac + Local Interface
				* Index to Java Client
				*/
				while ((wBytes += write(csock, pktbuff + wBytes, plen - wBytes))
					   && (wBytes != plen));
				#ifdef DEBUG
				printf("IS-IS SEND To Java Client: [%d], aclen [%d]\n", wBytes, zn); 
				#endif
			}
	        
			wBytes = 0;
		}
	}
	/* protocol_flag is set to 0 for OSPF */
	else if (protocol_flag ^ 1) {
		while (loop) {
			/* Receive Ethernet Frame */
			zn = recvfrom(rawsock, pktbuff, ETH_FRAME_LEN, 0,
                      (struct sockaddr *)&iinfo, &addrlen);
       
			if (iinfo.sll_pkttype == PACKET_OUTGOING) continue;
    
			/* For OSPF packet */
	
			if ((htons(*(unsigned short *)(pktbuff + 12)) == 0x0800) &&
				(pktbuff[23] == 0x59)) {
				/* ip header length */
				ip_header_length = ((pktbuff[14] & 0x0F) << 2) + 14;
				plen = 1521 - ip_header_length;				
				/* copy the index and source ip address before OSPF packet*/
			    pktbuff[ETH_FRAME_LEN + 2] = (unsigned char)iinfo.sll_ifindex;
			    memcpy(pktbuff + ETH_FRAME_LEN + 3, pktbuff + 26, 4);
               
				while ((wBytes += write(csock, pktbuff + ip_header_length +
								wBytes, plen - wBytes)) && (wBytes != plen));
				#ifdef DEBUG
				printf("OSPF SEND To Java Client: [%d], aclen [%d]\n", wBytes, zn); 
				#endif
			}
			
			wBytes = 0;
		}
	}
	
	return NULL;
}

int main(int argc, char **argv)
{
	/* argument 2 should be either isis or ospf */

    if (argc ^ 2) err_info("Usage: [%s] [isis|ospf]\n", argv[0]);
       
    strcasecmp(argv[1], "isis") ? (strcasecmp(argv[1], "ospf") ?
                (fprintf(stderr, "protocol not supported\n"), exit(110), 0) : 0)
                : (protocol_flag = 1); 
       
    /* Store the highest interface index in nif */
               
    struct if_nameindex *if_ni, *tni;
    struct ifreq ifr = {0x0};
	int ospf_wsock = -1;
               
    if_ni = if_nameindex();
      
    if (if_ni == NULL)
    {
        err_info("%s %d\n", strerror(errno), __LINE__)
    }
              
    for (tni = if_ni; ! (tni->if_index == 0 && tni->if_name == NULL); tni++)
    {
        (nif > tni->if_index) || (nif = tni->if_index);
    }
       
    /* Number of interfaces */
               
    ifdata ifindex[nif];
    memset(ifindex, 255, sizeof(ifdata) * nif);
    ifindexp = ifindex; // index pointer
   
    /* Interface mac addresses */
               
    unsigned char ifmac[ETH_ALEN * nif];
    ifmacp = ifmac;
      
    if ((rawsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        err_info("%s %d\n", strerror(errno), __LINE__)
    }
       
    /* Based on number of interface get corresponding MAC addresses */
    for (tni = if_ni; ! (tni->if_index == 0 && tni->if_name == NULL); tni++) {
		if (strcmp("lo", tni->if_name) == 0) continue;
              
        memcpy(ifr.ifr_name, tni->if_name, strlen(tni->if_name) + 1);
        memcpy(ifindex[tni->if_index -1].if_name, tni->if_name,
			   strlen(tni->if_name) + 1);
              
        if (ioctl(rawsock, SIOCGIFHWADDR, &ifr) == -1) {
            err_info("%s %d\n", strerror(errno), __LINE__)
        }
              
        memcpy(ifmac + ((tni->if_index - 1) * ETH_ALEN), ifr.ifr_hwaddr.sa_data,
                           ETH_ALEN);
    }
      
    if_freenameindex(if_ni);
               
    /* Set raw socket to receive only ISIS packet */
    if (setsockopt(rawsock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf,
				   sizeof(bpf)) == -1) {
		err_info("%s %d\n", strerror(errno), __LINE__)
    }
	
    /* Create TCP socket */
          
    int sock = -1;
    struct sockaddr_in saddr = {0x0};
    socklen_t reuseaddr = 1;
                 
    saddr.sin_family = AF_INET;
	
	/* Create socket and assign port based on IS-IS or OSPF protocol */
	
    saddr.sin_port = htons(protocol_flag ? SPORT: OSPFPORT);
    saddr.sin_addr.s_addr = inet_addr(SHOST);
                  
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        err_info("%s %d\n", strerror(errno), __LINE__)
    }      
      
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
    	
    /* Bind the TCP socket to address and port*/
  
    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        close(sock);
        err_info("%s %d\n", strerror(errno), __LINE__)
    }
      
    /* Listen Queue */
    listen(sock, 5);
  
    if ((csock = accept(sock, NULL, NULL)) == -1) {
        close(sock);
        err_info("%s %d\n", strerror(errno), __LINE__)
    }
    
	/* For OSPF IP routing new socket has been created to send out OSPF packet to network */
	
    if (protocol_flag ^ 1) {
        if((ospf_wsock = socket(AF_INET, SOCK_RAW, 0x59)) < 0) {
            err_info("ospf_wsock:error\n");
        }
    }
    
    /* Create thread to receive ISIS /OSPF packet and send the same along
    * with meta data to Java client
    */
          
    pthread_create(&wthrd, NULL, thread_callback, NULL);
    pthread_detach(wthrd);
       
    /* extra five byte  for interface index and Ip address*/
               
    unsigned char recvbuff[ETH_FRAME_LEN + 1] = {}; 
    unsigned short zn = 0, rplen = 0;
       
    /* multicast structure */
    struct packet_mreq mreq = {0x0};
               
    unsigned char tindex = 0;
       
    mreq.mr_alen = ETH_ALEN;
    mreq.mr_type = PACKET_MR_MULTICAST;
     
    /* MTU(1500) 2 bytes + 3 bytes LLC */

    (protocol_flag) && memcpy(recvbuff + 2 * ETH_ALEN, (unsigned char [])
								  {0x05, 0xDC, 0xFE, 0xFE, 0x03}, 5);
     
    /* destination address structure */
               
    struct sockaddr_ll dll = {0x0};
    dll.sll_family = AF_PACKET;
    dll.sll_halen  = ETH_ALEN;
	   
    while (loop) {
		rplen = 0;
        LOOPIN:
               
        /* read the packet from java client and try to collect 1498 bytes, till
		 * it reaches 1498 bytes it continues (ISIS PDU + Interface Index )
        */
               
        if ((zn = read(csock, recvbuff + 17 + rplen, 1498 - rplen)) <= 0) {
            loop = FALSE;
            pthread_kill(wthrd, SIGALRM);
            break;
        }
        
        if((rplen += zn) && (rplen != 1498)) goto LOOPIN;
           
        #ifdef DEBUG
        printf("RECEIVED FROM Java Client: [%d]\n", zn);       
        #endif
		
		
		/* If its the ISIS configuration packet */
        if (recvbuff[17] == ISIS_CONFIG_PACKET_TYPE)
        {
            /* Max Interface supported */
            unsigned char if_entry = recvbuff[18];
                               
            /* Starting of interface entry */
            unsigned short istart = 19;
               
            /* Configure the interface based on ISIS configuration packet
			* which contains information
            * interface index, router type (L1, L2, P2P, L1NL2 )
            * First Byte - 0XFF
            * Second Byte - Number of interface need to be configured
            * Successive Tuple of Two Byte - Interface Index, Router Type
            */
            for (; if_entry-- > 0; istart += 2) {
                tindex = recvbuff[istart];
                mreq.mr_ifindex = tindex;
                                                                            
                mreq.mr_type = PACKET_MR_MULTICAST;
                   
                /* configuation is updated */
                if (ifindex[tindex - 1].type == L1NL2) {
                    memcpy(mreq.mr_address, marray[0], ETH_ALEN);
                       
                    if (setsockopt(rawsock, SOL_PACKET, PACKET_DROP_MEMBERSHIP
                                    , &mreq, sizeof(mreq))) {
                        perror("setsockopt:L1:DROP multicast");
                    }
                       
                    memcpy(mreq.mr_address, marray[1], ETH_ALEN);
                       
                    if (setsockopt(rawsock, SOL_PACKET, PACKET_DROP_MEMBERSHIP
                                    , &mreq, sizeof(mreq))) {
                        perror("setsockopt:L2:DROP multicast");
                    }
                }else if((ifindex[tindex - 1].type >= L1) &&
                         (ifindex[tindex - 1].type <= P2P)) {
                    memcpy(mreq.mr_address, marray[ifindex[tindex - 1].type],
                           ETH_ALEN);
                       
                    if (setsockopt(rawsock, SOL_PACKET, PACKET_DROP_MEMBERSHIP
                                    , &mreq, sizeof(mreq))) {
                        perror("setsockopt:DROP multicast");
                    }
                }
                   
                ifindex[tindex - 1].type = recvbuff[istart + 1];
                   
                if (recvbuff[istart + 1] == L1NL2) {
                    memcpy(mreq.mr_address, marray[0], ETH_ALEN);
                       
                    if (setsockopt(rawsock, SOL_PACKET, PACKET_ADD_MEMBERSHIP
                                    , &mreq, sizeof(mreq))) {
                        perror("setsockopt:L1: multicast");
                    }
                      
                    memcpy(mreq.mr_address, marray[1], ETH_ALEN);
 
                    if (setsockopt(rawsock, SOL_PACKET, PACKET_ADD_MEMBERSHIP
                                    , &mreq, sizeof(mreq))) {
                        perror("setsockopt:L2: multicast");
                    }                      
                }else {
                    memcpy(mreq.mr_address, marray[recvbuff[istart + 1]],
                              ETH_ALEN);
                    
                    if (setsockopt(rawsock, SOL_PACKET, PACKET_ADD_MEMBERSHIP
                                    , &mreq, sizeof(mreq))) {
                        perror("setsockopt: multicast");
                    }
                }
            }
               
            /* done with ISIS/OSPF configuration */
            (protocol_flag ^ 1) && (loop = FALSE);                   
            continue;
        }
       
        /* let us not add padding while sending packets */
		pdu_length = htons(*(unsigned short *)(recvbuff + 17 + recvbuff[23]));
		recvbuff[23] = 0; // isis reserved byte should always be zero
       
		/* change the ether header to include actual length */
		*(unsigned short *)(recvbuff + 12) = htons(3 + pdu_length);
       
		tindex = recvbuff[ETH_FRAME_LEN];
		dll.sll_ifindex = tindex; // interface index
                       
		/* source mac address */
		memcpy(recvbuff + ETH_ALEN, ifmac + ((tindex - 1) * ETH_ALEN),
			   ETH_ALEN);
           
		if (ifindex[tindex - 1].type == L1NL2) {
			tindex = L2;
           
			/* pdu type is 5th byte from fixed 17 bytes */
			if ((recvbuff[21] == L1_LAN) || (recvbuff[21] == L1_LSP) ||
				(recvbuff[21] == L1_CSNP) || (recvbuff[21] == L1_PSNP)) {
				tindex = L1;
			}
               
			/* destination mac address */
			memcpy(recvbuff, marray[tindex], ETH_ALEN);
            memcpy(dll.sll_addr, marray[tindex], ETH_ALEN);
		}else {
			/* destination address */
			memcpy(recvbuff, marray[ifindex[tindex - 1].type], ETH_ALEN);
			memcpy(dll.sll_addr, marray[ifindex[tindex - 1].type],ETH_ALEN);
		}
          
		/* Send ISIS packet as per the interface index
		* received from Java client
		*/
		zn = sendto(rawsock, recvbuff, 17 + pdu_length, 0,
					(struct sockaddr *)&dll, sizeof(dll));
		#ifdef DEBUG
		printf("IS-IS SEND: [%d], Interface Index %d\n", zn, recvbuff[ETH_FRAME_LEN]);       
		#endif
    }
	
	/* For received OSPF packet from Java Client */
	if (protocol_flag ^ 1) {
		loop = TRUE;
		struct sockaddr_in daddr = {.sin_family = AF_INET};
				
		while (loop) {
			rplen = 0;
               
			/* read the packet from java client and try to collect ospf pkt + 6
			 bytes (interface index, DR byte, destination IP address)
			*/
        
			ILOOPIN:       
			if ((zn = read(csock, recvbuff + rplen, 16 - rplen)) <= 0) {
				loop = FALSE;
				pthread_kill(wthrd, SIGALRM);
				break;
			}
        
			if((rplen += zn) && (rplen != 16)) goto ILOOPIN;
		
			rplen = 0;
		
			/* Getting PDU length of OSPF */
		
			pdu_length = htons(*(unsigned short *)(recvbuff + 2));
		
			OSPFLOOPIN:
			if ((zn = read(csock, recvbuff + 16 + rplen, (pdu_length - 10)
						   - rplen)) <= 0) {
				loop = FALSE;
				pthread_kill(wthrd, SIGALRM);
				break;
			}
		
			if((rplen += zn) && (rplen != (pdu_length - 10))) goto OSPFLOOPIN;
           
			#ifdef DEBUG
			printf("OSPF RECEIVED FROM Java Client: [%d]\n", pdu_length + 6);       
			#endif
		
		    memcpy(&daddr.sin_addr.s_addr, recvbuff + pdu_length + 2, 4);
                        
			setsockopt(ospf_wsock, SOL_SOCKET, SO_BINDTODEVICE,
				   ifindex[recvbuff[pdu_length] - 1].if_name,
				   strlen(ifindex[recvbuff[pdu_length] - 1].if_name));
		
			zn = sendto(ospf_wsock, recvbuff, pdu_length, 0,
						(struct sockaddr *)&daddr, sizeof(daddr));
			setsockopt(ospf_wsock, SOL_SOCKET, SO_BINDTODEVICE, "", 0);
			#ifdef DEBUG
			printf("OSPF SEND: [%d], Interface Index %d\n", pdu_length,
				   recvbuff[pdu_length]);       
			#endif
		}
	}
	
    close(csock);
    close(sock);
    close(rawsock);
    if (ospf_wsock > 0) close(ospf_wsock);
	
    /** reload the image */
    execlp(argv[0], argv[0], argv[1], NULL);
}
