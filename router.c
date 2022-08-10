#include "include/queue.h"
#include "include/skel.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#include <sys/types.h>


#include <unistd.h>
/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>
/* ethheader */
#include <net/ethernet.h>
/* ether_header */
#include <arpa/inet.h>
/* icmphdr */
#include <netinet/ip_icmp.h>
/* arphdr */
#include <net/if_arp.h>
#include <asm/byteorder.h>

#define MAX_LINES 70000
#define MAX_CHARS 100

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

int interfaces[ROUTER_NUM_INTERFACES];

struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;
int arp_table_len;

struct route_table_entry *get_best_route(__u32 dest_ip) {
	/* TODO 1: Implement the function */
	int i, pos = -1;

	for(i = 0; i < rtable_size; i++) {
		if ((htonl(dest_ip) & htonl(rtable[i].mask)) == htonl(rtable[i].prefix)) {
			if (pos == -1)
				pos = i;
			if (rtable[pos].mask < rtable[i].mask)
				pos = i;
		}
	}

	if (pos == -1)
		return NULL;

	return &rtable[pos];
}

struct arp_entry *get_arp_entry(uint32_t ip) {
    int i;
    //printf("Ip-ul primit este:	");
    //print_ip(ip);
    //printf("\n");

    for (i = 0; i < arp_table_len; i++) {
    	//printf("Ip-ul din tabelul arp nr %d este:	", i);
    	//print_ip(arp_table[i].ip);
    	//printf("\n");
		if(htonl(ip) == htonl(arp_table[i].ip)) {
			return &arp_table[i];
		}
	}
    return NULL;
}

// functie pentru parsarea tabelei de rutare
void parse_routing_table(char *rtable_txt) {
	int fd = open(rtable_txt, O_RDONLY);
	struct in_addr ip_addr;
	
	int rows = 0, cols = 0, i, sz;

	char **lines = malloc(MAX_LINES * sizeof(char*));
	for (int i = 0; i < MAX_LINES; i++) {
    	lines[i] = malloc(MAX_CHARS * sizeof(char));
	}	

	char oneByte;	
	while((sz = read(fd, &oneByte, 1)) != 0) {
		lines[rows][cols] = oneByte;
		
		cols++;
		if(oneByte == '\n') {
			cols = 0;
			rows++;
		}
	}

  	int index;
	rtable_size = rows + 1;
	rtable = malloc(sizeof(struct route_table_entry) * rtable_size);
	
	const char s[2] = " ";
   	char *token;

	for (i = 0; i < rtable_size; i++) {
		token = strtok (lines[i], s);
		index = 0;
		while (token != NULL) {
    		// aici am prefixul
    		if (index == 0) {
    			inet_aton(token, &ip_addr);
    			rtable[i].prefix = ip_addr.s_addr;
    		}
    		// aici am next hop
    		if (index == 1) {
    			inet_aton(token, &ip_addr);
    			rtable[i].next_hop = ip_addr.s_addr;
    		}
    		// aici am masca
    		if (index == 2) {
    			inet_aton(token, &ip_addr);
    			rtable[i].mask = ip_addr.s_addr;
    		}
			// aici am interfata
    		if (index == 3) {
    			rtable[i].interface = atoi(token);
    		}
    		index++;
    		token = strtok(NULL, s);
  		}
	}

	for (int i = 0; i < MAX_LINES; i++) {
    	free(lines[i]);
	}
	free(lines);
}

// Functie care compara daca doua adrese mac sunt la fel
int compare_macs(uint8_t *mac_first, uint8_t *mac_second) {
	int i = 0;
	
	for (i = 0; i < 6; i++) {
		if (mac_first[i] != mac_second[i]) {
			return 0;
		}
	}
	return 1;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);
	setvbuf (stdout, NULL, _IONBF, 0) ;
	
	parse_routing_table(argv[1]);
	int index = 0, i, j;

	queue temp_q;
	queue q;
	
	q = queue_create();
	temp_q = queue_create();

	arp_table = malloc(sizeof(struct arp_entry) * 100);
	
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		index++;

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		
		/* TODO 2: verific daca este un pachet de tip icmp destinat routerului
			si trimit un pachet de tip echo reply*/
		int check = 0;
		char *address;
		struct in_addr ip_addr;
		
		// interfata de pe care a venit pachetul
		uint8_t *mac_int = malloc((sizeof(uint8_t)) * 6);
		get_interface_mac(m.interface, mac_int);

		struct icmphdr *icmp_hdr = parse_icmp(m.payload);
		if (icmp_hdr != NULL) {
			// verific daca e un pachet destinat router-ului.
			for (i = 0; i < ROUTER_NUM_INTERFACES; i++) {
				address = get_interface_ip(i);
				inet_aton(address, &ip_addr);
				if (htonl(ip_addr.s_addr) == htonl(ip_hdr->daddr)) {
					check = 1;
					break;
				}
			}
			if (check == 1 && icmp_hdr->type == 8 && icmp_hdr->code == 0) {
				send_icmp(htonl(ip_hdr->saddr), htonl(ip_hdr->daddr), mac_int, eth_hdr->ether_shost,
								0, 0, m.interface, htons(getpid() & 0xFFFF), htons(index));	
				continue;		
			}
			if (check == 1)
				continue;
		}
		
		/* TODO 3 && TODO 4: verific daca este un pachet de tip arp*/
		struct arp_header *arp_hdr = parse_arp(m.payload);
		if (arp_hdr != NULL) {
			// Daca e ARP_REQUEST trimit adresa mac a routerului.
			if (arp_hdr->op == ntohs(ARPOP_REQUEST)) {
				// Verific daca trebuie trimit routerului
				int check_for_router = 0;
				for (i = 0; i < ROUTER_NUM_INTERFACES; i++) {
					address = get_interface_ip(i);

					inet_aton(address, &ip_addr);
					if (htonl(ip_addr.s_addr) == htonl(arp_hdr->tpa)) {
						check_for_router = 1;
						break;
					}
				}

				if (check_for_router == 1) {
					for (j = 0; j < 6; j++) {
						eth_hdr->ether_dhost[j] = eth_hdr->ether_shost[j];
					}
					get_interface_mac(m.interface, eth_hdr->ether_shost);
					
					send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, m.interface, htons(ARPOP_REPLY));
				}
			}

			// verific daca e arp reply, updatez tabela si trimit pachetele din coada
			if (arp_hdr->op == ntohs(ARPOP_REPLY)) {

				arp_table[arp_table_len].ip = arp_hdr->spa;
				for (j = 0; j < 6; j++) {
					arp_table[arp_table_len].mac[j] = eth_hdr->ether_shost[j];
				}
				arp_table_len++;				

				while(!queue_empty(q)) {
					packet *d = queue_deq(q);

					struct ether_header *eth_hdr_q = (struct ether_header *)d->payload;
					struct iphdr *ip_hdr_q = (struct iphdr *)(d->payload + sizeof(struct ether_header));
					
					struct route_table_entry *best_route_q = get_best_route(ip_hdr_q->daddr);
					
					uint8_t *mac_int_q = malloc((sizeof(uint8_t)) * 6);
					get_interface_mac(d->interface, mac_int_q);
					struct arp_entry *arp_match_q = get_arp_entry(best_route_q->next_hop);
					

					if(arp_match_q == NULL) {
						queue_enq(temp_q, d);
						send_icmp_error(htonl(ip_hdr_q->saddr), htonl(ip_hdr_q->daddr), mac_int_q, 
								eth_hdr_q->ether_shost, 3, 0, d->interface);

						continue;
					}

					get_interface_mac(best_route_q->interface, eth_hdr_q->ether_shost);
		
					for(j = 0; j < 6; j++) {
						eth_hdr_q->ether_dhost[j] = arp_match_q->mac[j];
					}
					send_packet(best_route_q->interface, d);
				}

				while(!queue_empty(temp_q)) {
					packet *temp = queue_deq(temp_q);
					struct arp_header *arp_hdr_temp = parse_arp(temp->payload);
					if(arp_hdr_temp != NULL)
						queue_enq(q, temp);
				}
			}
			continue;
		}

		/* TODO 5: Daca ttl este mai mic sau egal cu 1 trimit un icmp time exceeded */
		if(ip_hdr->ttl <= 1) {
			send_icmp_error(htonl(ip_hdr->saddr), htonl(ip_hdr->daddr), mac_int, 
								eth_hdr->ether_shost, 11, 0, m.interface);
			continue;
		}

		/* TODO 6: verific checksum-ul, arunc pachetul daca checksum-ul nu este corect */
		/* Presupun ca checksum-ul este corect si o sa primesc pe vmchecker momentan rezolv fara
		// poate se rezolva oricum*/
		int temp = ip_hdr->check;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
		
		if (temp != ip_hdr->check) {
			continue;
		}

		/* TODO 7: decrementez ttl-ul si updatez checksum-ul */
		ip_hdr->ttl--;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

		/* TODO 8: caut intrarea cea mai buna din tabela de rutare 
					daca nu gasesc nicio intrare trimit un ICMP - host unreachable*/
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
		if (best_route == NULL) {
			send_icmp_error(htonl(ip_hdr->saddr), htonl(ip_hdr->daddr), mac_int, 
								eth_hdr->ether_shost, 3, 0, m.interface);
			continue;
		}

		// caut adresa mac a destinatiei
		struct arp_entry *arp_match = get_arp_entry(best_route->next_hop);
		if (arp_match == NULL) {

			// bag pachetul in coada de pachete.
  			packet temp = m;
			queue_enq(q, &temp);
			
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			for (j = 0; j < 6; j++) {
				eth_hdr->ether_dhost[j] = 0xff;
			}
			
			eth_hdr->ether_type = htons(0x0806);

			address = get_interface_ip(best_route->interface);

			inet_aton(address, &ip_addr);
			
			print_ip(best_route->next_hop);
			printf("\n");
			// trimit request, nu am rezultatul in tabela.
			send_arp(best_route->next_hop, ip_addr.s_addr, eth_hdr,
						 best_route->interface, htons(ARPOP_REQUEST));
			continue;
		}

		get_interface_mac(best_route->interface, eth_hdr->ether_shost);
		for (j = 0; j < 6; j++) {
			eth_hdr->ether_dhost[j] = (unsigned char) arp_match->mac[j];
		}
		
		send_packet(best_route->interface, &m);
	}
}
