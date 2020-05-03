//
// Created by Richard Klem on 23.04.20.
//
#include <cstdint>
#include <sys/socket.h>
#include "my_string.h"


#ifndef PROJ2_PROJ_H
#define PROJ2_PROJ_H

#define RED "\033[0;91m"
#define RST "\033[0m"

int BUFFER_SIZE = 65536;
const char * help_text = "\n***Nápověda k snifferu paketů***\n"
                   "  Možné parametry:\n"
                   "    -i nazev_rozhrani (Rozhraní, na kterém se bude poslouchat.\n"
                   "            Nebude-li tento parametr uveden, vypíše se seznam aktivních rozhraní)\n"
                   "    -p int:cislo_portu (Sniffer bude zachytávat pakety pouze na daném portu,\n"
                   "            nebude-li tento parametr uveden, uvažují se všechny porty)\n"
                   "    -t | --tcp (bude zobrazovat pouze tcp pakety)\n"
                   "    -u | --udp (bude zobrazovat pouze udp pakety)\n"
                   "    Pokud nebude specifikován typ paketu, uvažují se tcp i udp pakety zároveň.\n"
                   "    Pokud bude specifikován více jak jeden typ, uvažuje se jejich kombinace.\n\n"
                   "    -n | --num int:pocet_paketu (Určuje počet vypsaných paketů,\n"
                   "        pokud nebude počet specifikován, vypíše se pouze 1 paket.)\n"
                   "    -a | --arp (Filtruje pouze ARP pakety a žádné jiné.)\n"
                   "    -6 | --ip6 (Filtruje IPv6 protokol, lze kombinovat s IPv4, tcp, udp a port filtrováním.)\n"
                   "    -4 | --ip4 (Filtruje IPv6 protokol, lze kombinovat s IPv6, tcp, udp a port filtrováním.)\n"
                   "    -A | --all (Nefiltruje se nic, zachytávají se všechny pakety, vypisují se pouze podporované.)\n"
                   "    -s | --stats (Výpis statistik o síťovém provozu na konci běhu programu.)\n"
                   "  Krátké parametry je možné zadávat ve tvaru \"-n5\" anebo \"-n 5\".\n"
                   "  Dlouhé parametry je nutné zadávat ve tvaru \"--num=5\".\n\n";

enum EXIT_CODES {OK = 0,
                 INTERFACE_ERROR = 1,
                 SOCKET_ERROR = 2,
                 PACKET_ERROR = 3,
                 BAD_ARG_VALUE = 11,
                 UNKNOWN_PARAMETER = 12};


void signal_callback_handler(int unused);
void callback(u_char * args, const struct pcap_pkthdr * header, const u_char * packet);
void print_packet_preamble(unsigned char *packet, const struct pcap_pkthdr *frame, sa_family_t ip_version,
                           uint16_t dest_port, uint16_t source_port);
void print_tcp_packet(unsigned char * packet, const struct pcap_pkthdr * frame, int size, sa_family_t ip_version);
void print_udp_packet(unsigned char * packet, const struct pcap_pkthdr * frame, int size, sa_family_t ip_version);
void print_arp_packet(unsigned char * packet, const struct pcap_pkthdr * frame, int size);
void print_data(unsigned char * data, int size);

#endif //PROJ2_PROJ_H
