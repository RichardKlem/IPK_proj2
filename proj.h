//
// Created by Richard Klem on 23.04.20.
//
#include "my_string.h"

#ifndef PROJ2_PROJ_H
#define PROJ2_PROJ_H
int BUFFER_SIZE = 65536;
const char * help_text = "***Napoveda k snifferu paket***\n"
                   "Mozne parametry:\n"
                   "   -i nazev_rozhrani (Rozhraní, na kterém se bude poslouchat.\n"
                   "           Nebude-li tento parametr uveden, vypíše se seznam aktivních rozhraní)\n"
                   "   -p int:cislo_portu (Sniffer bude zachytávat pakety pouze na daném portu,\n"
                   "           nebude-li tento parametr uveden, uvažují se všechny porty)\n"
                   "   -t | --tcp (bude zobrazovat pouze tcp pakety)\n"
                   "   -u | --udp (bude zobrazovat pouze udp pakety)\n"
                   "   Pokud nebude specifikován typ paketu, uvažují se všechny typy snifferem podporovaných\n"
                   "       paketů zároveň. Pokud bude specifikován více jak jeden typ, uvažuje se\n"
                   "       kombinace těchto paketů.\n"
                   "   -n | --num int:pocet_paketu (Určuje počet vypsaných paketů,\n"
                   "       pokud nebude počet specifikován, vypíše se pouze 1 paket.)\n";

enum EXIT_CODES {OK = 0, BAD_ARG_VALUE = 11, UNKNOWN_PARAMETER = 12};

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* Buffer, int Size, uint16_t source_port, uint16_t dest_port);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);

#endif //PROJ2_PROJ_H
