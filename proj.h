//
// Created by richardklem on 23.04.20.
//

#ifndef PROJ2_PROJ_H
#define PROJ2_PROJ_H
int BUFFER_SIZE = 65536;

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);

#endif //PROJ2_PROJ_H
