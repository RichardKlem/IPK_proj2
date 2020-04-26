//
// Created by richardklem on 23.04.20.
//
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string>    //strlen
#include <cstring>

#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp_count header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#include <pcap.h>
#include <getopt.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include "my_string.h"
#include "proj.h"


struct sockaddr_in source, dest;
int tcp_count = 0, udp_count = 0, total = 0, others = 0;
std::string interface_arg;
int interface_flag = 0, tcp_flag = 0, udp_flag = 0, port_arg = 0, num_arg = 1, bytes_read = 0;
FILE * logfile = stdout;

struct option long_options[] =
        {
                {"help", no_argument,        0, 'h'},
                {"tcp", no_argument,        0, 't'},
                {"udp",  no_argument,        0, 'u'},
                {"num",  optional_argument,  0, 'n'},
                {"port", optional_argument,  0, 'p'},
                {0, 0, 0, 0}  // ukoncovaci prvek
        };

char *short_options = (char*)"hn:p:tui:";

int main(int argc, char* argv[]) {
    int c;
    int option_index; //dale se nevyuziva, ale je povinny pro funkci getopt_long
    if (argc > 1){
        while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
        {
            str2int_struct_t *p_tmp = nullptr;
            str2int_struct_t tmp = str2int(optarg);//pouzije se dale
            p_tmp = &tmp;

            switch (c)
            {
                case 'h':
                    fprintf(stdout,"%s", help_text);
                    exit (OK);
                case 'i':
                    interface_flag = 1;
                    break;
                case 'p':
                    if (p_tmp->status)
                        port_arg = p_tmp->num;
                    else {
                        fprintf(stderr, "Nesprávný formát čísla. Zadali jste %s.\n", optarg);
                        exit(BAD_ARG_VALUE);
                    }
                    break;
                case 'n':
                    if (p_tmp->status){
                        if (p_tmp->num < 0){
                            fprintf(stderr, "Nesprávná hodnota čísla. Zadali jste %d.\n", p_tmp->num);
                            exit(BAD_ARG_VALUE);
                        }
                        num_arg = p_tmp->num;
                    }
                    else{
                        fprintf(stderr, "Nesprávný formát čísla. Zadali jste %s.\n", optarg);
                        exit(BAD_ARG_VALUE);
                    }
                    break;
                case 't':
                    if (p_tmp != nullptr){
                        fprintf(stderr, "Parametr -t | --tcp nepřijímá žádné argumenty.\n");
                        exit(BAD_ARG_VALUE);
                    }
                    tcp_flag = 1;
                    break;
                case 'u':
                    if (p_tmp != nullptr){
                        fprintf(stderr, "Parametr -u | --udp nepřijímá žádné argumenty.\n");
                        exit(BAD_ARG_VALUE);
                    }
                    udp_flag = 1;
                    break;

                default:
                    exit(UNKNOWN_PARAMETER);
            }
        }
        if (!tcp_flag && !udp_flag){
            tcp_flag = 1;
            udp_flag = 1;
        }
    }

    if(interface_flag == 0){
        char error[PCAP_ERRBUF_SIZE];
        pcap_if_t *interfaces, *tmp;
        int i = 0;
        if(pcap_findalldevs(&interfaces, error) == -1){
            fprintf(stderr, "Nastala chyba při zjišťování dostupných rozhraní.");
            exit(INTERFACE_ERROR);
        }

        printf("\n the interfaces present on the system are:");
        for(tmp = interfaces; tmp; tmp = tmp->next)
            fprintf(stdout, "\n%d  :  %s | %s", i++, tmp->name, tmp->description);
        fprintf(stdout, "\n");
        return OK;
    }
    int saddr_size, data_size;
    struct sockaddr saddr{};

    auto *buffer = (unsigned char *) malloc(BUFFER_SIZE);

    printf("Starting...\n");

    //vytvoreni noveho soketu, sock_raw obsahuje pri uspechu file descriptor
    int sock_raw = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

    if(sock_raw == -1){
        fprintf(stderr, "Nastala chyba při vytváření soketu.\n");
        exit(SOCKET_ERROR);
    }

    while(total < num_arg){
        saddr_size = sizeof saddr;
        //obdrzeni prichoziho soketu
        data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, (socklen_t*) &saddr_size);
        if(data_size == -1){
            fprintf(stderr, "Nastala chyba při čtení příchozího paketu.\n");
            exit(PACKET_ERROR);
        }

        auto *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        total++;
        switch (iph->protocol){
            case 6:  //TCP
                tcp_count++;
                print_tcp_packet(buffer , data_size);
                break;

            case 17: //UDP
                udp_count++;
                print_udp_packet(buffer , data_size);
                break;

            default:
                others++;
                break;
        }
    }
}

void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char* Buffer, int Size, uint16_t source_port, uint16_t dest_port)
{
    auto *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile , "\n");
    fprintf(logfile , "%s : ", inet_ntoa(source.sin_addr));
    fprintf(logfile , "%d > ", source_port);
    fprintf(logfile , "%s : ", inet_ntoa(dest.sin_addr));
    fprintf(logfile , "%d\n", dest_port);
}
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;

    auto *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = (unsigned short) iph->ihl*4;

    auto *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    print_ip_header(Buffer, Size, ntohs(tcph->source), ntohs(tcph->dest));

    fprintf(logfile , "\n");
    fprintf(logfile , "                        DATA Dump                         ");
    fprintf(logfile , "\n");

    fprintf(logfile , "IP Header\n");
    PrintData(Buffer, iphdrlen);

    fprintf(logfile , "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);

    fprintf(logfile, "MELTED HEADERS\n");
    PrintData(Buffer, iphdrlen + tcph->doff*4);

    fprintf(logfile , "Data Payload\n");
    PrintData(Buffer + header_size , Size - header_size );

    fprintf(logfile , "\n###########################################################\n");
}

void print_udp_packet(unsigned char *Buffer , int Size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");

    print_ip_header(Buffer, Size, ntohs(udph->source), ntohs(udph->dest));

    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer , iphdrlen);

    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);

    fprintf(logfile , "Data Payload\n");

    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);

    fprintf(logfile , "\n###########################################################\n");
}
void print_bytes(int size){
    if (size >= 0x0 && size <= 0xf)
        fprintf(logfile , "0x000%x", size);
    else if (size >= 0x10 && size <= 0xff)
        fprintf(logfile , "0x00%x", size);
    else if (size >= 0x100 && size <= 0xfff)
        fprintf(logfile , "0x0%x", size);
    else
        fprintf(logfile , "0x%x", size);
}


void PrintData (unsigned char* data , int Size)
{
    print_bytes(bytes_read);
    bytes_read += 0x10;
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(i%8 == 0 && i%16 != 0) fprintf(logfile , "   ");
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        }

        if(i%16==0) fprintf(logfile , "   ");
        fprintf(logfile , " %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
                fprintf(logfile , "   "); //extra spaces
            }

            fprintf(logfile , "         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                    fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                    fprintf(logfile , ".");
                }
            }

            fprintf(logfile ,  "\n" );
        }
    }
}