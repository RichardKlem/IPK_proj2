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
#include<ctime>
#include<sys/types.h>
#include<unistd.h>
#include <pcap.h>
#include <getopt.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <csignal>
#include "my_string.h"
#include "proj.h"


struct sockaddr_in source, dest;
int tcp_count = 0, udp_count = 0, total = 0, others = 0;
char * interface_arg;
int interface_flag = 0, tcp_flag = 0, udp_flag = 0, port_flag = 0, port_arg = 0, num_arg = 1, bytes_read = 0;
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
void signal_callback_handler(int signum) {
    fprintf(logfile, "\nByl zaslán signál SIGINT, program se ukočuje.\n");
    exit(OK);
}

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    bytes_read = 0;
    unsigned short iphdrlen;
    unsigned short tcphdrlen;

    auto *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
    iphdrlen = (unsigned short) iph->ihl*4;

    auto *tcph=(struct tcphdr*)(packet + iphdrlen + sizeof(struct ethhdr));
    tcphdrlen = (unsigned short) tcph->doff*4;


    //const char *payload; /* Packet payload */

    if (iphdrlen < 20) {
        printf("   * Invalid IP header length: %u bytes\n", iphdrlen);
        return;
    }

    switch (iph->protocol){
        case 6:  //TCP
            tcp_count++;
            print_tcp_packet((unsigned char *)packet , header, header->len);
            break;

        case 17: //UDP
            udp_count++;
            print_udp_packet((unsigned char *) packet , header, header->len);
            break;

        default:
            others++;
            break;
    }
    //PrintData(payload, strlen(reinterpret_cast<const char *>(payload)));
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_callback_handler);

    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp{};		/* The compiled filter */
    char filter_exp[PCAP_ERRBUF_SIZE] = "";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header{};	/* The header that pcap gives us */

    int c;
    int option_index;

    //zpracování argumentů
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
                    interface_arg = optarg;
                    break;
                case 'p':
                    if (p_tmp->status){
                        port_flag = 1;
                        port_arg = p_tmp->num;
                    }
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
                    if (p_tmp->status == S2I_OK){
                        fprintf(stderr, "Parametr -t | --tcp nepřijímá žádné argumenty.\n");
                        exit(BAD_ARG_VALUE);
                    }
                    tcp_flag = 1;
                    break;
                case 'u':
                    if (p_tmp->status == S2I_OK){
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
    else
        dev = interface_arg;

    if (dev == nullptr) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFFER_SIZE, 1, 100, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if ((!tcp_flag && !udp_flag) || (tcp_flag && udp_flag))
        sprintf(filter_exp, "(tcp or udp) ");
    else if (tcp_flag)
        sprintf(filter_exp, "tcp ");
    else if (udp_flag)
        sprintf(filter_exp, "udp ");
    if (port_flag)
        sprintf(filter_exp + strlen(filter_exp), "port %d ", port_arg);
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    //cyklus dokud pocet prectenych paketu neni roven num_arg
    pcap_loop(handle, num_arg, callback, nullptr);
    pcap_close(handle);
    exit(OK);
}

void print_ip_header(unsigned char* Buffer, const struct pcap_pkthdr *header, uint16_t source_port, uint16_t dest_port)
{
    auto *eth = (struct ethhdr *)Buffer;
    auto *iph = (struct iphdr *)(Buffer  + sizeof(*eth));

    memset(&source, 0, sizeof(source)); //"vyčistí" socket

    eth->h_proto = (Buffer[12] << (unsigned int) 8) + Buffer[13]; //nastavení ether type z ethernetového rámce
    if (eth->h_proto == ETH_P_IP)
        source.sin_family = AF_INET; //IPv4
    else if (eth->h_proto == ETH_P_IPV6)
        source.sin_family = AF_INET6; //IPv6

    source.sin_addr.s_addr = iph->saddr; //nastaví ve struktuře IP adresu

    char * src_name_print;
    char src_name[NI_MAXHOST];
    int rc = getnameinfo((struct sockaddr*)&source, sizeof(source),
                          src_name, sizeof(src_name),
                          nullptr, 0, 0);
    if (rc != 0)
        src_name_print = inet_ntoa(source.sin_addr);
    else
        src_name_print = src_name;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    tm * time = localtime(&(header->ts.tv_sec));
    int hours = time->tm_hour;
    int minutes = time->tm_min;
    int seconds = time->tm_sec;
    long int microseconds = header->ts.tv_usec;
    fprintf(logfile , "\n");
    fprintf(logfile, "%d:%d:%d.%ld ", hours, minutes, seconds, microseconds);
    fprintf(logfile , "%s : ", inet_ntoa(source.sin_addr));
    fprintf(logfile , "%s : ", src_name_print);
    fprintf(logfile , "%d > ", source_port);
    fprintf(logfile , "%s : ", inet_ntoa(dest.sin_addr));
    fprintf(logfile , "%d\n", dest_port);
}
void print_tcp_packet(unsigned char* Buffer, const struct pcap_pkthdr *header, int Size)
{
    unsigned short ethhdrlen;
    unsigned short iphdrlen;

    auto ethernet = (struct sniff_ethernet*)(Buffer);
    ethhdrlen = sizeof(struct ethhdr);

    auto *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = (unsigned short) iph->ihl*4;

    auto *tcph = (struct tcphdr*)(Buffer + iphdrlen + ethhdrlen);

    int header_size = ethhdrlen + iphdrlen + tcph->doff*4;

    print_ip_header(Buffer, header, ntohs(tcph->source), ntohs(tcph->dest));

    fprintf(logfile , "\n");
    PrintData(Buffer, header_size);
    fprintf(logfile , "\n");
    PrintData(Buffer + header_size , Size - header_size );
    fprintf(logfile , "\n");
}

void print_udp_packet(unsigned char *Buffer, const struct pcap_pkthdr *header, int Size)
{
    unsigned short ethhdrlen;
    unsigned short iphdrlen;

    auto ethernet = (struct sniff_ethernet*)(Buffer);
    ethhdrlen = sizeof(struct ethhdr);

    auto * iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = (unsigned short) iph->ihl*4;

    auto * udph = (struct udphdr*)(Buffer + iphdrlen  + ethhdrlen);

    int header_size = ethhdrlen + iphdrlen + (uint16_t) sizeof(udph);

    print_ip_header(Buffer, header, ntohs(udph->source), ntohs(udph->dest));
    fprintf(logfile , "\n");
    PrintData(Buffer, header_size);
    fprintf(logfile , "\n");
    PrintData(Buffer + header_size , Size - header_size );
    fprintf(logfile , "\n");
}
void print_bytes(int size){
    if (size >= 0x0 && size <= 0xf)
        fprintf(logfile , "0x000%x:", size);
    else if (size >= 0x10 && size <= 0xff)
        fprintf(logfile , "0x00%x:", size);
    else if (size >= 0x100 && size <= 0xfff)
        fprintf(logfile , "0x0%x:", size);
    else
        fprintf(logfile , "0x%x:", size);
}


void PrintData (unsigned char* data , int Size)
{
    int i, j, k;
    for(i=0 ; i < Size ; i++)
    {
        if (i != 0 && i % 8 == 0 && i % 16 != 0)//mezera navíc ve výpisu hodnot
            fprintf(logfile, " ");
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "   ");
            for(j=i-16 ; j<i ; j++)
            {
                if (j != 0 && j % 8 == 0 && j % 16 != 0)//mezera navíc ve výpisu hodnot
                    fprintf(logfile, " ");
                if(data[j]>=32 && data[j]<=127)
                    fprintf(logfile , "%c",(unsigned char)data[j]);
                else
                    fprintf(logfile , ".");
            }
            fprintf(logfile , "\n");
        }

        if(i % 16 == 0){
            print_bytes(bytes_read); //pocet doposud vytisnutych bajtu napr. 0x0010
            bytes_read += 0x10;
            fprintf(logfile , "  ");
        }

        fprintf(logfile , " %02X",(unsigned int)data[i]);

        //specialni postup pro posledni radek dat, musi se vyplnit prazdny prostor
        if(i == Size - 1)
        {
            //padding mezer
            k = 0;
            for(j=0; j<15-i%16; j++){
                if (i != 0 && i % 8 == 0 && i % 16 != 0)//mezera navíc ve výpisu hodnot
                    fprintf(logfile, " ");
                fprintf(logfile , "   ");
                k++;
            }
            //na posledním řádku se nevytiskla prostřední mezera, je potřebaj i dotisknout
            if (k >= 8)
                fprintf(logfile, " ");

            //mezera mezi hexa a tisknutelnymi znaky
            fprintf(logfile , "   ");

            //tisknutelne znaky, jinak tecka
            for(j = i - i % 16; j <= i; j++)
            {
                if (j != 0 && j % 8 == 0 && j % 16 != 0)//mezera navíc ve výpisu hodnot
                    fprintf(logfile, " ");
                if(data[j] >= 32 && data[j] <= 127)
                    fprintf(logfile , "%c",(unsigned char)data[j]);
                else
                    fprintf(logfile , ".");
            }
            fprintf(logfile ,  "\n" );
        }
    }
}