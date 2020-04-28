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
#include <netinet/ip6.h>
#include <net/if_arp.h>
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

//definice globálních proměnných
struct sockaddr_in sock_source_4, sock_dest_4;
struct sockaddr_in6 sock_source_6, sock_dest_6;
int tcp_count = 0, udp_count = 0, total = 0, others = 0;
char * interface_arg;
int interface_flag = 0, tcp_flag = 0, udp_flag = 0, port_flag = 0, port_arg = 0, num_arg = 1, bytes_read = 0;
FILE * logfile = stdout;
FILE * error_logfile = stderr;

//definice dlouhých přepínačů
struct option long_options[] =
        {
                {"help", no_argument,        0, 'h'},
                {"tcp", no_argument,        0, 't'},
                {"udp",  no_argument,        0, 'u'},
                {"num",  optional_argument,  0, 'n'},
                {"port", optional_argument,  0, 'p'},
                {0, 0, 0, 0}  // ukoncovaci prvek
        };
//definice krátkých přepínačů
char *short_options = (char*)"hn:p:tui:";

/**
 * @brief Funkce slouží jako koncová procedura při zachycení signálu SIGINT
 * @param unused povinně přítomný argument, není dále využit
 */
void signal_callback_handler(int unused) {
    unused = unused; //obelstění překladače a jeho varování na nevyužitou proměnnou
    fprintf(logfile, "\n   Byl zaslán signál SIGINT, program se ukočuje.\n");
    exit(OK);
}

/**
 * @brief
 *      Podle dokumentace https://linux.die.net/man/3/pcap_loop musí mít tři argumenty
 * @param args argumenty od uživatele, v tomto programu VŽDY nullptr, dále se nevyužívá
 * @param header ukazatel na hlavičku rámce paketu
 * @param packet ukazatel na data paketu
 */
void callback(u_char * args, const struct pcap_pkthdr * header, const u_char * packet){
    args = args; //ditto parametr unused funkce signal_callback_handler()
    bytes_read = 0; //nulování počtu přečtených bajtů na 0x0000
    sa_family_t ip_version = AF_UNSPEC;
    bool is_arp = false;
    int protocol;
    auto * eth = (struct ethhdr *)packet;

    //todo tady se musí řešit IPv4 vs. IPv6 logika. Dál musí jít už přímé zpracování.
    eth->h_proto = (packet[12] << (unsigned int) 8) + packet[13]; //nastavení ether type z ethernetového rámce

    //Zjištění typu IP, případně ARP a typ protokolu
    if (eth->h_proto == ETH_P_IP){
        sock_source_4.sin_family = AF_INET;
        ip_version = AF_INET;
        protocol = packet[23];
    }
    else if (eth->h_proto == ETH_P_IPV6){
        sock_source_6.sin6_family = AF_INET6;
        ip_version = AF_INET6;
        protocol = packet[20];
    }
    else if (eth->h_proto == ETH_P_ARP)
        is_arp = true;
    else //Něco nepodporovaného, třeba LLDP, STP, ...
        return;

    //Zpracování podle typu paketu
    if (is_arp)
        ;//print_arp_packet(...);
    else if (protocol == IPPROTO_TCP){
        tcp_count++;
        print_tcp_packet((unsigned char *) packet, header, header->len, ip_version);
     }
    else if (protocol == IPPROTO_UDP){
        udp_count++;
        print_udp_packet((unsigned char *) packet, header, header->len, ip_version);
    }
    else
        others++;
}

int main(int argc, char * argv[]) {
    signal(SIGINT, signal_callback_handler);

    pcap_t * handle;			/* Session handle */
    char * dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp{};		/* The compiled filter */
    char filter_exp[PCAP_ERRBUF_SIZE] = "";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */

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
                        fprintf(error_logfile, "\n   Nesprávný formát čísla. Zadali jste %s.\n", optarg);
                        exit(BAD_ARG_VALUE);
                    }
                    break;
                case 'n':
                    if (p_tmp->status){
                        if (p_tmp->num < 0){
                            fprintf(error_logfile, "\n   Nesprávná hodnota čísla. Zadali jste %d.\n", p_tmp->num);
                            exit(BAD_ARG_VALUE);
                        }
                        num_arg = p_tmp->num;
                    }
                    else{
                        fprintf(error_logfile, "\n   Nesprávný formát čísla. Zadali jste %s.\n", optarg);
                        exit(BAD_ARG_VALUE);
                    }
                    break;
                case 't':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_logfile, "\n   Parametr -t | --tcp nepřijímá žádné argumenty.\n");
                        exit(BAD_ARG_VALUE);
                    }
                    tcp_flag = 1;
                    break;
                case 'u':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_logfile, "\n   Parametr -u | --udp nepřijímá žádné argumenty.\n");
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

    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *tmp;
    int i = 0;

    if (pcap_findalldevs(&interfaces, error) == -1){
        fprintf(error_logfile, "\n   Nastala chyba při zjišťování dostupných rozhraní.\n");
        exit(INTERFACE_ERROR);
    }
    if (interface_flag == 0){
        fprintf(logfile, "\n Dostupná rozhraní:");
        for(tmp = interfaces; tmp; tmp = tmp->next)
            fprintf(logfile, "\n   %d :  %s | %s", i++, tmp->name, tmp->description);
        fprintf(logfile, "\n");
        exit(OK);
    }
    else{
        bool is_valid = false;
        for(tmp = interfaces; tmp; tmp = tmp->next){
            if (strcmp(tmp->name, interface_arg) == 0){
                is_valid = true;
                break;
            }
        }
        if (!is_valid){
            fprintf(error_logfile, "\n   Zadané rozhraní - \"%s\" není dostupné.\n", interface_arg);
            exit(INTERFACE_ERROR);
        }
        dev = interface_arg;
    }

    //https://linux.die.net/man/3/pcap_lookupnet
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(error_logfile, "\n   Nepodařilo se získat masku podsítě pro rozhraní - \"%s\".\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFFER_SIZE, 1, 100, errbuf);
    if (handle == nullptr) {
        fprintf(error_logfile, "\n   Rozhraní - \"%s\" se nepodařilo otevřít.\n", dev);
        exit(INTERFACE_ERROR);
    }

    if ((!tcp_flag && !udp_flag) || (tcp_flag && udp_flag))
        sprintf(filter_exp, "(tcp or udp) ");
    else if (tcp_flag)
        sprintf(filter_exp, "tcp ");
    else if (udp_flag)
        sprintf(filter_exp, "udp ");

    if (port_flag)
        sprintf(filter_exp + strlen(filter_exp), "port %d ", port_arg);

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(error_logfile, "\n   Nepodařilo se přeložit filtr - \"%s\" na rozhraní - \"%s\".\n", filter_exp, dev);
        exit(INTERFACE_ERROR);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(error_logfile, "\n   Nepodařilo se aplikovat filtr - \"%s\" na rozhraní - \"%s\".\n", filter_exp, dev);
        exit(INTERFACE_ERROR);
    }

    //cyklus dokud pocet prectenych paketu neni roven num_arg
    pcap_loop(handle, num_arg, callback, nullptr); //https://linux.die.net/man/3/pcap_loop
    pcap_close(handle);
    exit(OK);
}

/**
 * @brief Funkce vytiskne úvodní údaje:
 *          - čas přijetí paketu
 *          - zdrojová a cílová adresa(nebo jméno, pokud se adresa podaří přeložit)
 *          - zdrojový a cílový port
 * @param buffer ukazatel na pole obsahující data příchozího paketu
 * @param frame ukazatel na strukturu představující zaobalující rámec celého paketu, 
 *              odsud funkce získává čas přijetí paketu
 * @param source_port zdrojový port
 * @param dest_port cílový port
 */
void
print_packet_preamble(unsigned char *buffer, const struct pcap_pkthdr *frame, uint16_t source_port, uint16_t dest_port,
                      sa_family_t ip_version){
    auto * eth = (struct ethhdr *)buffer;
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    auto * iph = (struct iphdr *)(buffer + ethhdrlen);
    auto * ip6h = (struct ip6_hdr *)(buffer + ethhdrlen);
    auto * arph = (struct arphdr *)(buffer + ethhdrlen);

    //"vyčistí" socket
    memset(&sock_source_4, 0, sizeof(sock_source_4));
    memset(&sock_dest_4, 0, sizeof(sock_dest_4));
    memset(&sock_source_6, 0, sizeof(sock_source_6));
    memset(&sock_dest_6, 0, sizeof(sock_dest_6));
    char * src_name_print;
    char * dest_name_print;
    char * dest_name_print_tmp[INET6_ADDRSTRLEN];
    char src_name[NI_MAXHOST];
    char dest_name[NI_MAXHOST];

    if (ip_version == AF_INET){ //IPv4
        sock_source_4.sin_family = AF_INET;
        sock_source_4.sin_addr.s_addr = iph->saddr; //nastaví ve struktuře IP adresu
        sock_dest_4.sin_family = AF_INET;
        sock_dest_4.sin_addr.s_addr = iph->daddr;

        //zdrojová adresa
        int rc_s = getnameinfo((struct sockaddr*)&sock_source_4, sizeof(sock_source_4),
                             src_name, sizeof(src_name),nullptr, 0, 0);
        if (rc_s != 0)
            src_name_print = inet_ntoa(sock_source_4.sin_addr);
        else
            src_name_print = src_name;

        //cílová adresa
        int rc_d = getnameinfo((struct sockaddr*)&sock_dest_4, sizeof(sock_dest_4),
                               dest_name, sizeof(dest_name),nullptr, 0, 0);
        if (rc_d != 0)
            dest_name_print = inet_ntoa(sock_dest_4.sin_addr);
        else
            dest_name_print = dest_name;
    }
    else if (ip_version == AF_INET6){
        sock_source_6.sin6_family = AF_INET6; //IPv6
        sock_source_6.sin6_addr = ip6h->ip6_src;
        sock_dest_6.sin6_family = AF_INET6;
        sock_dest_6.sin6_addr = ip6h->ip6_dst;

        //zdrojová adresa
        int rc_s = getnameinfo((struct sockaddr*)&sock_source_6, sizeof(sock_source_6),
                             src_name, sizeof(src_name),nullptr, 0, 0);
        if (rc_s != 0)
            src_name_print = inet_ntoa(sock_source_4.sin_addr);
        else
            src_name_print = src_name;
        //cílová adresa
        int rc_d = getnameinfo((struct sockaddr*)&sock_dest_6, sizeof(sock_dest_6),
                               dest_name, sizeof(dest_name),nullptr, 0, 0);
        if (rc_d != 0){
            inet_ntop(AF_INET6, &(sock_dest_6.sin6_addr), (char *)(dest_name_print_tmp),
                      INET6_ADDRSTRLEN);
            dest_name_print = (char *)(dest_name_print_tmp);
        }
        else
            dest_name_print = dest_name;
    }
    else{ //ARP
        ;//eth->h_dest
        //ARP je na OSI vrstve 2, pouziva fyzicke mac adresy pro komunikaci, ale zaroven se v data payload pta pomoci IP
        // takze je i na OSI vrstve 3, toto musim vymyslet.
    }

    //získání a zpracování "časové stopy" paketu
    tm * time = localtime(&(frame->ts.tv_sec));
    int hours = time->tm_hour;
    int minutes = time->tm_min;
    int seconds = time->tm_sec;
    long int microseconds = frame->ts.tv_usec;

    fprintf(logfile, "\n%d:%d:%d.%ld ", hours, minutes, seconds, microseconds);
    fprintf(logfile , "%s : %d > ", src_name_print, source_port);
    fprintf(logfile , "%s : %d\n", dest_name_print, dest_port);
}

/**
 * @brief Funkce tiskne nejprve ethernetovou, IP a TCP hlavičku, pak jeden prázdný řádek a následně samotná data.
 * @param buffer ukazatel na pole obsahující data příchozího paketu
 * @param frame ukazatel na strukturu představující zaobalující rámec celého paketu,
 *              odsud funkce získává čas přijetí paketu
 * @param size celková velikost paketu
 */
void print_tcp_packet(unsigned char *buffer, const struct pcap_pkthdr *frame, int size, sa_family_t ip_version)
{
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    unsigned short iphXhdrlen;

    //IPv4
    if (ip_version == AF_INET){
        auto * iph = (struct iphdr *)(buffer + sizeof(struct ethhdr) );
        iphXhdrlen = (unsigned short) iph->ihl * 4;
        //IP hlavička musí mít 20-60 bajtů
        if (iphXhdrlen < 20 || iphXhdrlen > 60) {
            fprintf(error_logfile,"\n   Neplatná délka IPv4 hlavičky, délka = %u bajtů\n", iphXhdrlen);
            exit(PACKET_ERROR);
        }
    }
    //musí být IPv6, jiná hodnota se do funkce nemůže dostat
    else
        iphXhdrlen = 40;


    auto * tcph = (struct tcphdr*)(buffer + iphXhdrlen + ethhdrlen);
    //doff = data offset, horní 4 bity 46.bajtu, násobeno 4, protože se jedná o počet 32-bitových slov, 32bitů = 4bajtů
    //viz https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    int tcphdrlen = tcph->doff * 4;

    int header_size = ethhdrlen + iphXhdrlen + tcphdrlen;

    print_packet_preamble(buffer, frame, ntohs(tcph->source), ntohs(tcph->dest), ip_version);

    fprintf(logfile , "\n");
    print_data(buffer, header_size);
    fprintf(logfile , "\n");
    print_data(buffer + header_size, size - header_size);
    fprintf(logfile , "\n");
}

/**
 * @brief Funkce tiskne nejprve ethernetovou, IP a UDP hlavičku, pak jeden prázdný řádek a následně samotná data.
 * @param buffer ukazatel na pole obsahující data příchozího paketu
 * @param frame ukazatel na strukturu představující zaobalující rámec celého paketu,
 *              odsud funkce získává čas přijetí paketu
 * @param size celková velikost paketu
 */
void print_udp_packet(unsigned char *buffer, const struct pcap_pkthdr *frame, int size, sa_family_t ip_version)
{
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    unsigned short iphXhdrlen;

    //IPv4
    if (ip_version == AF_INET){
        auto * iph = (struct iphdr *)(buffer + sizeof(struct ethhdr) );
        iphXhdrlen = (unsigned short) iph->ihl*4;
        //IP hlavička musí mít 20-60 bajtů
        if (iphXhdrlen < 20 || iphXhdrlen > 60) {
            fprintf(error_logfile,"\n   Neplatná délka IPv4 hlavičky, délka = %u bajtů\n", iphXhdrlen);
            exit(PACKET_ERROR);
        }
    }
    //musí být IPv6, jiná hodnota se do funkce nemůže dostat
    else
        iphXhdrlen = 40;

    auto * udph = (struct udphdr*)(buffer + iphXhdrlen + ethhdrlen);
    unsigned short udphdrlen = 8; //UDP hlavička má vždy 8 bajtů

    int header_size = ethhdrlen + iphXhdrlen + udphdrlen;

    print_packet_preamble(buffer, frame, ntohs(udph->source), ntohs(udph->dest), ip_version);
    fprintf(logfile , "\n");
    print_data(buffer, header_size);
    fprintf(logfile , "\n");
    print_data(buffer + header_size, size - header_size);
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


void print_data (unsigned char* data , int size)
{
    int i, j, k;
    for(i=0 ; i < size ; i++)
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
        if(i == size - 1)
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