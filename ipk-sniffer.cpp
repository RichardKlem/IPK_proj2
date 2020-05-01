//
// Created by richardklem on 23.04.20.
//
#include<netinet/in.h>
#include<netdb.h>
#include<cstdio> //For standard things
#include<cstdlib>    //malloc
#include <cstring>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp_count header
#include<netinet/ip.h>    //Provides declarations for ip header
#include <netinet/ip6.h>
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<ctime>
#include<sys/types.h>
#include <pcap.h>
#include <getopt.h>
#include <csignal>
#include <netinet/ether.h>
#include "my_getnameinfo.h"
#include "my_arp.h"
#include "my_string.h"
#include "ipk-sniffer.h"


//definice globálních proměnných
struct sockaddr_in sock_source_4, sock_dest_4;
struct sockaddr_in6 sock_source_6, sock_dest_6;
int tcp_count = 0, udp_count = 0, total = 0, others = 0;
char * interface_arg;
int interface_flag = 0, tcp_flag = 0, udp_flag = 0, arp_flag = 0, ip6_flag = 0, ip4_flag = 0, all_flag = 0, port_flag = 0, port_arg = 0, num_arg = 1, bytes_read = 0;
FILE * logfile = stdout;
FILE * error_logfile = stderr;

//definice dlouhých přepínačů
struct option long_options[] =
        {
                {"help", no_argument,        0, 'h'},
                {"tcp", no_argument,        0, 't'},
                {"udp",  no_argument,        0, 'u'},
                {"arp",  no_argument,        0, 'a'},
                {"ip6",  no_argument,        0, '6'},
                {"ip4",  no_argument,        0, '4'},
                {"all",  no_argument,        0, 'A'},
                {"num",  optional_argument,  0, 'n'},
                {"port", optional_argument,  0, 'p'},
                {0, 0, 0, 0}  // ukoncovaci prvek
        };
//definice krátkých přepínačů
char *short_options = (char*)"htua64An:p:i:";



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

    eth->h_proto = (packet[12] << (unsigned int) 8) + packet[13]; //nastavení ether type z ethernetového rámce

    //Zpracování ether typu
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
    else{  // něco nepodporovaného
        others++;
        return;  // není třeba zpracovat, ale je potřeba inkrementovat pouze jednou
    }


    // Zpracování podle typu protokolu
    if (is_arp)
        print_arp_packet((unsigned char *) packet, header, header->len);
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

    // zpracování argumentů
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
                        fprintf(error_logfile, "\n%s   Nesprávný formát čísla. Zadali jste %s.%s\n\n", RED, optarg, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    break;
                case 'n':
                    if (p_tmp->status){
                        if (p_tmp->num < 0){
                            fprintf(error_logfile, "\n%s   Nesprávná hodnota čísla. Zadali jste %d.%s\n\n", RED, p_tmp->num, RST);
                            exit(BAD_ARG_VALUE);
                        }
                        num_arg = p_tmp->num;
                    }
                    else{
                        fprintf(error_logfile, "\n%s   Nesprávný formát čísla. Zadali jste %s.%s\n\n", RED, optarg, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    break;
                case 't':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_logfile, "\n%s   Parametr -t | --tcp nepřijímá žádné argumenty.%s\n\n", RED, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    tcp_flag = 1;
                    break;
                case 'u':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_logfile, "\n%s   Parametr -u | --udp nepřijímá žádné argumenty.%s\n\n", RED, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    udp_flag = 1;
                    break;
                case 'a':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_logfile, "\n%s   Parametr -a | --arp nepřijímá žádné argumenty.%s\n\n", RED, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    arp_flag = 1;
                    break;
                case '6':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_logfile, "\n%s   Parametr -6 | --ip6 nepřijímá žádné argumenty.%s\n\n", RED, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    ip6_flag = 1;
                    break;
                case '4':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_logfile, "\n%s   Parametr -4 | --ip4 nepřijímá žádné argumenty.%s\n\n", RED, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    ip4_flag = 1;
                    break;
                case 'A':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_logfile, "\n%s   Parametr -A | --all nepřijímá žádné argumenty.%s\n\n", RED, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    all_flag = 1;
                    break;
                default:
                    exit(UNKNOWN_PARAMETER);
            }
        }
        if (!tcp_flag and !udp_flag){
            tcp_flag = 1;
            udp_flag = 1;
        }
    }

    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t * interfaces, * tmp;
    int i = 0;

    if (pcap_findalldevs(&interfaces, error) == -1){
        fprintf(error_logfile, "\n%s   Nastala chyba při zjišťování dostupných rozhraní.%s\n\n", RED, RST);
        exit(INTERFACE_ERROR);
    }
    if (interface_flag == 0){
        int maxlen = 0;
        fprintf(logfile, "\n\033[0;93m Specifikujte rozhraní.%s\n Dostupná rozhraní:\n", RST);
        for(tmp = interfaces; tmp; tmp = tmp->next){
            if ((int)strlen(tmp->name) > maxlen)
                maxlen = (int)strlen(tmp->name) - maxlen;
        }
        for(tmp = interfaces; tmp; tmp = tmp->next) {
            fprintf(logfile, "   %d :  %s", i++, tmp->name);
            for (int j = maxlen - (int)strlen(tmp->name); 0 < j; j--)
                fprintf(logfile, " ");
            fprintf(logfile, " | %s\n", tmp->description);
        }
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
            fprintf(error_logfile, "\n%s   Zadané rozhraní \"%s\" není dostupné.%s\n\n", RED, interface_arg, RST);
            exit(INTERFACE_ERROR);
        }
        dev = interface_arg;
    }

    // https://linux.die.net/man/3/pcap_lookupnet
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(error_logfile, "\n%s   Nepodařilo se získat masku podsítě pro rozhraní - \"%s\".%s\n\n", RED, dev, RST);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFFER_SIZE, 1, 100, errbuf);
    if (handle == nullptr) {
        fprintf(error_logfile, "\n%s   Rozhraní \"%s\" se nepodařilo otevřít.%s\n\n", RED, dev, RST);
        exit(INTERFACE_ERROR);
    }

    if (ip4_flag and ip6_flag)
        sprintf(filter_exp, "(ether proto \\ip or ether proto \\ip6) and ");
    else if (ip4_flag)
        sprintf(filter_exp, "ether proto \\ip and ");
    else if (ip6_flag)
        sprintf(filter_exp, "ether proto \\ip6 and ");

    if (all_flag)
    {}
    else if (arp_flag)
        sprintf(filter_exp, "ether proto \\arp");
    else{
        if (port_flag){
            if ((!tcp_flag and !udp_flag) or (tcp_flag and udp_flag))
                sprintf(filter_exp + strlen(filter_exp), "(udp port %d or tcp port %d)", port_arg, port_arg);
            else if (tcp_flag)
                sprintf(filter_exp + strlen(filter_exp), "tcp port %d", port_arg);
            else if (udp_flag)
                sprintf(filter_exp + strlen(filter_exp), "udp port %d", port_arg);
        }
        else{
            if ((!tcp_flag and !udp_flag) or (tcp_flag and udp_flag))
                sprintf(filter_exp + strlen(filter_exp), "(udp or tcp)");
            else if (tcp_flag)
                sprintf(filter_exp + strlen(filter_exp), "tcp");
            else if (udp_flag)
                sprintf(filter_exp + strlen(filter_exp), "udp");
        }
    }


    //printf("%s", filter_exp); //todo debug
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(error_logfile, "\n   Nepodařilo se přeložit filtr \"%s\" na rozhraní \"%s\".\n\n", filter_exp, dev);
        exit(INTERFACE_ERROR);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(error_logfile, "\n   Nepodařilo se aplikovat filtr \"%s\" na rozhraní \"%s\".\n\n", filter_exp, dev);
        exit(INTERFACE_ERROR);
    }

    // cyklus dokud počet přijatých paketu není roven num_arg
    pcap_loop(handle, num_arg, callback, nullptr); //https://linux.die.net/man/3/pcap_loop
    pcap_close(handle);
    exit(OK);
}

/**
 * @brief Funkce vytiskne úvodní údaje:
 *          - čas přijetí paketu
 *          - zdrojová a cílová adresa(nebo jméno, pokud se adresa podaří přeložit)
 *          - zdrojový a cílový port
 * @param packet ukazatel na pole obsahující data příchozího paketu
 * @param frame ukazatel na strukturu představující zaobalující rámec celého paketu, 
 *              odsud funkce získává čas přijetí paketu
 * @param source_port zdrojový port
 * @param dest_port cílový port
 */
void print_packet_preamble(unsigned char *packet, const struct pcap_pkthdr *frame, sa_family_t ip_version,
                           uint16_t dest_port = 0, uint16_t source_port = 0) {
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    char * src_name_print;
    char * dest_name_print;
    char src_name[NI_MAXHOST];
    char dest_name[NI_MAXHOST];

    if (ip_version == AF_INET){
        auto * iph = (struct iphdr *)(packet + ethhdrlen);
        ip_generic_addr addr{};
        addr.address.addr = iph->saddr;

        getnameinfo(addr, ip_version, src_name);
        src_name_print = src_name;

        addr = {};
        addr.address.addr = iph->daddr;

        getnameinfo(addr, ip_version, dest_name);
        dest_name_print = dest_name;

    }
    else if (ip_version == AF_INET6){
        auto * ip6h = (struct ip6_hdr *)(packet + ethhdrlen);
        ip_generic_addr addr{};
        addr.address.addr6 = ip6h->ip6_src;

        getnameinfo(addr, ip_version, src_name);
        src_name_print = src_name;

        addr = {};
        addr.address.addr6 = ip6h->ip6_dst;

        getnameinfo(addr, ip_version, dest_name);
        dest_name_print = dest_name;
    }
    //ARP
    else{
        auto * arp = (struct arp *)(packet + ethhdrlen);
        tm * time = localtime(&(frame->ts.tv_sec));
        int hours = time->tm_hour;
        int minutes = time->tm_min;
        int seconds = time->tm_sec;
        long int microseconds = frame->ts.tv_usec;

        char tmp[INET_ADDRSTRLEN];
        fprintf(logfile, "\n%02d:%02d:%02d.%06ld ", hours, minutes, seconds, microseconds);
        fprintf(logfile , "%s(%s) > ", inet_ntop(AF_INET, &(arp->src_ip), (char *)(tmp), INET_ADDRSTRLEN), ether_ntoa((ether_addr*)arp->src_mac));
        fprintf(logfile , "%s(%s)\n", inet_ntop(AF_INET, &(arp->dst_ip), (char *)(tmp), INET_ADDRSTRLEN), ether_ntoa((ether_addr*)arp->dst_mac));
        return;
    }

    //získání a zpracování "časové stopy" paketu
    tm * time = localtime(&(frame->ts.tv_sec));
    int hours = time->tm_hour;
    int minutes = time->tm_min;
    int seconds = time->tm_sec;
    long int microseconds = frame->ts.tv_usec;

    fprintf(logfile, "\n%02d:%02d:%02d.%06ld ", hours, minutes, seconds, microseconds);
    fprintf(logfile , "%s : %d > ", src_name_print, source_port);
    fprintf(logfile , "%s : %d\n", dest_name_print, dest_port);
}

/**
 * @brief Funkce tiskne nejprve ethernetovou, IP a TCP hlavičku, pak jeden prázdný řádek a následně samotná data.
 * @param packet ukazatel na pole obsahující data příchozího paketu
 * @param frame ukazatel na strukturu představující zaobalující rámec celého paketu,
 *              odsud funkce získává čas přijetí paketu
 * @param size celková velikost paketu
 */
void print_tcp_packet(unsigned char * packet, const struct pcap_pkthdr * frame, int size, sa_family_t ip_version)
{
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    unsigned short iphXhdrlen;

    //IPv4
    if (ip_version == AF_INET){
        auto * iph = (struct iphdr *)(packet + sizeof(struct ethhdr) );
        iphXhdrlen = (unsigned short) iph->ihl * 4;
        //IP hlavička musí mít 20-60 bajtů
        if (iphXhdrlen < 20 or iphXhdrlen > 60) {
            fprintf(error_logfile,"\n   Neplatná délka IPv4 hlavičky, délka = %u bajtů\n", iphXhdrlen);
            exit(PACKET_ERROR);
        }
    }
    //musí být IPv6, jiná hodnota se do funkce nemůže dostat
    else
        iphXhdrlen = 40;

    auto * tcph = (struct tcphdr *)(packet + iphXhdrlen + ethhdrlen);

    //doff = data offset, horní 4 bity 46.bajtu, násobeno 4, protože se jedná o počet 32-bitových slov, 32bitů = 4bajtů
    //viz https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    int tcphdrlen = tcph->doff * 4;

    int header_size = ethhdrlen + iphXhdrlen + tcphdrlen;

    print_packet_preamble(packet, frame, ip_version, ntohs(tcph->dest), ntohs(tcph->source));

    fprintf(logfile , "\n");
    print_data(packet, header_size);
    fprintf(logfile , "\n");
    print_data(packet + header_size, size - header_size);
    fprintf(logfile , "\n");
}

/**
 * @brief Funkce tiskne nejprve ethernetovou, IP a UDP hlavičku, pak jeden prázdný řádek a následně samotná data.
 * @param packet ukazatel na pole obsahující data příchozího paketu
 * @param frame ukazatel na strukturu představující zaobalující rámec celého paketu,
 *              odsud funkce získává čas přijetí paketu
 * @param size celková velikost paketu
 */
void print_udp_packet(unsigned char * packet, const struct pcap_pkthdr * frame, int size, sa_family_t ip_version)
{
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    unsigned short iphXhdrlen;

    //IPv4
    if (ip_version == AF_INET){
        auto * iph = (struct iphdr *)(packet + sizeof(struct ethhdr) );
        iphXhdrlen = (unsigned short) iph->ihl * 4;
        //IP hlavička musí mít 20-60 bajtů
        if (iphXhdrlen < 20 or iphXhdrlen > 60) {
            fprintf(error_logfile,"\n   Neplatná délka IPv4 hlavičky, délka = %u bajtů\n", iphXhdrlen);
            exit(PACKET_ERROR);
        }
    }
    //musí být IPv6, jiná hodnota se do funkce nemůže dostat
    else
        iphXhdrlen = 40;

    auto * udph = (struct udphdr*)(packet + iphXhdrlen + ethhdrlen);
    unsigned short udphdrlen = 8; //UDP hlavička má vždy 8 bajtů

    int header_size = ethhdrlen + iphXhdrlen + udphdrlen;

    print_packet_preamble(packet, frame, ip_version, ntohs(udph->dest), ntohs(udph->source));
    fprintf(logfile , "\n");
    print_data(packet, header_size);
    fprintf(logfile , "\n");
    print_data(packet + header_size, size - header_size);
    fprintf(logfile , "\n");
}
/**
 * @brief Funkce tiskne ethernetovou a ARP hlavičku, pak jeden prázdný řádek a následně samotná data.
 * @param packet ukazatel na pole obsahující data příchozího paketu
 * @param frame ukazatel na strukturu představující zaobalující rámec celého paketu,
 *              odsud funkce získává čas přijetí paketu
 * @param size celková velikost paketu
 */
void print_arp_packet(unsigned char *packet, const struct pcap_pkthdr *frame, int size) {
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    unsigned short arphdrlen = 28;

    int header_size = ethhdrlen + arphdrlen;

    print_packet_preamble(packet, frame, AF_UNSPEC);
    fprintf(logfile , "\n");
    print_data(packet, header_size);
    fprintf(logfile , "\n");
    print_data(packet + header_size, size - header_size);
    fprintf(logfile , "\n");
}

/**
 * @brief Vytiskne číslo v hexadecimálním tvaru s fixní délkou 4 s vyplňujícími nulami před číslem
 * @param size číslo, které se má vytisknout
 */
void print_bytes(int size){
    fprintf(logfile, "0x%04x", size);
}

/**
 * @brief Funkce tiskne formátovný výstup dle specifikace snifferu.
 * @param data ukazatel na začátek dat k vytištění
 * @param size délka dat
 */
void print_data(unsigned char *data, int size)
{
    int i, j, k;
    for(i = 0 ; i < size ; i++)
    {
        if (i != 0 and i % 8 == 0 and i % 16 != 0)//po 8 bajtech mezera navíc
            fprintf(logfile, " ");

        if(i != 0 and i % 16 == 0){
            fprintf(logfile , "   ");
            for(j = i - 16; j < i; j++){
                if (j != 0 and j % 8 == 0 and j % 16 != 0)//mezera navíc ve výpisu hodnot
                    fprintf(logfile, " ");
                if(data[j] >= 32 and data[j] <= 127)
                    fprintf(logfile , "%c",(unsigned char)data[j]);
                else
                    fprintf(logfile , ".");
            }
            fprintf(logfile , "\n");
        }

        if(i % 16 == 0){
            print_bytes(bytes_read); //počet doposud vytisnutych bajtu napr. 0x0010
            bytes_read += 0x10;
            fprintf(logfile , "  ");
        }

        fprintf(logfile , " %02X",(unsigned int)data[i]);

        //speciální postup pro poslední řadek dat, musí se vyplnit prázdný prostor
        if(i == size - 1){
            //padding mezer
            k = 0;
            for(j = 0; j < 15 - i % 16; j++){
                if (i != 0 and i % 8 == 0 and i % 16 != 0)//mezera navíc ve výpisu hodnot
                    fprintf(logfile, " ");
                fprintf(logfile , "   ");
                k++;
            }
            //na posledním řádku se nevytiskla prostřední mezera, je potřeba ji dotisknout
            if (k >= 8)
                fprintf(logfile, " ");

            //mezera mezi hexa a tisknutelnými znaky
            fprintf(logfile , "   ");

            //tisknutelne znaky, jinak tecka
            for(j = i - i % 16; j <= i; j++){
                if (j != 0 and j % 8 == 0 and j % 16 != 0)//mezera navíc ve výpisu hodnot
                    fprintf(logfile, " ");
                if(data[j] >= 32 and data[j] <= 127)
                    fprintf(logfile , "%c",(unsigned char)data[j]);
                else
                    fprintf(logfile , ".");
            }
            fprintf(logfile ,  "\n" );
        }
    }
    if (i % 16 != 0)
        bytes_read -= 0x10 - i % 16; //korekce výpisu počtu přečtených bajtů kvůli rozdělení hlavičky a dat do dvou bloků
}