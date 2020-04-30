//
// Created by rklem on 4/30/20.
//
#include <cstring>
#include <netinet/if_ether.h>
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp_count header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <map>
#include <netdb.h>
#include <netinet/in.h>
#include <vector>

#include "functions.h"

#include <cstdio>


int getnameinfo(ip_generic_addr address, sa_family_t ip_version, char * host) {
    static std::vector<std::map<sockaddr_in, char *>> ip_dns_cache;
    static std::vector<std::map<sockaddr_in6, char *>> ip6_dns_cache;
    struct sockaddr_in sa_in{};
    struct sockaddr_in6 sa_in6{};

    //inicializce soketu
    /*memset(&sa_in, 0, sizeof(sa_in));
    memset(&sa_in6, 0, sizeof(sa_in6));*/

    char * name_print;
    char name[NI_MAXHOST];

    if (ip_version == AF_INET){
        get(address.address.addr, name);
        name_print = name;
    }
    else if (ip_version == AF_INET6){
        sa_in6.sin6_family = AF_INET6; //IPv6
        sa_in6.sin6_addr = address.address.addr6;

        get_ip6(address.address.addr6, name);
        name_print = name;
    }
    else
        return 0;

    strcpy(host, name_print);
    return 1;
}

void add(dns_cache_record record) {
    dns_cache[count++ % CACHE_SIZE] = record;
}

void add_ip6(dns_cache_record record) {
    dns_cache_ip6[count_ip6++ % CACHE_SIZE_IP6] = record;
}

void remove(int index) {

}

void remove(dns_cache_record record, DnsCacheRemoveFlag flag) {

}

int get(u_int32_t address, char * buffer) {
    struct sockaddr_in sa_in{};
    char * hostname;
    char name[NI_MAXHOST];
    sa_in.sin_family = AF_INET;
    sa_in.sin_addr.s_addr = address; //nastaví ve struktuře IP adresu
    char * addr_string = inet_ntoa(sa_in.sin_addr);

    for (auto & i : dns_cache) {
        if (i.address != nullptr and strcmp(i.address, addr_string) == 0){
            strcpy(buffer, i.hostname);
            return 0;
        }
    }

    int rc_s = getnameinfo((struct sockaddr *) &sa_in, sizeof(sa_in), name, sizeof(name), nullptr, 0, 0);
    if (rc_s != 0)
        hostname = inet_ntoa(sa_in.sin_addr);
    else
        hostname = name;

    strcpy(buffer, hostname);
    add(dns_cache_record{addr_string, name});
    return 0;
}

int get_ip6(struct in6_addr address, char * buffer) {
    struct sockaddr_in6 sa_in6{};
    char * hostname;
    char * hostname_tmp[INET6_ADDRSTRLEN];
    char name[NI_MAXHOST];
    sa_in6.sin6_family = AF_INET6;
    sa_in6.sin6_addr = address; //nastaví ve struktuře IP adresu
    char * addr_string = (char *)inet_ntop(AF_INET6, &(sa_in6.sin6_addr), (char *)(hostname_tmp), INET6_ADDRSTRLEN);

    for (auto & i : dns_cache_ip6) {
        if (i.address != nullptr and strcmp(i.address, addr_string) == 0){
            strcpy(buffer, i.hostname);
            return 0;
        }
    }

    int rc_s = getnameinfo((struct sockaddr *)&sa_in6, sizeof(sa_in6),
                           name, sizeof(name), nullptr, 0, 0);
    if (rc_s != 0){

        hostname = (char *)hostname_tmp;
    }
    else
        hostname = name;
    strcpy(buffer, hostname);
    add_ip6(dns_cache_record{addr_string, name});
    return 0;
}