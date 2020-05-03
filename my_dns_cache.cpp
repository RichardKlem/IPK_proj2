//
// Created by rklem on 5/1/20.
//
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <cstring>
#include <string>
#include "my_getnameinfo.h"
#include "my_dns_cache.h"

#include <cstdio>
#include <utility>

dns_cache_record dns_cache[CACHE_SIZE];
static int count = 0;
dns_cache_record dns_cache_ip6[CACHE_SIZE_IP6];
static int count_ip6 = 0;
static int dns_match = 0;
static int dns_miss = 0;

void dns_cache_add(dns_cache_record record) {
    dns_cache[count++ % CACHE_SIZE] = std::move(record);
}

void dns_cache_add_ip6(dns_cache_record record) {
    dns_cache_ip6[count_ip6++ % CACHE_SIZE_IP6] = std::move(record);
}

int dns_cache_get(u_int32_t address, char * buffer) {
    struct sockaddr_in sa_in{};
    char * hostname;
    char name[NI_MAXHOST];
    sa_in.sin_family = AF_INET;
    sa_in.sin_addr.s_addr = address; //nastaví ve struktuře IP adresu
    char * addr_string = inet_ntoa(sa_in.sin_addr);

    for (auto & i : dns_cache) {
        if (i.address.c_str() != nullptr and strcmp(i.address.c_str(), addr_string) == 0){
            strcpy(buffer, i.hostname.c_str());
            dns_match++;
            return 0;
        }
    }
    // Funkce getnameinfo http://man7.org/linux/man-pages/man3/getnameinfo.3.html
    int rc_s = getnameinfo((struct sockaddr *) &sa_in, sizeof(sa_in), name, sizeof(name), nullptr, 0, 0);
    if (rc_s != 0)
        hostname = inet_ntoa(sa_in.sin_addr);
    else
        hostname = name;

    strcpy(buffer, hostname);
    dns_cache_add(dns_cache_record{addr_string, hostname});
    dns_miss++;
    return 0;
}

int dns_cache_get_ip6(struct in6_addr address, char * buffer) {
    struct sockaddr_in6 sa_in6{};
    char * hostname;
    char * hostname_tmp[INET6_ADDRSTRLEN];
    char name[NI_MAXHOST];
    sa_in6.sin6_family = AF_INET6;
    sa_in6.sin6_addr = address; //nastaví ve struktuře IP adresu
    char * addr_string = (char *)inet_ntop(AF_INET6, &(sa_in6.sin6_addr), (char *)(hostname_tmp), INET6_ADDRSTRLEN);

    for (auto & i : dns_cache_ip6) {
        if (i.address.c_str() != nullptr and strcmp(i.address.c_str(), addr_string) == 0){
            strcpy(buffer, i.hostname.c_str()   );
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
    dns_cache_add_ip6(dns_cache_record{addr_string, name});
    return 0;
}