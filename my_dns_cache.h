//
// Created by rklem on 5/1/20.
//

#ifndef PROJ2_MY_DNS_CACHE_H
#define PROJ2_MY_DNS_CACHE_H

#include <string>
#include <sys/socket.h>

/**
 * @brief Struktura zapouzřující dvojici adresa:doménové jméno
 *  Pokud se nepodařil překlad adresy, bude struktura obsahovat dvojici adresa:adresa.
 */
struct dns_cache_record{
    std::string address;
    std::string hostname;
};

/**
 * @brief Struktura představující generickou IP adresu, buď IPv4 anebo IPv6
 */
struct ip_generic_addr{
    union {
        u_int32_t addr;
        struct in6_addr addr6;
    } address;
};

// Funce vloží strukturu dns_cache_record do IPv4 DNS cache
void dns_cache_add(dns_cache_record record);

// Funce vloží strukturu dns_cache_record do IPv6 DNS cache
void dns_cache_add_ip6(dns_cache_record record);

// Pokud v IPv4 DNS cache nalezne hledanou adresu, použije její uložený překlad.
// Jinak provede překlad a výsledek uloží pomocí dns_cache_add().
int dns_cache_get(u_int32_t address, char * buffer);

// Pokud v IPv6 DNS cache nalezne hledanou adresu, použije její uložený překlad.
// Jinak provede překlad a výsledek uloží pomocí dns_cache_add_ip6().
int dns_cache_get_ip6(struct in6_addr address, char * buffer);

#endif //PROJ2_MY_DNS_CACHE_H
