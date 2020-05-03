//
// Created by rklem on 4/30/20.
//
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include "my_getnameinfo.h"
#include "my_dns_cache.h"

/**
 * @brief Funkce reimplementuje funkcionalitu GNU getnameinfo z knihovny netdb.h pro potřeby snifferu.
 *   Obstarává i jendoduchou DNS cache, aby nevznikalo zacyklení a zahlecní sítě neustálým dotazováním
 *   na jméno a opětovným zachycením tohoto paketu etc.
 * @param address generická struktura obsahující IPv4 nebo IPv6 adresu
 * @param ip_version Verze IP adresy
 * @param host Pokud se podaří adresu přeložit, uloží se do této proměnné doménové jméno. Jinak původní adresa.
 * @return Vrací 1, pokud je zadaná adresa IPv4 nebo IPv6, jinak 0. V paměti host je uložen výsledek
 */
int getnameinfo(ip_generic_addr address, sa_family_t ip_version, char * host) {
    struct sockaddr_in6 sa_in6{};
    char * name_print;
    char name[NI_MAXHOST];

    if (ip_version == AF_INET){
        dns_cache_get(address.address.addr, name);
        name_print = name;
    }
    else if (ip_version == AF_INET6){
        sa_in6.sin6_family = AF_INET6; //IPv6
        sa_in6.sin6_addr = address.address.addr6;

        dns_cache_get_ip6(address.address.addr6, name);
        name_print = name;
    }
    else
        return 0;

    strcpy(host, name_print);
    return 1;
}
