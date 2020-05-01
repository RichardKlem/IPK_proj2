//
// Created by rklem on 5/1/20.
//

#ifndef PROJ2_MY_ARP_H
#define PROJ2_MY_ARP_H

#include <net/if_arp.h>

/**
 * @brief Struktura reprezentující ARP paket.
 *   Předpokládá IPv4 adresy, protože pro IPv6 se používá NDP.
 *   Celková délka ARP paketu je 28 bajtů.
 */
struct arp{
    struct arphdr * arphdr = (struct arphdr *)arphdr;  // 8 bajtů
    unsigned char src_mac[6]{};  // 6 bajtů
    unsigned char src_ip[4]{};   // 4 bajty
    unsigned char dst_mac[6]{};  // 6 bajtů
    unsigned char dst_ip[4]{};   // 4 bajty
};

#endif //PROJ2_MY_ARP_H
