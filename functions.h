//
// Created by rklem on 4/30/20.
//

#ifndef PROJ2_FUNCTIONS_H
#define PROJ2_FUNCTIONS_H

#include <bits/socket.h>

#define CACHE_SIZE 64
#define CACHE_SIZE_IP6 16

enum DnsCacheRemoveFlag {
    ADDRESS, HOSTNAME, BOTH
};

struct ip_generic_addr{
    union {
        u_int32_t addr;
        struct in6_addr addr6;
    } address;
};

struct dns_cache_record{
    char * address;
    char * hostname;
};

static dns_cache_record dns_cache[CACHE_SIZE];
static int dns_cache_size;
static int count;
static dns_cache_record dns_cache_ip6[CACHE_SIZE_IP6];
static int dns_cache_ip6_size;
static int count_ip6;

static void add(dns_cache_record record);
void remove(int index);
void remove(dns_cache_record record, DnsCacheRemoveFlag flag);
static int get(u_int32_t address, char * buffer);
static int get_ip6(struct in6_addr address, char * buffer);


/**
 * @brief
 * @param address
 * @param ip_version
 * @param host
 * @return
 */
int getnameinfo(ip_generic_addr address, sa_family_t ip_version, char *host);
#endif //PROJ2_FUNCTIONS_H
