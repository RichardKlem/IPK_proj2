//
// Created by rklem on 4/30/20.
//

#ifndef PROJ2_MY_GETNAMEINFO_H
#define PROJ2_MY_GETNAMEINFO_H

#include <sys/socket.h>
#include "my_dns_cache.h"

#define CACHE_SIZE 64
#define CACHE_SIZE_IP6 16

// Provádí překlad adresy na doménové jméno, pracuje s vlastní DNS IPv4/6 cache.
int getnameinfo(ip_generic_addr address, sa_family_t ip_version, char *host);
#endif //PROJ2_MY_GETNAMEINFO_H
