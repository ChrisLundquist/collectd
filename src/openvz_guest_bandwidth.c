/**
 * collectd - src/openvz_guest_bandwidth.c
 * Copyright (C) 2012       Chris Lundquist
 * Copyright (C) 2012       Dustin Lundquist
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Chris Lundquist <clundquist@bluebox.net>
 *   Dustin Lundquist <dlundquist@bluebox.net>
 **/


#include "collectd.h"
#include "common.h" /* auxiliary functions */
#include "plugin.h" /* plugin_register_*, plugin_dispatch_values */

#include <arpa/inet.h>        /* inet_pton, inet_ntop */
#include <libiptc/libiptc.h>  /* ip_t* */
#include <libiptc/libip6tc.h> /* ip6_t* */
#include "utils_avltree.h"    /* c_avl_* */

static int build_tree(void);
static void update_ip4();
static void update_ip6();
static void destroy_tree();

static int vps_ctid_cmp(const int *, const int *);
static int in6_addr_cmp(const struct in6_addr *, const struct in6_addr *);

static struct in_addr *ipv6_map(struct in6_addr *);
static struct in6_addr *ipv6_mapped(const struct in_addr *, struct in6_addr *);

struct vps {
    int ctid;
    char uuid[37];
    long tx_bytes;
    long rx_bytes;
    int ip_count;
};

static c_avl_tree_t *ip_lookup_table = NULL; /* maps IP to VPS since a VPS (often) has many IPs */
static c_avl_tree_t *vps_lookup_table = NULL; /* maps IP to VPS since a VPS (often) has many IPs */

/* This is a little wonky because this one host must submit values 
 * on behalf of several others
 */
static void ogb_vps_submit( struct vps* vps)
{
    value_t transmit_value[1];
    value_list_t transmit_value_list = VALUE_LIST_INIT;

    value_t receive_value[1];
    value_list_t receive_value_list = VALUE_LIST_INIT;

    transmit_value[0].counter = vps->tx_bytes;
    transmit_value_list.values = transmit_value;
    transmit_value_list.values_len = STATIC_ARRAY_SIZE(transmit_value);

    /* TODO send the real hostname */
    sstrncpy(transmit_value_list.host, "TestHost", sizeof(transmit_value_list.host));
    sstrncpy(transmit_value_list.plugin, "bandwidth", sizeof(transmit_value_list.plugin));
    sstrncpy(transmit_value_list.plugin_instance, "tx", sizeof(transmit_value_list.plugin_instance));
    sstrncpy(transmit_value_list.type, "counter", sizeof(transmit_value_list.type));

    plugin_dispatch_values(&transmit_value_list);

    receive_value[0].counter = vps->rx_bytes;
    receive_value_list.values = receive_value;
    receive_value_list.values_len = STATIC_ARRAY_SIZE(receive_value);

    sstrncpy(receive_value_list.host, "TestHost", sizeof(receive_value_list.host));
    sstrncpy(receive_value_list.plugin, "bandwidth", sizeof(receive_value_list.plugin));
    sstrncpy(receive_value_list.plugin_instance, "rx", sizeof(receive_value_list.plugin_instance));
    sstrncpy(receive_value_list.type, "counter", sizeof(receive_value_list.type));

    plugin_dispatch_values(&receive_value_list);
}

static int ogb_read(void)
{
    c_avl_iterator_t *iter = NULL;
    struct in6_addr *key = NULL;
    struct vps *vps = NULL;
    int failed = 0;
    /* build our map of IP -> VPS */
    failed = build_tree();
    if(failed)
        return failed;
    /* walk IP tables totalling transfer for the VPses we found */
    update_ip4();
    update_ip6();

    /* Output the totals per VPS */
    iter = c_avl_get_iterator(vps_lookup_table);
    while (c_avl_iterator_next(iter, (void **)&key, (void **)&vps) == 0) {
        ogb_vps_submit(vps);
    }

    /* clean up */
    c_avl_iterator_destroy(iter);
    destroy_tree();

    return 0;
}

void module_register (void)
{
    plugin_register_read ("openvz_guest_bandwidth", ogb_read);
} /* void module_register */


/*
 * Walks the IP tables chain looking for matches of the IP Addresses we found
 * in /prov/vz/veinfo, then totals the transfer for that VPS across all
 * of the IP addresses it has assigned.
 */
static void update_ip6() {
    struct ip6tc_handle *handle = NULL;
    ip6t_chainlabel chain;
    const struct ip6t_entry *entry = NULL;
    struct vps *vps = NULL;
    struct in6_addr slash128;

    memset(&slash128, 0xff, sizeof(slash128));

    handle = ip6tc_init("filter");

    strncpy(chain, "FORWARD", sizeof(chain));

    entry = ip6tc_first_rule(chain, handle);
    do {
        if (IN6_IS_ADDR_UNSPECIFIED(&entry->ipv6.src)
                && IN6_IS_ADDR_UNSPECIFIED(&entry->ipv6.smsk)
                && IN6_ARE_ADDR_EQUAL(&entry->ipv6.dmsk, &slash128)
                && c_avl_get(ip_lookup_table, (void *)&entry->ipv6.dst, (void *)&vps) == 0) {
            /* Destination address matches */
            vps->rx_bytes += entry->counters.bcnt;
        } else if (IN6_IS_ADDR_UNSPECIFIED(&entry->ipv6.dst)
                && IN6_IS_ADDR_UNSPECIFIED(&entry->ipv6.dmsk)
                && IN6_ARE_ADDR_EQUAL(&entry->ipv6.smsk, &slash128)
                && c_avl_get(ip_lookup_table, (void *)&entry->ipv6.src, (void *)&vps) == 0) {
            /* Source address matches */
            vps->tx_bytes += entry->counters.bcnt;
        }
    } while ((entry = ip6tc_next_rule(entry, handle)) != NULL);
    ip6tc_free(handle);
}

static void update_ip4() {
    struct iptc_handle *handle = NULL;
    ipt_chainlabel chain;
    const struct ipt_entry *entry = NULL;
    struct vps *vps = NULL;
    struct in6_addr ip;

    handle = iptc_init("filter");  

    strncpy(chain, "FORWARD", sizeof(chain));

    if (iptc_is_chain(chain, handle)) {
        /* printf("%s chain in %s table exists\n", chain, "filter"); */
    } 

    entry = iptc_first_rule(chain, handle);
    do {
        if (entry->ip.src.s_addr == INADDR_ANY
                && entry->ip.smsk.s_addr == INADDR_ANY
                && entry->ip.dmsk.s_addr == INADDR_BROADCAST
                && c_avl_get(ip_lookup_table, (void *)ipv6_mapped(&entry->ip.dst, &ip), (void *)&vps) == 0) {
            /* Destination address matches */
            vps->rx_bytes += entry->counters.bcnt;
        } else if (entry->ip.dst.s_addr == INADDR_ANY
                && entry->ip.dmsk.s_addr == INADDR_ANY
                && entry->ip.smsk.s_addr == INADDR_BROADCAST
                && c_avl_get(ip_lookup_table, (void *)ipv6_mapped(&entry->ip.src, &ip), (void *)&vps) == 0) {
            /* Source address matches */
            vps->tx_bytes += entry->counters.bcnt;
        }
    } while ((entry = iptc_next_rule(entry, handle)) != NULL);
    iptc_free(handle);
}

static void destroy_tree() {
    struct in6_addr *key = NULL;
    struct vps *vps = NULL;

    while(c_avl_pick(ip_lookup_table, (void **)&key, (void **)&vps) == 0) {
        free(key);

        vps->ip_count--;

        if(vps->ip_count == 0) {
            c_avl_remove(vps_lookup_table, &vps->ctid, NULL, NULL);
            free(vps);
        }
    }
    c_avl_destroy(ip_lookup_table);
    c_avl_destroy(vps_lookup_table);
}

static int build_tree() {
    FILE *veinfo = NULL;
    char buffer[256];
    char *token = NULL;
    char *tok_pos = NULL;
    struct vps *vps = NULL; /* The vps we are working on */
    int field = 0; /* which column of veinfo we are on */
    int status = 0; /* stores status of insert */
    struct in6_addr ip;
    struct in6_addr *key = NULL;

    /* We expect /proc/vz/veinfo to hold something like 
     * 377368     0    54        2607:f700:1:5c:25:90ff:fe49:6561   199.91.170.72   199.91.170.71
     *      0     0   521
     */
    veinfo = fopen("/proc/vz/veinfo", "r");
    if (veinfo == NULL) {
        ERROR("openvz_guest_bandwidth: fopen /proc/vz/veinfo");
        return(-1);
    }

    /* now we are sure it is worth building a tree */
    ip_lookup_table = c_avl_create((int (*) (const void *, const void *))in6_addr_cmp);
    if(ip_lookup_table == NULL) {
        ERROR ("openvz_guest_bandwidth: c_avl_create failed");
        return(-2);
    }

    vps_lookup_table = c_avl_create((int (*) (const void *, const void *))vps_ctid_cmp);
    if(vps_ctid_cmp == NULL) {
        ERROR ("openvz_guest_bandwidth: c_avl_create failed");
        return (-3);
    }

    while (fgets(buffer, sizeof(buffer), veinfo) != NULL) {
        token = strtok_r(buffer, " \t\n", &tok_pos);
        vps = NULL;
        for (field = 0; token != NULL; field ++) {
            switch(field) {
                case 0: /* VEID */
                    vps = malloc(sizeof(struct vps));
                    vps->ctid = atol(token);
                    vps->ip_count = 0;
                    vps->tx_bytes = 0;
                    vps->rx_bytes = 0;
                    break;
                case 1: /* Class */
                case 2: /* Num Processes */
                    /* Ignore Both */
                    break;
                default: /* additional fields are IPs */
                    key = NULL;
                    /* Try parsing our IP address as both address families */
                    if (inet_pton(AF_INET6, token, &ip) == 1) {
                        key = malloc(sizeof(ip));
                        bcopy(&ip, key, sizeof(ip));
                        status = c_avl_insert(ip_lookup_table, key, vps);
                    } else if (inet_pton(AF_INET, token, ipv6_map(&ip)) == 1) {
                        key = malloc(sizeof(ip));
                        bcopy(&ip, key, sizeof(ip));
                        status = c_avl_insert(ip_lookup_table, key, vps);
                    } else {
                        ERROR ("openvz_guest_bandwidth: Could not parse %s\n", token);
                        continue;
                    }

                    /* Insert the record and check for success */
                    if( status < 0 ){	
                        ERROR ("openvz_guest_bandwidth: failed inserting\n");
                        if(key != NULL)
                            free(key);
                    } else if( status > 0) {
                        ERROR ("openvz_guest_bandwidth: failed inserting duplicate\n");
                        if(key != NULL)
                            free(key);
                    } else {
                        vps->ip_count++;
                    }
            } /* switch field */
            token = strtok_r(NULL, " \t\n", &tok_pos);
        } /* for fields */

        /* free VPS if IP count is zero */
        if (vps != NULL && vps->ip_count == 0)
            free(vps);
        else {
            status = c_avl_insert(vps_lookup_table, &vps->ctid, vps);
            if (status < 0) {	
                ERROR ("openvz_guest_bandwidth: failed inserting\n");
            } else if ( status > 0) {
                ERROR ("openvz_guest_bandwidth: failed inserting duplicate\n");
            }
        }
    } /* while(fgets) */

    fclose(veinfo);
    return 0;
} /* build_tree() */

/* Turns an IPv4 address in ddd.ddd.ddd.ddd to a mapped IPv6 address
 * in the form of ::ffff:ddd.ddd.ddd.ddd
 */
static struct in_addr * ipv6_map(struct in6_addr *ipv6) {
    unsigned char mapped_template[] = {
        0, 0, 0,    0,
        0, 0, 0,    0,
        0, 0, 0xff, 0xff,
        0, 0, 0,    0 };

    bcopy(mapped_template, ipv6, sizeof(mapped_template));

    return &((struct in_addr *)ipv6)[3];
}

static struct in6_addr * ipv6_mapped(const struct in_addr *ipv4, struct in6_addr *ipv6) {
    unsigned char mapped_template[] = {
        0, 0, 0,    0,
        0, 0, 0,    0,
        0, 0, 0xff, 0xff,
        0, 0, 0,    0 };

    bcopy(mapped_template, ipv6, sizeof(mapped_template));
    bcopy(ipv4, &((struct in_addr *)ipv6)[3], sizeof(ipv4));

    return ipv6;
}


/* compare two IPv6 address */
static int in6_addr_cmp(const struct in6_addr *a, const struct in6_addr *b) {
    int i;

    for (i = 0; i < 4; i ++) {
        if (((uint32_t *)a)[i] > ((uint32_t *)b)[i])
            return 1;
        else if (((uint32_t *)a)[i] < ((uint32_t *)b)[i])
            return -1;
    }
    return 0;
}

/* Compare two int pointers, used to build an AVL tree of VPSes based on their CTID */
static int vps_ctid_cmp(const int *a, const int *b) {
    if (*a > *b)
        return 1;
    else if (*a < *b)
        return -1;
    else
        return 0;
}

