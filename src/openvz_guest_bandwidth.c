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

struct vps {
    int ctid; /* TODO check OpenVZ source for CTID type */
    char uuid[37]; /* string repesentiation of UUID is 36 characters */
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    int ip_count;
};

static int build_tree(void);
static void update_ip4();
static void update_ip6();
static void destroy_tree();

static int vps_ctid_cmp(const int *, const int *);
static int in6_addr_cmp(const struct in6_addr *, const struct in6_addr *);

static struct in_addr *ipv6_map(struct in6_addr *);
static struct in6_addr *ipv6_mapped(const struct in_addr *, struct in6_addr *);

static struct vps* init_vps(const char* token);
static int load_vps_uuid(struct vps *);

static const char *config_keys[] = {
    "UUIDPath"
};
static int config_keys_count = STATIC_ARRAY_SIZE (config_keys);

static char *vps_uuid_path = NULL; /* The path within the OpenVZ guest to a file that contains the guests UUID i.e. /etc/hostuuid */
static c_avl_tree_t *ip_lookup_table = NULL; /* maps IP to VPS since a VPS (often) has many IPs */
static c_avl_tree_t *vps_lookup_table = NULL; /* maps IP to VPS since a VPS (often) has many IPs */
static struct ip6tc_handle *handle6 = NULL;
static struct iptc_handle *handle = NULL;

/* This is a little wonky because this one host must submit values
 * on behalf of several others
 */
static void ogb_vps_submit( struct vps* vps)
{
    value_t values[1];
    value_list_t vl = VALUE_LIST_INIT;

    vl.values = values;
    vl.values_len = STATIC_ARRAY_SIZE(values);
    sstrncpy(vl.host, vps->uuid, sizeof(vl.host));
    sstrncpy(vl.plugin, "bandwidth", sizeof(vl.plugin));
    sstrncpy(vl.type, "counter", sizeof(vl.type));

    sstrncpy(vl.plugin_instance, "tx", sizeof(vl.plugin_instance));
    values[0].counter = vps->tx_bytes;
    plugin_dispatch_values(&vl);

    sstrncpy(vl.plugin_instance, "rx", sizeof(vl.plugin_instance));
    values[0].counter = vps->rx_bytes;
    plugin_dispatch_values(&vl);
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

static int ogb_config(const char *key, const char *value) {
    if (strcasecmp(key, "UUIDPath") == 0) {
        /* Blindly accpet the UUID Path they provide */
        vps_uuid_path = strdup(value);

        if (vps_uuid_path == NULL) {
            char errbuf[1024];
            ERROR ("strdup failed: %s",
                    sstrerror (errno, errbuf, sizeof (errbuf)));
            return (1);
        }
        return (0);
    } else {
        return (-1);
    }
}

static int ogb_init() {
    handle6 = ip6tc_init("filter");
    handle = iptc_init("filter");
    return 0;
}

static int ogb_shutdown() {
    ip6tc_free(handle6);
    iptc_free(handle);
    return 0;
}

void module_register (void) {
    plugin_register_init("openvz_guest_bandwidth",ogb_init);
    plugin_register_read ("openvz_guest_bandwidth", ogb_read);
    plugin_register_config("openvz_guest_bandwidth", ogb_config, config_keys, config_keys_count);
    plugin_register_shutdown("openvz_guest_bandwidth",ogb_shutdown);
} /* void module_register */


/*
 * Walks the IP tables chain looking for matches of the IP Addresses we found
 * in /prov/vz/veinfo, then totals the transfer for that VPS across all
 * of the IP addresses it has assigned.
 */
static void update_ip6() {
    ip6t_chainlabel chain;
    const struct ip6t_entry *entry = NULL;
    struct vps *vps = NULL;
    struct in6_addr slash128;

    memset(&slash128, 0xff, sizeof(slash128));

    strncpy(chain, "FORWARD", sizeof(chain));

    entry = ip6tc_first_rule(chain, handle6);
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
    } while ((entry = ip6tc_next_rule(entry, handle6)) != NULL);
}

static void update_ip4() {
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

static struct vps* init_vps(const char* token) {
    struct vps* vps = NULL;
    vps = malloc(sizeof(struct vps));
    if (vps == NULL){
        ERROR("openvz_guest_bandwidth: malloc failed\n");
        return NULL;
    }
    vps->ctid = atol(token);
    /* Initialize VPS UUID to fallback value CTID: #### */
    snprintf(vps->uuid, sizeof(vps->uuid), "CTID: %d", vps->ctid);
    vps->ip_count = 0;
    vps->tx_bytes = 0;
    vps->rx_bytes = 0;
    if (vps->ctid > 0 ) /* 0 is the host and we want to skip */
        load_vps_uuid(vps);
    return vps;
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
        ERROR("openvz_guest_bandwidth: fopen /proc/vz/veinfo\n");
        return(-1);
    }

    /* now we are sure it is worth building a tree */
    ip_lookup_table = c_avl_create((int (*) (const void *, const void *))in6_addr_cmp);
    if(ip_lookup_table == NULL) {
        ERROR ("openvz_guest_bandwidth: c_avl_create failed\n");
        return(-2);
    }

    vps_lookup_table = c_avl_create((int (*) (const void *, const void *))vps_ctid_cmp);
    if(vps_lookup_table == NULL) {
        ERROR ("openvz_guest_bandwidth: c_avl_create failed\n");
        return (-3);
    }

    while (fgets(buffer, sizeof(buffer), veinfo) != NULL) {
        token = strtok_r(buffer, " \t\n", &tok_pos);
        vps = NULL;
        for (field = 0; token != NULL; field++) {
            switch(field) {
                case 0: /* VEID */
                    vps = init_vps(token);
                    if (vps == NULL){
                        ERROR("openvz_guest_bandwidth: malloc failed\n");
                        return -4;
                    }
                    break;
                case 1: /* Class */
                case 2: /* Num Processes */
                    /* Ignore Both */
                    break;
                default: /* additional fields are IPs */
                    key = NULL;
                    /* Try parsing our IP address as both address families */
                    if (inet_pton(AF_INET6, token, &ip) == 1) {
                        /* side effect assignment */
                    } else if (inet_pton(AF_INET, token, ipv6_map(&ip)) == 1) {
                        /* side effect assignment */
                    } else {
                        ERROR("openvz_guest_bandwidth: Could not parse %s\n", token);
                        continue; /* next ip */
                    }

                    key = malloc(sizeof(ip));
                    if (key == NULL){
                        ERROR("openvz_guest_bandwidth: malloc failed\n");
                        return (-5);
                    }
                    bcopy(&ip, key, sizeof(ip));
                    status = c_avl_insert(ip_lookup_table, key, vps);

                    /* Insert the record and check for success */
                    if( status < 0 ){
                        ERROR("openvz_guest_bandwidth: failed inserting\n");
                        if(key != NULL)
                            free(key);
                    } else if( status > 0) {
                        ERROR("openvz_guest_bandwidth: failed inserting duplicate\n");
                        if(key != NULL)
                            free(key);
                    } else {
                        vps->ip_count++;
                    }
            } /* switch field */
            token = strtok_r(NULL, " \t\n", &tok_pos);
        } /* for fields */

        /* free VPS if IP count is zero */
        if (vps != NULL && vps->ip_count == 0){
            free(vps);
            continue; /* next line */
        }

        status = c_avl_insert(vps_lookup_table, &vps->ctid, vps);
        if (status < 0) {
            ERROR ("openvz_guest_bandwidth: failed inserting\n");
        } else if ( status > 0) {
            ERROR ("openvz_guest_bandwidth: failed inserting duplicate\n");
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

static int load_vps_uuid(struct vps *vps) {
    FILE *uuid_file = NULL;
    char buffer[256];
    int len;

    len = snprintf(buffer, sizeof(buffer), "/vz/private/%d/%s", vps->ctid, vps_uuid_path);
    if (len >= sizeof(buffer) - 1) {
        ERROR ("openvz_guest_bandwidth: /vz/private/%d/%s is too long, skipping this guest\n", vps->ctid, vps_uuid_path);
        return -1;
    }

    uuid_file = fopen(buffer,"r");
    if (uuid_file == NULL) {
        char errbuf[1024];
        ERROR ("fopen(%s) failed: %s\n", buffer,
                sstrerror (errno, errbuf, sizeof (errbuf)));
        return (1);
    }
    if (fgets(buffer, sizeof(buffer), uuid_file) == NULL) {
        char errbuf[1024];
        ERROR ("fgets() failed: %s\n",
                sstrerror (errno, errbuf, sizeof (errbuf)));
        return (1);
    }
    /* "69a83143-3765-4d1c-98b9-0dbf9823330a" */
    /* Validate */
    /*
       for (int i = 0; buffer[i] != '\0'; i++) {
       if (i == 8 || i == 13 || i == 18 || i == 23) {
       if (buffer[i] != '-')
       ERROR("openvz_guest_bandwith: UUID in unexpected format");
       } else {

       }
       }
       */
    len = snprintf(vps->uuid,sizeof(vps->uuid),buffer);
    if (len >= sizeof(buffer) - 1) {
        ERROR ("openvz_guest_bandwidth: contents of /vz/private/%d/%s is too long, truncated\n", vps->ctid, vps_uuid_path);
        return -1;
    }
    return 0;
}
/* vi:sw=4:ts=4:et:nu 
*/
