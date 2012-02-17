/**
 * collectd - src/openvz_guest_bandwidth.c
 * Copyright (C) 2012       Chris Lundquist
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
 **/


#include "collectd.h"
#include "common.h" /* auxiliary functions */
#include "plugin.h" /* plugin_register_*, plugin_dispatch_values */

#include <arpa/inet.h>        /* inet_pton, inet_ntop */
#include <libiptc/libiptc.h>  /* ip_t* */
#include <libiptc/libip6tc.h> /* ip6_t* */
#include "utils_avltree.h"    /* c_avl_* */

static void build_tree(void); /* puts veids and their assigned IPs into a map */
static void update_tree();    /* sums transfer */
  static void update_ip6();   /* updates ipv6 transfer */
  static void update_ip4();   /* updates ipv4 transfer */
static void print_data();     /* outputs our results */
static void destroy_tree();   /* frees our memory */

static int line_count(const char*);
static char* ipv4_mapped(char*);

struct vps {
    int ctid;
    char uuid[37];
    long tx_bytes;
    long rx_bytes;
};

static c_avl_tree_t* lookup_table = NULL; /* maps IP to VPS since a VPS (often) has many IPs */
static struct vps *vpses = NULL;  /* the collection of all the vpses minus the host */
static int vps_count = 0; /* the number of guests found in veinfo */

static void ogb_submit()
{
    print_data();
}

static int ogb_read(void)
{
    /* build our map of IP -> VPS */
    build_tree();
    /* walk IP tables totalling transfer for the VPses we found */
    update_tree();
    /* Output the totals per VPS */
    ogb_submit();
    /* clean up */
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
    char src_address[INET6_ADDRSTRLEN], dst_address[INET6_ADDRSTRLEN];
    char src_mask[INET6_ADDRSTRLEN], dst_mask[INET6_ADDRSTRLEN];
    struct vps *vps = NULL;
    void* key = NULL;
    int status = 0;

    handle = ip6tc_init("filter");

    strncpy(chain, "FORWARD", sizeof(chain));

    /* ensure the chain exists so we don't segfault */
    if (! ip6tc_is_chain(chain, handle)) {
        printf("ERROR: %s chain in %s table does NOT exists\n", chain, "filter");
        return;
    } 

    entry = ip6tc_first_rule(chain, handle);
    do {
        /* set the src and dst addresses with their masks */
        /* we need them as strings so we can use strcmp to insert into avl */
        inet_ntop(AF_INET6, &(entry->ipv6.src), src_address, sizeof(src_address));
        inet_ntop(AF_INET6, &(entry->ipv6.smsk), src_mask, sizeof(src_mask));

        inet_ntop(AF_INET6, &(entry->ipv6.dst), dst_address, sizeof(dst_address));
        inet_ntop(AF_INET6, &(entry->ipv6.dmsk), dst_mask, sizeof(dst_mask));

        /* if the source address is in our map, then it was outbound */
        key = src_address;

        status = c_avl_get(lookup_table, key, (void *)&vps);

        if(status == 0){
            vps->tx_bytes += entry->counters.bcnt;
        } 

        /* if the destination address is in our map, then it was inbound*/
        key = dst_address;

        status = c_avl_get(lookup_table, key, (void *)&vps);

        /* make sure we got answer */
        if(status == 0){
            vps->rx_bytes += entry->counters.bcnt;
        }
    } while ((entry = ip6tc_next_rule(entry, handle)) != NULL);
}

static void update_ip4() {
    struct iptc_handle *handle = NULL;
    const struct ipt_entry *entry = NULL;
    ipt_chainlabel chain;
    char src_address[INET6_ADDRSTRLEN], dst_address[INET6_ADDRSTRLEN];
    char src_mask[INET6_ADDRSTRLEN], dst_mask[INET6_ADDRSTRLEN];
    struct vps *vps = NULL;
    void* key = NULL;
    int status = 0;

    handle = iptc_init("filter");  

    strncpy(chain, "FORWARD", sizeof(chain));

    /* ensure the chain exists so we don't segfault */
    if (! iptc_is_chain(chain, handle)) {
        printf("ERROR: %s chain in %s table does NOT exists\n", chain, "filter");
        return;
    } 


    entry = iptc_first_rule(chain, handle);
    do {
        /* set the src and dst addresses with their masks */
        inet_ntop(AF_INET, &(entry->ip.src), src_address, sizeof(src_address));
        inet_ntop(AF_INET, &(entry->ip.smsk), src_mask, sizeof(src_mask));

        inet_ntop(AF_INET, &(entry->ip.dst), dst_address, sizeof(dst_address));
        inet_ntop(AF_INET, &(entry->ip.dmsk), dst_mask, sizeof(dst_mask));

        /* if the source address is in our map, then it was outbound */
        key = ipv4_mapped(src_address);

        status = c_avl_get(lookup_table, key, (void *)&vps);

        if(status == 0){
            /* we only want exact subnet matches for source */
            if(strcmp("255.255.255.255", src_mask) != 0)
                continue;
            vps->tx_bytes += entry->counters.bcnt;
        } 

        /* if the destination address is in our map, then it was inbound*/
        key = ipv4_mapped(dst_address);

        status = c_avl_get(lookup_table, key, (void *)&vps);

        /* make sure we got answer */
        if(status == 0){
            vps->rx_bytes += entry->counters.bcnt;
        }
    } while ((entry = iptc_next_rule(entry, handle)) != NULL);

}

static void update_tree(){
    update_ip4();
    update_ip6();
}


static void print_data(){
    int i = 0;
    for(;i < vps_count; i++){
        printf("VPS %d\n",vpses[i].ctid);
        printf("  tx_bytes: %ld\n",vpses[i].tx_bytes);
        printf("  rx_bytes: %ld\n",vpses[i].rx_bytes);
    }

}

static void destroy_tree() {
    char* key = NULL;
    void* value = NULL;
    while(c_avl_pick(lookup_table,(void**) &key,(void**) &value) == 0){
        if(key)
            free(key);
        value = NULL;
    }
    free(vpses);
}

void
build_tree() {
    FILE *veinfo = NULL;
    char buffer[256];
    char *token = NULL;
    char *tok_pos = NULL;
    struct vps *vps = NULL; /* The vps we are working on */
    int field = 0; /* which column of veinfo we are on */
    int line = 0; /* lets us know which line, thus which vps, we are working with */
    void* key = NULL;
    int status = 0; /* stores status of insert */

    /* We expect /proc/vz/veinfo to hold something like 
     * 377368     0    54        2607:f700:1:5c:25:90ff:fe49:6561   199.91.170.72   199.91.170.71
     *      0     0   521
     */
    veinfo = fopen("/proc/vz/veinfo", "r");
    if (veinfo == NULL) {
        perror("fopen /proc/vz/veinfo");
        exit(1);
    }

    vps_count = line_count("/proc/vz/veinfo") - 1; /* don't count veid 0 since it is the host */
    /* printf("Found %d VPSes\n", vps_count); */
    vpses = malloc(vps_count * sizeof(struct vps));

    /* now we are sure it is worth building a tree */
    lookup_table = c_avl_create ((int (*) (const void *, const void *)) strcmp);

    if(lookup_table == NULL) {
        perror("c_avl_create failed");
        exit(-2);
    }

    while (fgets(buffer, sizeof(buffer), veinfo) != NULL) {
        /*        printf("Line %s", buffer); */
        token = strtok_r(buffer, " \t\n", &tok_pos);
        for (field = 0; token != NULL; field ++) {
            switch(field) {
                case 0: /* VEID */
                    vps = vpses + line;
                    vps->ctid = atol(token);
                    line++;
                    break;
                case 1: /* Class */
                case 2: /* Num Processes */
                    /* Ignore */
                    break;
                default: /* additional fields are IPs */
                    /* TODO free all the keys we allocate here when we destroy our tree*/
                    key = ipv4_mapped(token);

                    /* Insert the record and check for success */
                    status = c_avl_insert(lookup_table, key, vps);
                    if( status < 0 ){	
                        printf("Error: failed inserting: %s\n", (char*)key);
                    } else if( status > 0) {
                        printf("Error: failed inserting duplicate: %s\n", (char*)key);
                    }
            } /* switch field */
            token = strtok_r(NULL, " \t\n", &tok_pos);
        } /* for fields */
    } /* while(fgets) */

    /* printf("lookup table has size of %d\n", c_avl_size(lookup_table)); */

    fclose(veinfo);
} /* build_tree() */

/* Turns an IPv4 address in ddd.ddd.ddd.ddd to a mapped IPv6 address
 * in the form of ::ffff:ddd.ddd.ddd.ddd
 */
static char *ipv4_mapped(char* addr) {
    struct in6_addr ip = IN6ADDR_ANY_INIT;
    char address_str[INET6_ADDRSTRLEN];
    unsigned char mapped_template[] = {
        0,0,0,0,
        0,0,0,0,
        0,0,0xff,0xff,
        0,0,0,0 };

    memcpy(mapped_template,addr, sizeof(mapped_template));
    /* Try parsing our IP address as both address families */
    inet_pton(AF_INET, addr, &(((struct in_addr *)&ip)[3]));
    inet_pton(AF_INET6, addr, &ip);

    inet_ntop(AF_INET6, &ip, address_str, sizeof(address_str));

    return strndup (address_str,INET6_ADDRSTRLEN);
}

/* There is probably a better way to count the lines in a file */
static int line_count(const char* filename) {
    FILE* file = 0;
    int lines = 0;
    char c = 0;

    file = fopen(filename, "r");

    if(!file) {
        perror(filename);
        return -1;
    }

    do {
        c = getc (file);
        if (c == '\n')
            lines++;
    } while (c != EOF);

    fclose(file);
    return lines;
}

