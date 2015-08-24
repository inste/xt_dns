/*
 *	xt_dns
 *      Copyright (c) Stanislav Petr, 2015
 *      based on libxt_dns (c) Ondrej Caletka, 2013
 *	based on xt_dns (c) Bartlomiej Korupczynski, 2011
 *
 *	This is kernel part of module used to match DNS queries
 * 
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from gnu.org/gpl.
 */

/* Linux kernel module */
#define MODULE
#define LINUX
#define __KERNEL__

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include "xt_dns.h"
#include "config.h"

#ifdef CONFIG_NETFILTER_DEBUG
#warning debugging on
#define NFDEBUG(format, args...)  printk(KBUILD_MODNAME ": " format , ## args)
void debug_dump_buf(u8 *dns, size_t len, size_t offset, char *title) {
	int i;
	printk("%s[%zu]: ", title, offset);
	for (i=offset; i<len && i<(offset+24); i++)
		printk("%02x ", dns[i]);
	printk("\n");
}	
#else
#define NFDEBUG(format, args...)
#define debug_dump_buf(dns, len, offset, title)
#endif

#define MAX_MTU 2000
static u8 pktbuf[MAX_MTU]; /* buffer for whole packet in case skb is fragmented */

static int readname_loop(char *packet, int packetlen, char *src, char *dst, size_t length, size_t loop){
	char *dummy;
	char *s;
	char *d;
	int len;
	int offset;
	char c;

	if (loop <= 0)
		return 0;

	len = 0;
	s = src;
	d = dst;
	while(*s && len < length - 2) {
		c = *s++;

		/* is this a compressed label? */
		if((c & 0xc0) == 0xc0) {
			offset = (((s[-1] & 0x3f) << 8) | (s[0] & 0xff));
			if (offset > packetlen) {
				if (len == 0) {
					/* Bad jump first in packet */
					return 0;
				} else {
					/* Bad jump after some data */
					break;
				}
			}
			dummy = packet + offset;
			len += readname_loop(packet, packetlen, dummy, d, length - len, loop - 1);
			goto end;
		}

		while(c && len < length - 1) {
			*d++ = *s++;
			len++;

			c--;
		}

		if (len >= length - 1) {
			break; /* We used up all space */
		}

		if (*s != 0) {
			*d++ = '.';
			len++;
		}
	}
	dst[len++] = '\0';

end:
	src = s+1;
	return len;
}

int readname(char *packet, int packetlen, char *src, char *dst, size_t length){
	return readname_loop(packet, packetlen, src, dst, length, 10);
}


static int is_inside_zone(char *dns, size_t len, size_t offset, const char * zone, int zone_len){
	char name[XT_DNS_MAX_NAME_LEN];
	int domain_len;
	int inside_zone = 0;
	int data_len = len - (offset);
	char data[data_len];
	int name_len;
	strncpy(data, dns + (offset), data_len);
	name_len = readname(dns, len, data, name, XT_DNS_MAX_NAME_LEN) - 1;
	if(name_len<=0)
		return 0;
	domain_len = name_len - zone_len;
	NFDEBUG("domain_len:%d, zone_len:%d, name_len:%d\n", domain_len, zone_len, name_len);
	debug_dump_buf(name, name_len, 0, "name:");
	debug_dump_buf(zone, zone_len, 0, "zone:");
	if (domain_len >= 0 && !strncasecmp(name + domain_len, zone, zone_len))
		inside_zone = 1;
	// require dot before topdomain
	if (domain_len >= 1 && name[domain_len - 1] != '.')
		inside_zone = 0;
	return inside_zone;
}

static bool skip_name(u8 *dns, size_t len, size_t *offset) {
	/* skip labels */
	debug_dump_buf(dns, len, *offset, "skip_name");
	while (dns[*offset] > 0 && (*offset) < len-4) {
		if (dns[*offset] <= 63)
			(*offset) += dns[*offset] + 1;
		else	{
			(*offset) += 1; /* Compressed label */
			break;
		}
	}
	if (*offset >= len-4) {
		pr_warn(KBUILD_MODNAME ": Tried to skip past packet length! offset: %zu, len: %zu\n",
		        *offset, len);
		return false;
	}
	/* offset is now pointing on the last octet of name */
	(*offset) += 5; /* skip qtype and qclass */
	return true;
}

static bool skip_rr(u8 *dns, size_t len, size_t *offset) {
	u16 rdlength;
	if (skip_name(dns, len, offset) && ((*offset) + 6) <= len ){
		rdlength = dns[(*offset) + 4] << 8 | dns[(*offset) + 5];
		debug_dump_buf(dns, len, *offset, "skip_rr");
		NFDEBUG("rdlength: %d\n", rdlength);
		if ((*offset) + 6 + rdlength < len) {
			(*offset) += 6 + rdlength;
			return true;
		}
	}
	pr_warn("Skipping RR failed. offset: %zu, len: %zu\n", *offset, len);
	return false;
}

#ifdef HAVE_XT_MATCH_PARAM
static bool dns_mt(const struct sk_buff *skb, const struct xt_match_param *par)
#else
static bool dns_mt(const struct sk_buff *skb, struct xt_action_param *par)
#endif
{
	const struct xt_dns_info *info = par->matchinfo;
	XT_DNS_HEADER * dns_header;

	u8 *dns;
	size_t len, offset;
	bool is_match, invert;
	u16 counts[4]; /* qdcount, ancount, nscount, arcount */
	u16 udpsize;
	int i;

	/* skip fragments */
	if (par->fragoff)
		return false;

	NFDEBUG("skb->len: %d, skb->data_len: %d, par->thoff: %d\n", skb->len, skb->data_len, par->thoff);
	/* find UDP payload */
	offset = par->thoff + sizeof(struct udphdr);
	len = skb->len - offset;
	if (len > sizeof(pktbuf)) {
		pr_warn(KBUILD_MODNAME": Packet too big. Increase MAX_MTU (size %d)\n", skb->len);
		return false;
	}
	dns = skb_header_pointer(skb, offset, len, pktbuf);
	if (dns == NULL) {
		pr_warn(KBUILD_MODNAME": skb_header_pointer failed!\n");
		return false;
	}

	/* minimum DNS query payload is 17 bytes (for "." root zone) */
	if (len < 17)
		return false;

	NFDEBUG("skb->len: %d, skb->data_len: %d, len: %zu\n", skb->len, skb->data_len, len);
	debug_dump_buf(dns, len, 0, "ipt_dns");

	dns_header = (XT_DNS_HEADER *) dns;

	/* check if we are dealing with DNS query */
	if (info->flags & XT_DNS_QUERY) {
		invert = ((info->invert_flags & XT_DNS_QUERY) != 0);
		is_match = ((dns[2] & NS_QR) == NS_QR_QUERY);
		if (is_match == invert)
			return false;
	}

	/* check if we are dealing with DNS response */
	if (info->flags & XT_DNS_RESPONSE) {
		invert = ((info->invert_flags & XT_DNS_RESPONSE) != 0);
		is_match = ((dns[2] & NS_QR) == NS_QR_RESPONSE);
		if (is_match == invert)
			return false;
	}

	/* fill counts[] with data from dns header */
	for (i=0; i<4; i++) {
		counts[i] = ntohs(((u16*)dns)[i+2]);
	}

	/* query type test */
	if (info->flags & XT_DNS_QTYPE) {
		NFDEBUG("Entering qtype match\n");
		invert = ((info->invert_flags & XT_DNS_QTYPE) != 0);
		is_match = counts[0] > 0; /* qdcount at least 1 */

		if (!is_match)
			goto qtype_out;

		/* offset is set to the first question section */
		offset = sizeof(XT_DNS_HEADER);
		is_match = skip_name(dns, len, &offset);
		if (!is_match)
			goto qtype_out;

		NFDEBUG("Matching qtype: %x %x %x %x\n", dns[offset-4], dns[offset-3], dns[offset-2], dns[offset-1]);
		/* match if type=info->type, class IN */
		is_match = (dns[offset-4] == 0x00) && (dns[offset-3] == info->qtype)
			&& (dns[offset-2] == 0x00) && (dns[offset-1] == 0x01);
	
	qtype_out:
		if (is_match == invert)
			return false;
	}

	/* check for EDNS0 */
	if (info->flags & XT_DNS_EDNS0) {
		invert = ((info->invert_flags & XT_DNS_EDNS0) != 0);
		is_match = counts[3] > 0; /* arcount at least 1 */
		
		offset = sizeof(XT_DNS_HEADER);
		/* skip query sections */
		for (i=0; i<counts[0]; i++) {
			is_match &= skip_name(dns, len, &offset);
			if (!is_match)
				break;
		}
		if (!is_match)
			goto edns0_out;

		/* skip answer and authority sections */
		for (i=0; i<(counts[1]+counts[2]); i++) {
			is_match &= skip_rr(dns, len, &offset);
			if (!is_match)
				break;
		}
		if (!is_match)
			goto edns0_out;

		/* try to find EDNS0 pseudo-RR */
		for (i=0; i<counts[3]; i++) {
			if (dns[offset] == 0 && dns[offset+1] == 0 && dns[offset+2] == 41)
				break;
			is_match &= skip_rr(dns, len, &offset);
			if (!is_match)
				break;
		}
		if (!is_match || (i == counts[3])) {
			is_match = false;
			goto edns0_out;
		}
		/* EDNS0 found */
		if (info->flags & XT_DNS_BUFSIZE) {
			/* TODO: XT_DNS_BUFSIZE inversion not implemented */
			udpsize = dns[offset+3] << 8 | dns[offset+4];
			if (udpsize < info->bufsize[0] || udpsize > info->bufsize[1]) {
				is_match = false;
				goto edns0_out;
			}
		}
		debug_dump_buf(dns, len, offset, "ipt_dns_edns0");
	edns0_out:
		if (is_match == invert)
			return false;
		
	}

	/* zone test */
	if (info->flags & XT_DNS_ZONE){
		NFDEBUG("Entering zone match\n");
		invert = ((info->invert_flags & XT_DNS_ZONE) != 0);
		is_match = 0;
		offset = sizeof(XT_DNS_HEADER);
		if (info->flags & XT_DNS_QUERY && dns_header->qdcount > 0) {
			if(is_inside_zone(dns, len, offset, info->zone, info->zone_len)){
				is_match = 1;
				NFDEBUG("Zone is matched !\n");
			}
		}
		else if (info->flags & XT_DNS_RESPONSE) {
		}
		if (is_match == invert)
			return false;
	}

	/* Nothing stopped us so far, let's accept the packet */
	return true;
}

#ifdef HAVE_XT_MATCH_PARAM
static bool dns_mt_check(const struct xt_mtchk_param *par)
{
	const struct ipt_ip *ip = par->entryinfo;
//	const struct xt_dns_info *info = par->matchinfo;

	/* we can deal with UDP only */
	if (ip->proto != IPPROTO_UDP) {
		printk("xt_dns: cannot work with other protocol than UDP\n");
		return false;
	}

	return true;
}
#else
static int dns_mt_check(const struct xt_mtchk_param *par)
{
	const struct ipt_ip *ip = par->entryinfo;
//	const struct xt_dns_info *info = par->matchinfo;

	/* we can deal with UDP only */
	if (ip->proto != IPPROTO_UDP) {
		printk("xt_dns: cannot work with other protocol than UDP\n");
		return -EPROTOTYPE;
	}

	return 0;
}
#endif

#ifdef HAVE_XT_MATCH_PARAM
static bool dns_mt6_check(const struct xt_mtchk_param *par)
{
	const struct ip6t_ip6 *ip = par->entryinfo;
//	const struct xt_dns_info *info = par->matchinfo;

	/* we can deal with UDP only */
	if (ip->proto != IPPROTO_UDP) {
		printk("xt_dns: cannot work with other protocol than UDP\n");
		return false;
	}

	return true;
}
#else
static int dns_mt6_check(const struct xt_mtchk_param *par)
{
	const struct ip6t_ip6 *ip = par->entryinfo;
//	const struct xt_dns_info *info = par->matchinfo;

	/* we can deal with UDP only */
	if (ip->proto != IPPROTO_UDP) {
		printk("xt_dns: cannot work with other protocol than UDP\n");
		return -EPROTOTYPE;
	}

	return 0;
}
#endif


static struct xt_match dns_reg[] __read_mostly = {
	{
		.name		= "dns",
		.revision	= 1,
		.family		= NFPROTO_IPV4,
		.checkentry	= dns_mt_check,
		.match		= dns_mt,
		.matchsize	= sizeof(struct xt_dns_info),
		.me		= THIS_MODULE
	},
	{
		.name		= "dns",
		.revision	= 1,
		.family		= NFPROTO_IPV6,
		.checkentry	= dns_mt6_check,
		.match		= dns_mt,
		.matchsize	= sizeof(struct xt_dns_info),
		.me		= THIS_MODULE
	},
};

static int __init dns_init(void)
{
	printk("registering %s %s\n", "xt_dns", VERSION);
	return xt_register_matches(dns_reg, ARRAY_SIZE(dns_reg));
}

static void __exit dns_exit(void)
{
	printk("unregistering %s\n", "xt_dns");
	xt_unregister_matches(dns_reg, ARRAY_SIZE(dns_reg));
}

module_init(dns_init);
module_exit(dns_exit);
MODULE_AUTHOR("Stanislav Petr <stanislav@petr.email>");
MODULE_DESCRIPTION("Xtables: DNS matcher");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_dns");
MODULE_ALIAS("ip6t_dns");

