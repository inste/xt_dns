/*
 *	libxt_dns
 *      Copyright (c) Ondrej Caletka, 2013
 *	based on libxt_dns (c) Bartlomiej Korupczynski, 2011
 *
 *	This is userspace part of module used to match DNS MX queries
 * 
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from gnu.org/gpl.
 */

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <arpa/nameser.h>

#include "xt_dns.h"
#include "config.h"

//For old version of iptables
#ifndef XT_GETOPT_TABLEEND
#define XT_GETOPT_TABLEEND {.name = NULL, .has_arg = false}
#endif
#if XTABLES_VERSION_CODE < 6
	/* prior to iptables-1.4.11, the space was printed after option */
#define S1 ""
#define S2 " "
#else
	/* from iptables-1.4.11 on, the space is printed before option */
#define S1 " "
#define S2 ""
#endif

// uncomment this for older version of iptables
//#define xtables_error exit_error


struct {
	char *name;
	u_int8_t type;
} dns_types[] = {
	{ "A", ns_t_a },
	{ "NS", ns_t_ns },
	{ "CNAME", ns_t_cname },
	{ "SOA", ns_t_soa },
	{ "WKS", ns_t_wks },
	{ "PTR", ns_t_ptr },
	{ "MX", ns_t_mx },
	{ "TXT", ns_t_txt },
	{ "AAAA", ns_t_aaaa },
	{ "LOC", ns_t_loc },
	{ "SRV", ns_t_srv },
	{ "NAPTR", ns_t_naptr },
        { "IXFR", ns_t_ixfr },
        { "AXFR", ns_t_axfr },
	{ "ANY", ns_t_any },
	{ NULL },
};

static const struct option dns_opts[] = {
	{ .name = "dns-query",		.has_arg = false,	.val = '1' },
	{ .name = "dns-response",	.has_arg = false,	.val = '2' },
	{ .name = "query-type",		.has_arg = true,	.val = '3' },
	{ .name = "edns0",		.has_arg = false,	.val = '4' },
	{ .name = "bufsize",		.has_arg = true,	.val = '5' },
	{ .name = "zone",		.has_arg = true,	.val = '6' },
	XT_GETOPT_TABLEEND,
};

uint16_t parse_u16(const char *buf)
{
	unsigned int num;
	
	if (xtables_strtoui(buf, NULL, &num, 0, UINT16_MAX)) 
		return num;

	xt_params->exit_err(PARAMETER_PROBLEM,
	           "invalid number `%s' specified", buf);
}	


static void parse_uint16_range(const char *rangestring, uint16_t *bufsize)
{
	char *buffer;
	char *cp;

	buffer = strdup(rangestring);
	if ((cp = strchr(buffer, ':')) == NULL)
		bufsize[0] = bufsize[1] = parse_u16(buffer);
	else {
		*cp = '\0';
		cp++;

		bufsize[0] = buffer[0] ? parse_u16(buffer) : 0;
		bufsize[1] = cp[0] ? parse_u16(cp) : 0xFFFF;

		if (bufsize[1] < bufsize[0])
			xtables_error(PARAMETER_PROBLEM,
			          "invalid bufsize (min > max)");
	}
	free(buffer);
}
		

static const char* find_type_name(u_int8_t type)
{
	int i;

	for (i=0; dns_types[i].name != NULL; i++) {
		if (dns_types[i].type != type)
			continue;

		return dns_types[i].name;
	}

	return NULL;
}

static u_int8_t get_type(char *name)
{
	int i;

	/* find by name */
	for (i=0; dns_types[i].name != NULL; i++) {
		if (strcasecmp(dns_types[i].name, name))
			continue;

		return dns_types[i].type;
	}

	/* is name numeric? */
	for (i=0; name[i] != '\0'; i++) {
		if (name[i]<'0' || name[i]>'9')
			return ns_t_invalid;
	}

	i = atoi(name);
	if (i < 1 || i > 255)
		return ns_t_invalid;

	return i;
}


static void dns_help(void)
{
	printf(
"dns match options:\n"
"[!] --dns-query        match DNS query\n"
"[!] --dns-response     match DNS response\n"
"[!] --query-type {A|NS|CNAME|SOA|WKS|PTR|MX|TXT|AAAA|SRV|NAPTR|IXFR|AXFR|ANY|0-255}\n"
"                       match specific query type\n"
"[!] --edns0            match packets with EDNS0 field\n"
"[!] --zone zone-name match request only to name under zone-name\n"
"    --bufsize value[:value] match EDNS0 buffer size\n"
);
}

static int dns_parse(int c, char **argv, int invert, unsigned int *flags,
          const void *entry, struct xt_entry_match **match)
{
	struct xt_dns_info *info = (void *) (*match)->data;
	u_int8_t type;
	
	switch (c) {
	case '1': /* query */
		if (*flags & XT_DNS_QUERY)
			xtables_error(PARAMETER_PROBLEM, "xt_dns: "
			         "Only use \"--%s\" once!", dns_opts[0].name);
		if (*flags & XT_DNS_RESPONSE)
			xtables_error(PARAMETER_PROBLEM, "xt_dns: "
			         "You cannot mix \"--%s\" and \"--%s\"!",
			         dns_opts[0].name, dns_opts[1].name);
		*flags |= XT_DNS_QUERY;
		info->flags |= XT_DNS_QUERY;
		if (invert)
			info->invert_flags |= XT_DNS_QTYPE;
		return true;

	case '2': /* response */
		if (*flags & XT_DNS_RESPONSE)
			xtables_error(PARAMETER_PROBLEM, "xt_dns: "
			         "Only use \"--%s\" once!", dns_opts[1].name);
		if (*flags & XT_DNS_QUERY)
			xtables_error(PARAMETER_PROBLEM, "xt_dns: "
			         "You cannot mix \"--%s\" and \"--%s\"!",
			         dns_opts[1].name, dns_opts[0].name);
		*flags |= XT_DNS_RESPONSE;
		info->flags |= XT_DNS_RESPONSE;
		if (invert)
			info->invert_flags |= XT_DNS_RESPONSE;
		return true;

	case '3': /* query type */
		if (*flags & XT_DNS_QTYPE)
			xtables_error(PARAMETER_PROBLEM, "xt_dns: "
			         "Only use \"--%s\" once!", dns_opts[2].name);
		if ((type = get_type(optarg)) == 0)
			xtables_error(PARAMETER_PROBLEM, "xt_dns: "
			         "Unknown DNS query type");
		*flags |= XT_DNS_QTYPE;
		info->flags |= XT_DNS_QTYPE;
		info->qtype = type;
		if (invert)
			info->invert_flags |= XT_DNS_QTYPE;
		return true;

	case '4': /* edns0 */
		if (*flags & XT_DNS_EDNS0)
			xtables_error(PARAMETER_PROBLEM, "xt_dns: "
			         "Only use \"--%s\" once!", dns_opts[3].name);
		*flags |= XT_DNS_EDNS0;
		info->flags |= XT_DNS_EDNS0;
		if (invert)
			info->invert_flags |= XT_DNS_EDNS0;
		return true;

	case '5': /* bufsize */
		if (*flags & XT_DNS_BUFSIZE)
			xtables_error(PARAMETER_PROBLEM, "xt_dns: "
			         "Only use \"--%s\" once!", dns_opts[4].name);
		if (invert)
			xtables_error(PARAMETER_PROBLEM, "xt_dns: "
			         "%s cannot be inverted!", dns_opts[4].name);
		*flags |= XT_DNS_BUFSIZE;
		info->flags |= XT_DNS_EDNS0 | XT_DNS_BUFSIZE; /* bufsize implies edns0 */
		parse_uint16_range(optarg, info->bufsize);
		return true;
	case '6': /* zone */
		if (*flags & XT_DNS_ZONE)
                        xtables_error(PARAMETER_PROBLEM, "xt_dns: "
                                 "Only use \"--%s\" once!", dns_opts[5].name);
                if (invert)
			info->invert_flags |= XT_DNS_ZONE;
		*flags |= XT_DNS_ZONE;
		info->flags |= XT_DNS_ZONE;
		info->zone_len = strlen(optarg);
		if(info->zone_len> XT_DNS_MAX_NAME_LEN - 1)
			xtables_error(PARAMETER_PROBLEM, "xt_dns: "
				"%s is too long!", dns_opts[5].name);
		strcpy(info->zone, optarg);
		return true;

	}
	return false;
}

static void dns_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct xt_dns_info *info = (void *) match->data;
	const char *name;
	
	printf(S1"dns"S2);
	if (info->flags & XT_DNS_QUERY) {
		printf("%s",S1);
		if (info->invert_flags & XT_DNS_QUERY)
			printf("!");
		printf("query"S2);
	}
	if (info->flags & XT_DNS_RESPONSE) {
		printf("%s",S1);
		if (info->invert_flags & XT_DNS_RESPONSE)
			printf("!");
		printf("response"S2);
	}
	if (info->flags & XT_DNS_QTYPE) {
		printf("%s",S1);
		if (info->invert_flags & XT_DNS_QTYPE)
			printf("!");
		name = find_type_name(info->qtype);
		if (name)
			printf("qtype %s"S2, name);
		else
			printf("qtype %d"S2, info->qtype);
	}
	if (info->flags & XT_DNS_ZONE) {
		printf("%s",S1);
		printf("zone %s"S2, info->zone);
	}
	if (info->flags & XT_DNS_EDNS0) {
		printf("%s",S1);
		if (info->invert_flags & XT_DNS_EDNS0)
			printf("!");
		printf("edns0"S2);
		if (info->flags & XT_DNS_BUFSIZE) {
			printf("%s",S1);
			if (info->bufsize[0] == info->bufsize[1])
				printf("bufsize %d"S2, info->bufsize[0]);
			else
				printf("bufsize %d:%d"S2,
				       info->bufsize[0], info->bufsize[1]);
		}
	}
}

static void dns_save(const void *ip, const struct xt_entry_match *match)
{
	struct xt_dns_info *info = (void *) match->data;
	const char *name;
	
	if (info->flags & XT_DNS_QUERY) {
		if (info->invert_flags & XT_DNS_QUERY)
			printf(S1"!"S2);
		printf(S1"--%s"S2, dns_opts[0].name);
	}
	if (info->flags & XT_DNS_RESPONSE) {
		if (info->invert_flags & XT_DNS_RESPONSE)
			printf(S1"!"S2);
		printf(S1"--%s"S2, dns_opts[1].name);
	}
	if (info->flags & XT_DNS_QTYPE) {
		if (info->invert_flags & XT_DNS_QTYPE)
			printf(S1"!"S2);
		name = find_type_name(info->qtype);
		if (name)
			printf(S1"--%s %s"S2, dns_opts[2].name, name);
		else
			printf(S1"--%s %d"S2, dns_opts[2].name, info->qtype);
	}
	if (info->flags & XT_DNS_EDNS0) {
		if (info->invert_flags & XT_DNS_EDNS0)
			printf(S1"!"S2);
		printf(S1"--%s"S2, dns_opts[3].name);
		if (info->flags & XT_DNS_BUFSIZE) {
			if (info->bufsize[0] == info->bufsize[1])
				printf(S1"--%s %d"S2, dns_opts[4].name, info->bufsize[0]);
			else
				printf(S1"--%s %d:%d"S2, dns_opts[4].name,
				       info->bufsize[0], info->bufsize[1]);
		}
	}
}

static struct xtables_match dns_match = {
	.version	= XTABLES_VERSION,
	.name		= "dns",
	.revision	= 1,
	.family		= AF_INET,
	.size		= XT_ALIGN(sizeof(struct xt_dns_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_dns_info)),
	.help		= dns_help,
	.parse		= dns_parse,
	.print		= dns_print,
	.save		= dns_save,
	.extra_opts	= dns_opts,
};

static struct xtables_match dns_match6 = {
	.version	= XTABLES_VERSION,
	.name		= "dns",
	.revision	= 1,
	.family		= AF_INET6,
	.size		= XT_ALIGN(sizeof(struct xt_dns_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_dns_info)),
	.help		= dns_help,
	.parse		= dns_parse,
	.print		= dns_print,
	.save		= dns_save,
	.extra_opts	= dns_opts,
};

void _init(void)
{
	xtables_register_match(&dns_match);
	xtables_register_match(&dns_match6);
}
