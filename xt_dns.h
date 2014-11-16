#ifndef _XT_DNS_H_
#define _XT_DNS_H_

/* DNS constants */
#define NS_QR			0x80	/* 10000000 */
#define NS_QR_QUERY		0x00	/* 0xxxxxxx */
#define NS_QR_RESPONSE		0x80	/* 1xxxxxxx */

#define NS_OPCODE		0x78	/* 01111000 */
#define NS_OPCODE_QUERY		0x00	/* x0000xxx */
#define NS_OPCODE_IQUERY	0x08	/* x0001xxx */
#define NS_OPCODE_STATUS	0x10	/* x0010xxx */

//#define NS_T_MX			0x0f
#define XT_DNS_MAX_NAME_LEN	256
enum {
	XT_DNS_QUERY	= 1 << 0,
	XT_DNS_RESPONSE	= 1 << 1,
	XT_DNS_QTYPE	= 1 << 2,
	XT_DNS_EDNS0	= 1 << 3,
	XT_DNS_BUFSIZE	= 1 << 4,
	XT_DNS_ZONE     = 1 << 5,
};
struct xt_dns_info {
	u_int8_t flags;
	u_int8_t invert_flags;
	u_int8_t qtype;	/* record type */
	u_int16_t bufsize[2];	/* edns0 bufsize [min:max] */
	char zone[XT_DNS_MAX_NAME_LEN];
	int zone_len;
};

typedef struct {
        unsigned        id :16;         /* query identification number */
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritive answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */
                        /* fields in fourth byte */
        unsigned        rcode :4;       /* response code */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
                        /* remaining bytes */
        unsigned        qdcount :16;    /* number of question entries */
        unsigned        ancount :16;    /* number of answer entries */
        unsigned        nscount :16;    /* number of authority entries */
        unsigned        arcount :16;    /* number of resource entries */
} XT_DNS_HEADER;

#endif
