/*
 *    $Id: gre.c,v 1.2 2001/10/27 13:22:51 igor Exp $
 *
 * Glenn Chisholm <glenn@ircache.net>
 * Duane Wessels <wessels@ircache.net>
 */


/*
 * This gre.c you should use for FreeBSD 4.x instead of
 * http://www.squid-cache.org/WCCP-support/FreeBSD-4.x/gre.c
 * for wccp2.c
 * Difference is in the size of struct gre only.
 * You need this file for wccp v2.
 *
 * Igor Khasilev <igor@paco.net>
 */

#include "opt_gre.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <vm/vm_zone.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip_mroute.h>

#define GRE_PROTOCOL_TYPE 0x883E

struct gre {
    int type;
    int redirect_header;
};

void
gre_input(m, iphlen, proto)
     register struct mbuf *m;
     int iphlen, proto;
{
    register struct ip *ip = mtod(m, struct ip *);
    register struct gre *gre;
    int len;

    len = iphlen + sizeof(struct gre);
    if (m->m_len < len) {
	if ((m = m_pullup(m, len)) == 0) {
	    printf("gre_input: m_pullup failed\n");
	    return;
	}
	ip = mtod(m, struct ip *);
    }
    gre = (struct gre *) ((caddr_t) ip + iphlen);
    if (ntohl(gre->type) != GRE_PROTOCOL_TYPE) {
	printf("gre_input: bad GRE type %x\n", gre->type);
	rip_input(m, iphlen, proto);
	return;
    }
    if (m->m_len < len) {
	printf("gre_input: small packet?  len=%d, m_len=%d\n", len, m->m_len);
	m_freem(m);
	return;
    }
    /* drop IP and GRE headers */
    m_adj(m, len);
    ip_input(m);
}

