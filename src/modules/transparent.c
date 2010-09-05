/*
Copyright (C) 1999 Igor Khasilev, igor@paco.net

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#include	"../oops.h"
#include	"../modules.h"

#if	defined(HAVE_IPF)
#if     defined(va_start) /* dirty hack. sol7 x86 + gcc 2.95.2 */
#define _SYS_VARARGS_H
#endif
#include	<sys/ioctl.h>
#if	defined(HAVE_IP6_H)
#include        <netinet/ip6.h>
#endif
#include	<netinet/tcp.h>
#include	<net/if.h>
#include	<netinet/ip_compat.h>
#include	<netinet/ip_fil.h>
#include	<netinet/ip_nat.h>
int		natfd;
#endif

#define	MODULE_NAME	"transparent"
#define	MODULE_INFO	"Transparent proxy"

#if	defined(MODULES)
char		module_type   = MODULE_REDIR ;
char		module_name[] = MODULE_NAME ;
char		module_info[] = MODULE_INFO ;
int		mod_load();
int     	mod_unload();
int		mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run();
int		redir(int so, struct group *group, struct request *rq, int *flags, int);
#define		MODULE_STATIC
#else
static	char	module_type   = MODULE_REDIR ;
static	char	module_name[] = MODULE_NAME ;
static	char	module_info[] = MODULE_INFO ;
static  int     mod_load();
static  int     mod_unload();
static  int     mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run();
static	int	redir(int so, struct group *group, struct request *rq, int *flags, int);
#define		MODULE_STATIC	static
#endif

struct  redir_module    transparent = {
	{
	NULL, NULL,
	MODULE_NAME,
	mod_load,
	mod_unload,
	mod_config_beg,
	mod_config_end,
	mod_config,
	NULL,
	MODULE_REDIR,
	MODULE_INFO,
	mod_run
	},
	redir,
	NULL,
	NULL
};

static	pthread_rwlock_t	tp_lock;
#define	RDLOCK_TP_CONFIG	pthread_rwlock_rdlock(&tp_lock)
#define	WRLOCK_TP_CONFIG	pthread_rwlock_wrlock(&tp_lock)
#define	UNLOCK_TP_CONFIG	pthread_rwlock_unlock(&tp_lock)

#define	NMYPORTS	4
static	myport_t	myports[NMYPORTS];	/* my ports		*/
static	int		nmyports;		/* actual number	*/
static	char		*myports_string;
/* static	char		*build_src(struct request*); */

int
mod_load()
{
    printf("Transparent started\n");
    pthread_rwlock_init(&tp_lock, NULL);
    nmyports = 0;
#if	defined(HAVE_IPF)
    natfd = -1;
#endif
    myports_string = NULL;
    return(MOD_CODE_OK);
}

int
mod_unload()
{
    verb_printf("Transparent stopped\n");
    return(MOD_CODE_OK);
}

int
mod_config_beg(int i)
{
    WRLOCK_TP_CONFIG ;
    nmyports = 0;
    if ( myports_string ) free(myports_string);
    myports_string = NULL;
#if	defined(HAVE_IPF)
    if ( natfd != -1 ) close(natfd);
    natfd = -1;
#endif
    UNLOCK_TP_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_run()
{
    if ( myports_string ) {
	WRLOCK_TP_CONFIG ;
	nmyports = parse_myports(myports_string, &myports[0], NMYPORTS);
	verb_printf("%s will use %d ports\n", module_name, nmyports);
	UNLOCK_TP_CONFIG ;
    }
    return(MOD_CODE_OK);
}

int
mod_config_end(int i)
{
    return(MOD_CODE_OK);
}

int
mod_config(char *config, int i)
{
char		*p = config;

    WRLOCK_TP_CONFIG ;
    while( *p && IS_SPACE(*p) ) p++;

    if ( !strncasecmp(p, "myport", 6) ) {
	p += 6;
	while (*p && IS_SPACE(*p) ) p++;
	myports_string = strdup(p);
    }
    UNLOCK_TP_CONFIG ;
    return(MOD_CODE_OK);
}

int
redir(int so, struct group *group, struct request *rq, int *flags, int instance)
{
char			*host = NULL;
u_short			port;
char			*dd = NULL;

    RDLOCK_TP_CONFIG ;
    my_xlog(OOPS_LOG_DBG, "redir(): redir/transparent called.\n");
    if ( !rq ) goto done;
    port = ntohs(rq->my_sa.sin_port);
    if ( nmyports > 0 ) {
	int     n = nmyports;
	myport_t *mp = myports;
	/* if this is not on my port */
	while( n ) {
	    /* if accepted on my socket */
	    if ( mp->so == rq->accepted_so) break;
	    n--;mp++;
	}
	if ( !n ) {
	    goto notdone;  /* not my */
	}
    } else
	goto notdone;

    if ( rq->url.host )	   /* it have hostpart in url already */
	goto notdone;

    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "redir(): transparent: my.\n");
    if ( rq->av_pairs)
	host = attr_value(rq->av_pairs, "host");
    if ( !host ) {
	/* We can try to fetch destination using IPF */
#if	defined(HAVE_IPF)
	struct natlookup natLookup, *natLookupP = &natLookup;
	static int natfd = -1, r;

	natLookup.nl_inport = rq->my_sa.sin_port;
	natLookup.nl_outport = rq->client_sa.sin_port;
	natLookup.nl_inip = rq->my_sa.sin_addr;
	natLookup.nl_outip = rq->client_sa.sin_addr;
	natLookup.nl_flags = IPN_TCP;
	if (natfd < 0) {
	    natfd = open(IPL_NAT, O_RDONLY, 0);
	    if (natfd < 0) {
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG|OOPS_LOG_SEVERE, "redir(): transparent: NAT open failed: %m\n");
		goto notdone;
	    }
	}
#define	NEWSIOCGNATLCMD	_IOWR('r', 63, struct natlookup *)
        if ( SIOCGNATL == NEWSIOCGNATLCMD)
		r = ioctl(natfd, SIOCGNATL, &natLookupP);
        else
		r = ioctl(natfd, SIOCGNATL, &natLookup);
#undef	NEWSIOCGNATLCMD
        if ( r < 0 ) {
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG|OOPS_LOG_SEVERE, "redir(): transparent: NAT lookup failed: ioctl(SIOCGNATL).\n");
	    goto notdone;
	} else {
	    struct sockaddr_in	sa;
	    bzero(&sa, sizeof(sa));
	    sa.sin_addr = natLookup.nl_realip;
	    rq->url.host = my_inet_ntoa(&sa);
	    rq->url.port = ntohs(natLookup.nl_realport);
	    goto done;
	}
#else
	/* last resort - take destination ip from my_sa */
	rq->url.host = my_inet_ntoa(&rq->my_sa);
	rq->url.port = ntohs(rq->my_sa.sin_port);
	goto notdone;
#endif
    }

    if ( (dd = strchr(host, ':')) ) {
	u_short host_port;
	*dd = 0;
	host_port = atoi(dd+1);
	if ( host_port ) port = host_port;
    } else
	    port = 80;
    rq->url.host = strdup(host);
    rq->url.port = port;
    if ( dd ) *dd = ':';
    if ( !TEST(rq->flags, RQ_HAS_HOST) && rq->url.host) {
	/* insert Host: header */
	put_av_pair(&rq->av_pairs, "Host:", rq->url.host);
    }

done:
    SET(*flags, MOD_AFLAG_CKACC); /* we must check acces again */
notdone:
    UNLOCK_TP_CONFIG ;
    return(MOD_CODE_OK);
}
