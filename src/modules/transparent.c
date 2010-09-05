#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<string.h>
#include	<strings.h>
#include	<netdb.h>
#include	<unistd.h>
#include	<ctype.h>
#include	<signal.h>
#include	<locale.h>
#include	<time.h>

#if	defined(SOLARIS)
#include	<thread.h>
#endif

#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/file.h>
#include	<sys/time.h>
#include	<sys/resource.h>

#include	<netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include	"../oops.h"
#include	"../modules.h"

#if		HAVE_IPF==1
#include	<sys/ioctl.h>
#include	<netinet/tcp.h>
#include	<net/if.h>
#include	<netinet/ip_compat.h>
#include	<netinet/ip_fil.h>
#include	<netinet/ip_nat.h>
int		natfd;
#endif

char	module_type   = MODULE_REDIR ;
char	module_name[] = "transparent" ;
char	module_info[] = "Tranparent proxy" ;

static	rwl_t	tp_lock;
#define	RDLOCK_TP_CONFIG	rwl_rdlock(&tp_lock)
#define	WRLOCK_TP_CONFIG	rwl_wrlock(&tp_lock)
#define	UNLOCK_TP_CONFIG	rwl_unlock(&tp_lock)

#define	NMYPORTS	4
static	myport_t	myports[NMYPORTS];	/* my ports		*/
static	int		nmyports;		/* actual number	*/
static	char		*myports_string;
/* static	char		*build_src(struct request*); */

int
mod_load()
{
    verb_printf("Transparent started\n");
    rwl_init(&tp_lock);
    nmyports = 0;
#if	HAVE_IPF==1
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
mod_config_beg()
{
    WRLOCK_TP_CONFIG ;
    nmyports = 0;
    if ( myports_string ) free(myports_string);
    myports_string = NULL;
#if	HAVE_IPF==1
    if ( natfd != -1 ) close(natfd);
    natfd = -1;
#endif
    UNLOCK_TP_CONFIG ;
    return(MOD_CODE_OK);
}

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
mod_config_end()
{
    return(MOD_CODE_OK);
}

int
mod_config(char *config)
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
redir(int so, struct group *group, struct request *rq, int *flags)
{
char			*host = NULL;
u_short			port;
char			*dd = NULL;

    RDLOCK_TP_CONFIG ;
    my_xlog(LOG_DBG, "redir(): redir/transparent called.\n");
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

    my_xlog(LOG_HTTP|LOG_DBG, "redir(): transparent: my.\n");
    if ( rq->av_pairs)
	host = attr_value(rq->av_pairs, "host");
    if ( !host ) {
	/* We can try to fetch destination using IPF */
#if	HAVE_IPF==1
	struct natlookup natLookup;
	static int natfd = -1;

	natLookup.nl_inport = rq->my_sa.sin_port;
	natLookup.nl_outport = rq->client_sa.sin_port;
	natLookup.nl_inip = rq->my_sa.sin_addr;
	natLookup.nl_outip = rq->client_sa.sin_addr;
	natLookup.nl_flags = IPN_TCP;
	if (natfd < 0) {
	    natfd = open(IPL_NAT, O_RDONLY, 0);
	    if (natfd < 0) {
		my_xlog(LOG_HTTP|LOG_DBG|LOG_SEVERE, "redir(): transparent: NAT open failed: %s\n",
		    strerror(errno));
		goto notdone;
	    }
	}
	if (ioctl(natfd, SIOCGNATL, &natLookup) < 0) {
	    my_xlog(LOG_HTTP|LOG_DBG|LOG_SEVERE, "redir(): transparent: NAT lookup failed: ioctl(SIOCGNATL).\n");
	    goto notdone;
	} else {
	    struct sockaddr_in	sa;
	    bzero(&sa, sizeof(sa));
	    sa.sin_addr = natLookup.nl_realip;
	    rq->url.host = my_inet_ntoa(&sa);
	    rq->url.port = natLookup.nl_realport;
	    goto done;
	}
#else
	/* last resort - take destination ip from my_sa */
	rq->url.host = my_inet_ntoa(&rq->my_sa);
	rq->url.port = rq->my_sa.sin_port;
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
