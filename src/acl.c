#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<errno.h>
#include	<string.h>
#include	<strings.h>
#include	<stdarg.h>
#include	<netdb.h>
#include	<ctype.h>
#include	<time.h>

#include	<sys/stat.h>
#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/socketvar.h>
#include	<sys/time.h>

#include	<netinet/in.h>

#include	<arpa/inet.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"


struct	domain_list	*find_best_dom(struct domain_list*, char*);
int			port_deny(struct group *, struct request *);

struct group *
inet_to_group(struct in_addr * addr)
{
struct	cidr_net	*net;
int			i;
    if ( !sorted_networks_cnt || !sorted_networks_ptr )
	return(NULL);
    for(i=0;i<sorted_networks_cnt;i++) {
	net = sorted_networks_ptr[i];
	if ( (net->network & net->mask) == (ntohl(addr->s_addr) & net->mask) )
		break;
	net = net->next;
    }
    if ( i < sorted_networks_cnt )
	return(net->group);
    return(NULL);
}

int
is_domain_allowed(char *name, struct acls *acls)
{
struct	domain_list	*allow = NULL, *deny = NULL, *best_allow = NULL, *best_deny = NULL;
struct	acl		*acl;

    acl = acls->allow ;
    while ( acl ) {
	if ( acl->type == ACL_DOMAINDST ) {
	    allow = (struct domain_list*)acl->list;
	    break;
	}
	acl = acl->next;
    }
    acl = acls->deny ;
    while ( acl ) {
	if ( acl->type == ACL_DOMAINDST ) {
	    deny = (struct domain_list*)acl->list;
	    break;
	}
	acl = acl->next;
    }
    if ( allow )
	best_allow = find_best_dom(allow, name);
    if ( deny  )
	best_deny = find_best_dom(deny, name);
    if ( best_deny  && !best_allow ) return(FALSE);
    if ( best_allow && !best_deny  ) return(TRUE);
    if ( !best_allow && !best_deny ) return(FALSE);
    if ( best_deny->length >= best_allow->length )
		return(FALSE);
	else
		return(TRUE);
}

int
deny_http_access(int so, struct request *rq)
{
struct  sockaddr_in	peer;
int			peerlen = sizeof(peer);
struct  group		*group;
struct	acl		*acl;
struct	domain_list	*dom, *best_allow, *best_deny;
struct	domain_list	*best_allow1, *best_deny1;
char			host[MAXHOSTNAMELEN], lh[MAXHOSTNAMELEN], *t;
char			*s;

    strncpy(host, (*rq).url.host, sizeof(host)-1);
    if ( !strchr(host, '.') ) {
	gethostname(lh, sizeof(lh));
	t = strchr(lh, '.');
	if ( !t ) /* host in request has no domain part and local hostname
		     has no domain */
		return(0);
	strncpy(host+strlen(host), t, sizeof(host) - strlen(host) -1 );
    }
    if ( getpeername(so, (struct sockaddr*)&peer, &peerlen) ) {
	my_log("Can't getpeername: %s\n", strerror(errno));
	return(ACCESS_DOMAIN);
    }
    group = inet_to_group(&peer.sin_addr);
    s = my_inet_ntoa(&peer);
    if ( !group ) {
	if ( s ) {
	    my_log("No group for address %s - access denied\n", s);
	    xfree(s);
	}
	return(ACCESS_DOMAIN);
    }
    if ( s ) my_log("Connect from %s - group [%s]\n",
		s, group->name);
    if ( !group->http || !group->http->allow ) {
	if (s) {
	    my_log("No http or http_>allow for address %s - access denied\n", s);
	    xfree(s);
	}
	return(ACCESS_DOMAIN);
    }
    if ( s ) xfree(s);
    best_allow = best_deny = NULL;
    /* find longest allow str */
    acl = group->http->allow;
    while ( acl ) {
	if ( acl )switch( acl->type ) {
	case ACL_DOMAINDST:
		dom = (struct domain_list*)acl->list;
		best_allow1 = find_best_dom(dom, host);
		break;
	default:
		break;
	}
	if ( !best_allow ) best_allow = best_allow1;
	    else {
		if (best_allow && best_allow1 && 
		    (best_allow1->length > best_allow->length))
		    	best_allow = best_allow1;
	}
	acl = acl->next;
    }
    /* find longest deny str */
    acl = group->http->deny;
    while( acl ) {
	if ( acl ) switch( acl->type ) {
	case ACL_DOMAINDST:
		dom = (struct domain_list*)acl->list;
		best_deny1 = find_best_dom(dom, host);
		break;
	default:
		break;
	}
	if ( !best_deny ) best_deny = best_deny1;
	    else {
		if (best_deny && best_deny1 && 
		    (best_deny1->length > best_deny->length))
		    	best_deny = best_deny1;
	}
	acl = acl->next;
    }
    if ( best_deny  && !best_allow ) return(ACCESS_DOMAIN);
    if ( best_allow && !best_deny  ) return(port_deny(group, rq));
    if ( !best_allow && !best_deny ) return(ACCESS_DOMAIN);
    if ( best_deny->length >= best_allow->length )
		return(ACCESS_DOMAIN);
	else
		return(port_deny(group, rq));
}

int
miss_deny(struct group *group)
{
    return(group->miss_deny);
}

int
port_deny(struct group *group, struct request *rq)
{
struct range	*range;

    if ( !group->badports ) return(0);
    if ( rq->url.proto && !strcmp(rq->url.proto,"ftp") ) {
	if ( (rq->url.port == 20) || (rq->url.port == 21) )
	return(0);
    }
    range = (struct range*)group->badports;
    while( range <= (struct range*)&group->badports[MAXBADPORTS-1] ) {
	if ( !range->length )
	    return(0);
	if ( rq->url.port >= range->from &&
	     rq->url.port < range->from+range->length )
		return(ACCESS_PORT);
	range++;
    }
    return(0);
}

/* find the longest string that is shorter then host and is substring
   of host.

   example: for host www.w3.org
   and list
	org
	w3.org
	com

   the best domain will be w3.org
 */

struct domain_list *
find_best_dom(struct domain_list *doml, char* host)
{
struct	domain_list	*best = NULL;
int			hostlen = strlen(host), i;
char			*d, *s;

    if ( hostlen <= 0 ) return(NULL);
    while(doml) {
	if ( doml->length == -1 ) /* this is "*" */
	    return(doml);
	if ( doml->length <= hostlen ) {
	    i = doml->length;
	    assert(doml->length>0);
	    s = &doml->domain[doml->length - 1];
	    d = &host[hostlen - 1];
	    while ( i ) {
		if ( tolower(*s) != tolower(*d) ) break;
		i--; s--; d--;
	    }
	    if ( !i ) {
		if ( !best )
			best = doml;
		    else {
			if ( doml->length > best->length )
			    best = doml;
		}
	    }
	}
	doml=doml->next;
    }
    return(best);
}

int
is_local_dom(char *host)
{
    if ( !local_domains )
	return(FALSE);
    if ( find_best_dom(local_domains, host ) )
	return(TRUE);
    return(FALSE);
}

int
is_local_net(struct sockaddr_in *sa)
{
struct	in_addr		*addr = &sa->sin_addr;
int			i;
struct	cidr_net	*net;

    if ( !local_networks_sorted || !local_networks_sorted_counter )
	return(FALSE);
    for(i=0;i<local_networks_sorted_counter;i++) {
	net = local_networks_sorted[i];
	if ( (net->network & net->mask) == (ntohl(addr->s_addr) & net->mask) )
		break;
	net = net->next;
    }
    if ( i < local_networks_sorted_counter )
	return(TRUE);
    return(FALSE);
}
int
denytime_check(struct denytime *dt)
{
int		reverse, sm,em,cm;
struct	tm	tm;
char		todaybit, dmask,yestdbit;

    if ( !dt ) return(0);

    localtime_r(&global_sec_timer, &tm);
    cm = tm.tm_hour * 60 + tm.tm_min;
    todaybit = 1 << tm.tm_wday;

    while(dt) {

	sm = dt->start_minute;
	em = dt->end_minute;
	dmask = dt->days;


	if ( sm < em ) reverse = FALSE;
	   else	       reverse = TRUE;

	my_log("Denytime check 0x%0x/0x%0x, %d-%d, %d\n", dmask,todaybit, sm, em, cm);
	if ( !reverse ) {
	    /* simple case of normal interval, like 09:00 - 18:00 */
	    if ( TEST(todaybit, dmask) ) {
		   /* this denytime cover this day */
		if ( sm <= cm && cm <= em )
			return(1);
		  else
			goto check_next_dt;
	    } else /* this denytime don't cover this day */
		goto check_next_dt;
	} else {
	    /* case of reverse interval, like 21:00 - 09:00 */
	    if ( TEST(todaybit, dmask) ) {
		if ( cm >= sm )
		    return(1);
		yestdbit = todaybit >> 1;
		/* if today is sunday, make yestd - sat */
		if ( !yestdbit ) yestdbit = 0x40;
		/* if this denytime record cover previous day? */
		if ( !TEST(yestdbit, dmask) )
		    goto check_next_dt;
		/* if we get in interval that started yesterday? */
		if ( cm <= em ) /* yes, we get */
		    return(1);
		/* no it finished earlier */
		goto check_next_dt;
	    }
	}

 check_next_dt:;
	dt = dt->next;
    }
    return(0);
}
