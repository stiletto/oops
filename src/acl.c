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
#include	<fcntl.h>

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
rq_to_group(struct request * rq)
{
struct	cidr_net	*net;
int			i;
struct	group		*g = groups;
struct	in_addr		*addr = &rq->client_sa.sin_addr;

    /* First check networks_acl for each group	*/
    while ( g ) {
	if (    g->networks_acl
	     && check_acl_list(g->networks_acl, rq) ) return(g);
	g = g->next;
    }
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
struct	domain_list	*best_allow1, *best_deny1, *dom;
struct	acl		*acl;

    acl = acls->allow ;
    while ( acl ) {
	if ( acl->type == ACL_DOMAINDST ) {
	    dom = (struct domain_list*)acl->list;
	    best_allow1 = find_best_dom(dom, name);
	    if ( !best_allow ) best_allow = best_allow1;
		else {
	    if (best_allow && best_allow1 && 
		(best_allow1->length > best_allow->length))
		    best_allow = best_allow1;
	    }
	}
	acl = acl->next;
    }
    acl = acls->deny ;
    while ( acl ) {
	if ( acl->type == ACL_DOMAINDST ) {
	    dom = (struct domain_list*)acl->list;
	    best_deny1 = find_best_dom(dom, name);
	    if ( !best_deny ) best_deny = best_deny1;
		else {
		    if (best_deny && best_deny1 && 
			(best_deny1->length > best_deny->length))
			  best_deny = best_deny1;
	    }
	}
	acl = acl->next;
    }
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
struct  sockaddr_in		peer;
int				peerlen = sizeof(peer);
struct  group			*group;
struct	acl			*acl;
struct	domain_list		*dom, *best_allow, *best_deny;
struct	domain_list		*best_allow1, *best_deny1;
char				host[MAXHOSTNAMELEN], lh[MAXHOSTNAMELEN], *t;
char				*s;
int				dstdomain_cache_result = DSTDCACHE_NOTFOUND;
struct	dstdomain_cache_entry	**dst_he = NULL, *dst_he_data = NULL;

    if ( !rq->url.host ) return(0);
    strncpy(host, (*rq).url.host, sizeof(host)-1);
    if ( !strchr(host, '.') ) {
	gethostname(lh, sizeof(lh));
	t = strchr(lh, '.');
	if ( !t ) /* host in request has no domain part and local hostname
		     has no domain */
		return(0);
	strncpy(host+strlen(host), t, sizeof(host) - strlen(host) -1 );
    }
    group = rq_to_group(rq);
    s = my_inet_ntoa(&rq->client_sa);
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

    /* first, check it in the dstdomain cache */
    if ( group->dstdomain_cache ) {
	dst_he = (struct dstdomain_cache_entry**)hash_get(group->dstdomain_cache, host);
        if ( dst_he ) dst_he_data = *dst_he;
	if ( dst_he_data ) dstdomain_cache_result = dst_he_data->access;
    }

    best_allow = best_deny = NULL;
    /* find longest allow str */
    acl = group->http->allow;
    while ( acl ) {
	if ( acl )switch( acl->type ) {
	case ACL_DOMAINDST:
		if ( dstdomain_cache_result == DSTDCACHE_NOTFOUND ) {
		    dom = (struct domain_list*)acl->list;
		    best_allow1 = find_best_dom(dom, host);
		    if ( !best_allow ) best_allow = best_allow1;
			else {
		    if (best_allow && best_allow1 && 
		    	(best_allow1->length > best_allow->length))
			    best_allow = best_allow1;
		    }
		}
		break;
	default:
		break;
	}
	acl = acl->next;
    }
    /* find longest deny str */
    acl = group->http->deny;
    while( acl ) {
	if ( acl ) switch( acl->type ) {
	case ACL_DOMAINDST:
		if ( dstdomain_cache_result == DSTDCACHE_NOTFOUND ) {
		    dom = (struct domain_list*)acl->list;
		    best_deny1 = find_best_dom(dom, host);
		    if ( !best_deny ) best_deny = best_deny1;
			else {
			    if (best_deny && best_deny1 && 
				(best_deny1->length > best_deny->length))
				  best_deny = best_deny1;
		    }
		}
		break;
	default:
		break;
	}
	acl = acl->next;
    }
    if ( dstdomain_cache_result != DSTDCACHE_NOTFOUND ) {
	if ( group->dstdomain_cache && dst_he )
	    hash_release(group->dstdomain_cache, (void**)dst_he);
	if ( dstdomain_cache_result == DSTDCACHE_ALLOW )
		return(port_deny(group, rq));
	return(ACCESS_DOMAIN);
    } else {	/* we must insert data in cache */
	struct dstdomain_cache_entry	*new;

	if ( best_deny  && !best_allow )
		dstdomain_cache_result = DSTDCACHE_DENY;
	else if ( best_allow && !best_deny )
		dstdomain_cache_result = DSTDCACHE_ALLOW;
	else if ( !best_allow && !best_deny )
		dstdomain_cache_result = DSTDCACHE_DENY;
	else {
	    if ( best_deny->length >= best_allow->length )
		dstdomain_cache_result = DSTDCACHE_DENY;
	      else
		dstdomain_cache_result = DSTDCACHE_ALLOW;
	}
	new = xmalloc(sizeof(*new), "dstdhe");
	if ( new ) {
	    new->access = dstdomain_cache_result;
	    new->when_created = global_sec_timer;
	    *dst_he = (void*)new;
	}
	hash_release(group->dstdomain_cache, (void**)dst_he);
    }
    if ( dstdomain_cache_result == DSTDCACHE_ALLOW )
	    return(port_deny(group, rq));
	else
	    return(ACCESS_DOMAIN);
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
	    s = &doml->domain[doml->length - 1];
	    d = &host[hostlen - 1];
	    while ( i ) {
		if ( *s != *d ) break;
		i--; s--; d--;
	    }
	    if ( !i && ((doml->length == hostlen) || *d=='.') ) {
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
char
named_acl_type_by_name(char *type)
{
char	*res;

    if ( !strcasecmp(type, "urlregex") )
	return(ACL_URLREGEX);
    if ( !strcasecmp(type, "pathregex") )
	return(ACL_PATHREGEX);
    if ( !strcasecmp(type, "urlregexi") )
	return(ACL_URLREGEXI);
    if ( !strcasecmp(type, "pathregexi") )
	return(ACL_PATHREGEXI);
    if ( !strcasecmp(type, "usercharset") )
	return(ACL_USERCHARSET);
    if ( !strcasecmp(type, "src_ip") )
	return(ACL_SRC_IP);
    if ( !strcasecmp(type, "method") )
	return(ACL_METHOD);
    if ( !strcasecmp(type, "port") )
	return(ACL_PORT);
    if ( !strcasecmp(type, "dstdom") )
	return(ACL_DSTDOM);
    if ( !strcasecmp(type, "dstdom_regex") )
	return(ACL_DSTDOMREGEX);
    if ( !strcasecmp(type, "srcdom") )
	return(ACL_SRCDOM);
    if ( !strcasecmp(type, "srcdom_regex") )
	return(ACL_SRCDOMREGEX);
    return(-1);
}
void
free_named_acl(named_acl_t *acl)
{
struct	urlregex_acl_data	*ura = NULL;

    if ( !acl ) return;
    switch( acl->type ) {
case ACL_SRCDOM:
case ACL_DSTDOM:
	if (acl->data)
		free_dom_list((struct domain_list *)acl->data);
	acl->data = NULL;
	break;
case ACL_URLREGEX:
case ACL_PATHREGEX:
case ACL_URLREGEXI:
case ACL_PATHREGEXI:
case ACL_DSTDOMREGEX:
case ACL_SRCDOMREGEX:
	ura = (struct urlregex_acl_data*)acl->data;
	if ( ura ) {
	    /* free regex data */
	    if ( ura->regex ) free(ura->regex);
	    regfree(&ura->preg);
	}
	break;
case ACL_PORT:
case ACL_METHOD:
case ACL_USERCHARSET:
	/* nothing was allocated in structure	*/
	break;
case ACL_SRC_IP:
	{
	struct	acl_ip_data *acl_ip_data = (struct  acl_ip_data*)acl->data;

	if ( !acl_ip_data ) break;
	if ( acl_ip_data->unsorted ) free_net_list(acl_ip_data->unsorted);
	if ( acl_ip_data->sorted ) free(acl_ip_data->sorted);
	}
	break;
default:
	my_log("Try to free unknown named acl %s\n", acl->name);
    }
    if ( acl->data ) free(acl->data);
    free(acl);
}
int
parse_named_acl_data(named_acl_t *acl, char *data)
{
int	regflags = 0;
char	*p, *t, *tokptr;
struct	range *ports, *range;
int	must_free_data = FALSE;

    if ( !acl || !data )
	return(-1);
    if ( !strncasecmp(data, "include:", 8) ) {
	/* if data begins with 'include:' - load data from file */
	char		*fn;
	off_t		new_data_sz;
	struct	stat	sb;
	int		fd;

	fn = data + 8;
	if ( stat(fn, &sb) ) {
	    printf("Can't stat file %s: %s\n", fn, strerror(errno));
	    return(0);
	}
	new_data_sz = sb.st_size;
	if ( new_data_sz <= 0 ) {
	    printf("Empty file %s?\n", fn);
	    return(0);
	}
	fd = open(fn, O_RDONLY);
	if ( fd < 0 ) {
	    printf("Can't open file %s: %s\n", fn, strerror(errno));
	    return(0);
	}
	data = malloc(new_data_sz);
	if ( !data ) {
	    close(fd);
	    return(0);
	}
	if ( read(fd, data, new_data_sz) != new_data_sz ) {
	    printf("Can't read data from file %s\n", fn);
	    close(fd);
	    free(data);
	    return(0);
	}
	close(fd);
	must_free_data = TRUE;
    }
    switch(acl->type) {
case ACL_URLREGEXI:
case ACL_PATHREGEXI:
	regflags = REG_ICASE;
case ACL_DSTDOMREGEX:
case ACL_URLREGEX:
case ACL_PATHREGEX:
	regflags|= REG_EXTENDED|REG_NOSUB;
	/* data must be regex	*/
	{
	    struct	urlregex_acl_data	*urd;

	    urd = malloc(sizeof(*urd));
	    if ( !urd ) {
		if ( must_free_data ) free(data);
		return(1);
	    }
	    bzero(urd, sizeof(*urd));
	    urd->regex = strdup(data);
	    if ( !urd->regex ) {
		if ( must_free_data ) free(data);
		free(urd);
		return(1);
	    }
	    /* compile regex into pred */
	    if ( regcomp(&urd->preg, urd->regex, regflags) ) {
		if ( must_free_data ) free(data);
		free(urd->regex);
		free(urd);
		return(1);
	    }
	    acl->data = urd;
	}	
	return(0);
case ACL_PORT:
	printf("acl->data: '%s'\n", data);
	/* range,range,... where range = port | [port:port]	*/
	/* split on ',' */
	p = data;
	ports = calloc(MAXBADPORTS, sizeof(*ports));
	if ( !ports ) {
	    if ( must_free_data ) free(data);
	    return(0);
	}
	range = ports;
	while( (t = (char*)strtok_r(p, ", \n", &tokptr)) && (range-ports < MAXBADPORTS)) {
	  int	pf, pt;

	    p = NULL;
	    pf = pt = -1;
	    /*printf("Token: %s\n", t);*/
	    if ( sscanf(t, "%d", &pf) == 1 ) {
		range->length = 1;
		range->from = pf;
		range++;
	    } else
	    if ( sscanf(t, "[%d:%d]", &pf, &pt) == 2 ) {
		range->length = pt - pf + 1;
		range->from = pf;
		range++;
	    }
	}
	acl->data = ports;
	if ( must_free_data ) free(data);
	return(0);
case ACL_METHOD:
	printf("acl->data: '%s'\n", data);
	if ( data ) acl->data = strdup(data);
	if ( must_free_data ) free(data);
	return(0);
case ACL_USERCHARSET:
	/* string with charset name			*/
	{
	    u_charset_t	*ucsd;
	    ucsd = malloc(sizeof(*ucsd));
	    if ( !ucsd ) {
		if ( must_free_data ) free(data);
		return(1);
	    }
	    bzero(ucsd, sizeof(*ucsd));
	    strncpy(ucsd->name, data, sizeof(ucsd->name)-1);
	    acl->data = ucsd;
	}
	if ( must_free_data ) free(data);
	return(0);
case ACL_DSTDOM:
	{
	struct	domain_list	*new, *next;
	/* domain domain domain ...			*/
	    acl->data = NULL;
	    printf("acl->data: '%s'\n", data);
	    /* split on ' ' */
	    p = data;
	    while( (t = (char*)strtok_r(p, ", \n", &tokptr)) ) {
		int	pf, pt;

		p = NULL;
		printf("token: %s\n", t);
		new = calloc(1, sizeof(*new));
		if ( new && (new->domain = malloc(strlen(t)+1))) {
		    new->length = strlen(t);
		    memcpy_to_lower(new->domain, t, new->length + 1);
		    if ( !strcmp(t, "*") ) new->length = -1;
		    next = (struct  domain_list *)acl->data;
		    if ( next ) {
			while(next->next)next = next->next;
			next->next = new;
		    } else {
			acl->data = new;
		    }
		} else {
		    if ( new && new->domain ) free(new->domain);
		    if ( new ) free(new);
		}
	    }
	}
	if ( must_free_data ) free(data);
	return(0);
case ACL_SRC_IP:
	/* IP IP IP					*/
	/* IP in format a.b.c.d or a.b.c/l		*/
	{
	  char			*tptr, *t, *p;
	  struct cidr_net	*networks = NULL, *last = NULL;
	  int			networks_num = 0;

	    verb_printf("SRC_IP: %s\n", data);
	    t = data;
	    while ( (p = (char*)strtok_r(t, "\t \n", &tptr)) ) {
	      char	*slash = NULL, masklen, *tt, *pp, *ttptr;
	      int	net = 0, i = 24;
	      struct	cidr_net *new;

		t = NULL;
		verb_printf("SRC: %s\n", p);
		if ( (slash = strchr(p, '/')) ) {
		    masklen = atoi(slash+1);
		    *slash = 0;
		} else {
		    masklen = 32;
		}
		tt = p;
		while ( (pp = (char*)strtok_r(tt,".", &ttptr)) ) {
		    tt = NULL;

		    net |= (atol(pp) << i);
		    i -= 8;
		}
		if ( slash ) *slash = '/';
		verb_printf("NET: %0x/%d\n", net, masklen);
		new = malloc(sizeof(*new));
		if ( !new ) continue;
		bzero(new, sizeof(*new));
		new->network = net;
		new->masklen = masklen;
		if ( !masklen )
			new->mask = 0;
		    else {
			if ( masklen < 0 || masklen > 32 ) {
				free(new);
				continue;
			}
		    new->mask = (int)0x80000000 >> ( masklen - 1 );
		}
		if ( !last ) {
		    networks = new;
		} else {
		    last->next = new;
		}
		last = new;
		networks_num++;
	    }
	    if ( networks ) {
		struct acl_ip_data *acl_ip_data;
		acl_ip_data = malloc(sizeof(*acl_ip_data));
		if ( ! acl_ip_data ) {
		    if ( must_free_data ) free(data);
		    free_net_list(networks);
		    return(0);
		}
	        acl_ip_data->sorted = sort_n(networks, &acl_ip_data->num);
		acl_ip_data->unsorted = networks;
		print_networks(acl_ip_data->sorted, acl_ip_data->num, FALSE);
		acl->data = acl_ip_data;
	    }
	}
	if ( must_free_data ) free(data);
	return(0);
default:
	my_log("Unknown acl type %d in parse_named_acl_data\n", acl->type);
	printf("Unknown acl type %d in parse_named_acl_data\n", acl->type);
    }
    if ( must_free_data ) free(data);
    return(0);
}

int
rq_match_named_acl(struct request *rq, named_acl_t *acl)
{
int				length = 0;
char				*url;
struct	urlregex_acl_data	*urd;
u_charset_t			*ucsd;

    if ( !rq || !acl) return(FALSE);
    switch(acl->type) {
case ACL_DSTDOMREGEX:
	if ( !rq->url.host ) return(FALSE);
	urd = (struct  urlregex_acl_data*)acl->data;
	if (regexec(&urd->preg, rq->url.host, 0,  NULL, 0))
	    return(FALSE);
	return(TRUE);
	break;
case ACL_URLREGEXI:
case ACL_URLREGEX:
	/* compose url and check against regex */
	if ( !rq->url.proto || !rq->url.host || !rq->url.path || !acl->data)
	    return(FALSE);
	length += strlen(rq->url.proto)
	         +strlen(rq->url.host)
	         +strlen(rq->url.path);
	length += 3 /* :// */ + 1 /* \0 */;
	url = malloc(length);
	if ( !url ) return(FALSE);
	sprintf(url, "%s://%s%s", rq->url.proto, rq->url.host, rq->url.path);
	/* now check */
	urd = (struct  urlregex_acl_data*)acl->data;
	if (regexec(&urd->preg, url, 0,  NULL, 0)) {
	    free(url);
	    return(FALSE);
	}
	free(url);
	return(TRUE);
	break;

case ACL_PATHREGEXI:
case ACL_PATHREGEX:
	/* take path and check against regex */
	if ( !rq->url.path || !acl->data)
	    return(FALSE);
	/* now check */
	urd = (struct  urlregex_acl_data*)acl->data;
	if (regexec(&urd->preg, rq->url.path, 0,  NULL, 0))
	    return(FALSE);
	return(TRUE);
	break;

case ACL_USERCHARSET:
	ucsd = (u_charset_t*)acl->data;
	if ( !ucsd ) return(FALSE);
	{
	    char	*agent = attr_value(rq->av_pairs, "user-agent");
	    charset_t	*agent_cs;

	    if ( !agent ) return(FALSE);
	    if ( !ucsd->cs ) {
		if ( !charsets ) return(FALSE);
		ucsd->cs = lookup_charset_by_name(charsets, ucsd->name);
	    }
	    agent_cs = lookup_charset_by_Agent(charsets, agent);
	    if ( !agent_cs ) return(FALSE);
	    return( agent_cs == ucsd->cs );
	}
	break;
case ACL_SRC_IP:
	{
	struct acl_ip_data *acl_ip_data = (struct acl_ip_data *)acl->data;
	struct  cidr_net   *net;
	int		   i;
	struct	in_addr	   *addr = &(rq->client_sa.sin_addr);

	    if ( !acl_ip_data ) break;
	    if (  (acl_ip_data->num<=0) 
	       || !acl_ip_data->sorted
	       || !acl_ip_data->unsorted ) break;

	    for(i=0;i<acl_ip_data->num;i++) {
		net = acl_ip_data->sorted[i];
		if ( (net->network & net->mask) ==
		     (ntohl(addr->s_addr) & net->mask) ) return(TRUE);
	    }
	}
	break;
case ACL_METHOD:
	if ( !acl->data ||
	     !rq->method ||
	     strcasecmp((char*)acl->data, rq->method) ) return(FALSE);
	return(TRUE);
	break;
case ACL_DSTDOM:
	if ( acl->data && rq->url.host ) {
	    struct domain_list	*best =
	    	find_best_dom((struct domain_list*)acl->data, rq->url.host);
	    if ( best ) return(TRUE);
	}
	break;
case ACL_PORT:
	if ( !acl->data ||
	     !rq->url.port ) return(FALSE);
	{
	    struct range *range = (struct range*)acl->data;

	    while ( range && range->length ) {
		if ( rq->url.port >= range->from &&
			rq->url.port < range->from+range->length )
				return(TRUE);
		range++;
	    }
	}
	break;
default:
	break;
    }
    return(FALSE);
}

int
rq_match_named_acl_by_index(struct request *rq, int index)
{
named_acl_t	*curr = named_acls;

    if ( !rq || !index ) return(FALSE);
    while( curr ) {
	if ( curr->internal_number == index ) {
	    return(rq_match_named_acl(rq, curr));
	}
	curr = curr->next;
    }
    return(FALSE);
}

int
url_match_named_acl(char *url, named_acl_t *acl)
{
int				length = 0;
struct	urlregex_acl_data	*urd;
struct	url			parsed_url;

    if ( !url || !acl) return(FALSE);

    bzero(&parsed_url, sizeof(parsed_url));
    parse_raw_url(url, &parsed_url);
    if ( !parsed_url.port ) parsed_url.port = 80;

    switch(acl->type) {
case ACL_DSTDOMREGEX:
	if ( !parsed_url.host ) return(FALSE);
	urd = (struct  urlregex_acl_data*)acl->data;
	if (regexec(&urd->preg, parsed_url.host, 0,  NULL, 0))
	    return(FALSE);
	return(TRUE);
	break;
case ACL_URLREGEXI:
case ACL_URLREGEX:
	free_url(&parsed_url);
	/* now check */
	urd = (struct  urlregex_acl_data*)acl->data;
	if (regexec(&urd->preg, url, 0,  NULL, 0)) {
	    return(FALSE);
	}
	return(TRUE);

case ACL_PATHREGEXI:
case ACL_PATHREGEX:
	/* take path and check against regex */
	if ( !parsed_url.path || !acl->data) {
	    free_url(&parsed_url);
	    return(FALSE);
	}
	/* now check */
	urd = (struct  urlregex_acl_data*)acl->data;
	if (regexec(&urd->preg, parsed_url.path, 0,  NULL, 0)) {
	    free_url(&parsed_url);
	    return(FALSE);
	}
	free_url(&parsed_url);
	return(TRUE);
case ACL_DSTDOM:
	if ( acl->data && parsed_url.host ) {
	    struct domain_list	*best =
	    	find_best_dom((struct domain_list*)acl->data, parsed_url.host);
	    if ( best ) return(TRUE);
	}
	break;
case ACL_PORT:
	if ( acl->data && parsed_url.port ) {
	    struct range *range = (struct range*)acl->data;

	    while ( range && range->length ) {
		if ( parsed_url.port >= range->from &&
			parsed_url.port < range->from+range->length ) {
				free_url(&parsed_url);
				return(TRUE);
		}
		range++;
	    }
	}
	free_url(&parsed_url);
	return(FALSE);
default:
	break;
    }
    return(FALSE);
}
int
url_match_named_acl_by_index(char *url, int index)
{
named_acl_t	*curr = named_acls;

    if ( !url || !index ) return(FALSE);
    while( curr ) {
	if ( curr->internal_number == index ) {
	    return(url_match_named_acl(url, curr));
	}
	curr = curr->next;
    }
    return(FALSE);
}


void
insert_named_acl_in_list(named_acl_t *acl)
{
named_acl_t	*curr = named_acls;
int		n = 1;
    if ( !acl )
	return;
    if ( !curr ) {
	acl->internal_number = 1;
	named_acls = acl;
	return;
    }
    while( curr->next ) curr = curr->next;
    curr->next = acl;
    acl->internal_number = curr->internal_number + 1;
    return;
}

void
free_named_acls(named_acl_t *aclist)
{
named_acl_t	*curr = aclist, *next;

    while ( curr ) {
	next = curr->next;
	my_log("Release acl %s\n", &curr->name);
	free_named_acl(curr);
	curr = next;
    }
    
}

/* must be called with config locked or during reconfigure process */
/* ret index if found, or 0					   */
int
acl_index_by_name(char *name)
{
named_acl_t	*curr = named_acls;

    if ( !name || !named_acls ) return(0);
    while ( curr ) {
	if ( !strcmp(curr->name, name) ) {
	    return(curr->internal_number);
	}
	curr = curr->next;
    }
    return(0);
}

/* must be called with config locked or during reconfigure process */
/* ret acl ptr, or NULL						   */
named_acl_t*
acl_by_name(char *name)
{
named_acl_t	*curr = named_acls;

    if ( !name || !named_acls ) return(0);
    while ( curr ) {
	if ( !strcmp(curr->name, name) ) {
	    return(curr);
	}
	curr = curr->next;
    }
    return(NULL);
}

int
check_acl_access(acl_chk_list_hdr_t *acl_access, struct request *rq)
{
acl_chk_list_hdr_t *curr = acl_access;

    while(curr) {
	if ( check_acl_list((acl_chk_list_t*)curr, rq) == TRUE ) {
	    if ( rq->matched_acl ) free(rq->matched_acl);
	    rq->matched_acl = NULL;
	    if (curr->aclbody)
		rq->matched_acl = strdup(curr->aclbody);
	    return(TRUE);
	}
	curr = curr->next_list;
    }
    return(FALSE);
}

/* return TRUE if request pass list	*/
int
check_acl_list(acl_chk_list_t *list, struct request *rq)
{
int	res;

    while(list) {
	if ( list->acl ) {
	    res = rq_match_named_acl(rq, list->acl);
	    res ^= list->sign;
	    if ( res == FALSE ) return(FALSE);
	}
	list = list->next;
    }
    return(TRUE);
}

void
free_acl_access(acl_chk_list_hdr_t *list)
{
acl_chk_list_hdr_t	*next;

    while(list) {
	if ( list->aclbody ) free(list->aclbody);
	next = list->next_list;
	free_acl_list((acl_chk_list_t*)list);
	list = next;
    }
}

void
free_acl_list(acl_chk_list_t *list)
{
acl_chk_list_t	*next;

    while(list) {
	next = list->next;
	free(list);
	list = next;
    }
}

void
parse_acl_access(acl_chk_list_hdr_t **list, char *string)
{
char			*p, *t, *tptr;
int			sign, first = TRUE;
named_acl_t		*acl;
acl_chk_list_t		*new, *next;
acl_chk_list_hdr_t	*newhdr, *nexthdr;

    newhdr = malloc(sizeof(*newhdr));
    if ( !newhdr ) return;

    bzero(newhdr, sizeof(*newhdr));
    verb_printf("PARSING ACL: %s\n", string);
    t = string;
    while ( (p=(char*)strtok_r(t, "\t ", &tptr)) ) {
	t = NULL;

	sign = 0;
	if ( *p == '!' ) {
	    sign = 1;
	    p++;
	}
	acl = acl_by_name(p);
	if ( acl ) {
	    if ( !first ) {
		new = malloc(sizeof(*new));
		bzero(new, sizeof(*new));
		next = (acl_chk_list_t*)newhdr;
		while ( next->next ) next = next->next;
		next->next = new;
	    } else {
		first = FALSE;
		new = (acl_chk_list_t*)newhdr;
	    }
	    if ( !new ) continue;
	    new->acl = acl;
	    new->sign = sign;
	} else {
	    verb_printf("Unknown acl '%s'\n", p);
	    goto error;
	}
    }
done:
    newhdr->aclbody = strdup(string);
    if ( !*list )
	*list = newhdr;
    else {
	nexthdr = *list;
	while ( nexthdr->next_list ) nexthdr = nexthdr->next_list;
	nexthdr->next_list = newhdr;
    }
    return;
error:
    if ( newhdr ) free_acl_list((acl_chk_list_t*)newhdr);
}

void
parse_networks_acl(acl_chk_list_hdr_t **list, string_list_t *string_list)
{
int			sign, first = TRUE;
named_acl_t		*acl;
acl_chk_list_t		*new, *next;
acl_chk_list_hdr_t	*newhdr, *nexthdr;
char			*p;

    newhdr = malloc(sizeof(*newhdr));
    if ( !newhdr ) return;

    bzero(newhdr, sizeof(*newhdr));
    while ( string_list) {

	sign = 0;
	p = string_list->string;
	if ( *p == '!' ) {
	    sign = 1;
	    p++;
	}
	acl = acl_by_name(p);
	if ( acl && (acl->type==ACL_SRC_IP) ) {
	    if ( !first ) {
		new = malloc(sizeof(*new));
		bzero(new, sizeof(*new));
		next = (acl_chk_list_t*)newhdr;
		while ( next->next ) next = next->next;
		next->next = new;
	    } else {
		first = FALSE;
		new = (acl_chk_list_t*)newhdr;
	    }
	    if ( !new ) continue;
	    new->acl = acl;
	    new->sign = sign;
	} else {
	    verb_printf("Unknown acl '%s' or bad type (only src_ip allowed)\n", p);
	    goto error;
	}
	string_list = string_list->next;
    }
done:
    newhdr->aclbody = NULL;
    if ( !*list )
	*list = newhdr;
    else {
	nexthdr = *list;
	while ( nexthdr->next_list ) nexthdr = nexthdr->next_list;
	nexthdr->next_list = newhdr;
    }
    return;
error:
    if ( newhdr ) free_acl_list((acl_chk_list_t*)newhdr);
}
