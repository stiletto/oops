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

#include	"oops.h"

static	named_acl_t	*acl_by_name(char*);
static	void		free_acl_list(acl_chk_list_t*);
static	int		rq_match_named_acl(struct request *rq, named_acl_t *acl);

inline	static	struct	domain_list	*find_best_dom(struct domain_list*, char*);
inline	static	int	check_acl_list(acl_chk_list_t *list, struct request *rq);
inline	static	int	obj_check_acl_list(acl_chk_list_t *, struct mem_obj *, struct request *);
inline	static	int	time_check_acl_list(acl_chk_list_t *, time_t);
inline	static	int	port_deny(struct group *, struct request *);


struct group *
rq_to_group(struct request * rq)
{
struct	cidr_net	*net = NULL;
int			i;
struct	group		*g = groups;
struct	in_addr		*addr = &rq->client_sa.sin_addr;

    /* First check networks_acl for each group	*/
    while ( g ) {
	if (    g->networks_acl
	     && check_acl_access(g->networks_acl, rq) ) return(g);
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
    if ( (i < sorted_networks_cnt) && net )
	return(net->group);
    return(NULL);
}

int
is_domain_allowed(char *name, struct acls *acls)
{
struct	domain_list	*best_allow = NULL, *best_deny = NULL;
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
deny_http_access(int so, struct request *rq, struct group *group)
{
struct	acl			*acl;
struct	domain_list		*dom, *best_allow, *best_deny;
struct	domain_list		*best_allow1, *best_deny1;
char				host[MAXHOSTNAMELEN], lh[MAXHOSTNAMELEN], *t;
char				*s;
int				dstdomain_cache_result = DSTDCACHE_NOTFOUND;
struct	dstdomain_cache_entry	**dst_he = NULL, *dst_he_data = NULL;
hash_entry_t                    *he = NULL;
int                             res;

    if ( !rq->url.host ) return(0);
    strncpy(host, (*rq).url.host, sizeof(host)-1);
    host[sizeof(host)-1] = 0;
    if ( !strchr(host, '.') ) {
	gethostname(lh, sizeof(lh));
	t = strchr(lh, '.');
	if ( !t ) /* host in request has no domain part and local hostname
		     has no domain */
		return(0);
	strncpy(host+strlen(host), t, sizeof(host) - strlen(host) -1 );
	host[sizeof(host)-1] = 0;
    }
    if ( !group ) group = rq_to_group(rq);
    s = my_inet_ntoa(&rq->client_sa);
    if ( !group ) {
	if ( s ) {
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "deny_http_access(): No group for address %s - access denied\n", s);
	    xfree(s);
	}
	return(ACCESS_DOMAIN);
    }
    if ( s ) my_xlog(OOPS_LOG_DBG, "deny_http_access(): Connect from %s - group [%s] allowed.\n",
		s, group->name);
    if ( !group->http || !group->http->allow ) {
	if (s) {
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "deny_http_access(): No http or http->allow for address %s - access denied\n", s);
	    xfree(s);
	}
	return(ACCESS_DOMAIN);
    }
    if ( s ) xfree(s);

    /* first, check it in the dstdomain cache */
    if ( group->dstdomain_cache ) {
	res = hash_get(group->dstdomain_cache, host, &he);
        if ( (res == 0) && (he != NULL) ) {
            dst_he_data = he->data;
	    if ( dst_he_data ) dstdomain_cache_result = dst_he_data->access;
            hash_unref(group->dstdomain_cache, he);
        }
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
	new = xmalloc(sizeof(*new), "deny_http_access(): dstdhe");
	if ( new ) {
	    new->access = dstdomain_cache_result;
	    new->when_created = global_sec_timer;
            res = hash_put(group->dstdomain_cache, host, new, &he);
            if ( res == 0 )
                hash_unref(group->dstdomain_cache,he);
              else {
                free(new);
            }
	}
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

inline
static int
port_deny(struct group *group, struct request *rq)
{
struct range	*range;

    if ( !group->badports ) return(0);
    if ( rq->url.proto && !strcasecmp(rq->url.proto,"ftp") ) {
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

inline
static struct domain_list *
find_best_dom(struct domain_list *doml, char* host)
{
struct	domain_list	*best = NULL;
int			hostlen = strlen(host), i;
char			*d, *s;

    if ( hostlen <= 0 ) return(NULL);
/* check if host is ended with a dot, like this: "www.domain.com." */
    if ( host[hostlen - 1] == '.' ) { hostlen--; }
    while(doml) {
	if ( doml->length == -1 ) /* this is "*" */
	    return(doml);
	if ( doml->length <= hostlen ) {
	    i = doml->length;
	    s = &doml->domain[doml->length - 1];
	    d = &host[hostlen - 1];
/* check if host is ended with a dot, like this: "www.domain.com." */
	    if( *d == '.' ) { d--; }
	    while ( i ) {
		if ( *s != tolower(*d) ) break;
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

    localtime_r((time_t*)&global_sec_timer, &tm);
    cm = tm.tm_hour * 60 + tm.tm_min;
    todaybit = 1 << tm.tm_wday;

    while(dt) {

	sm = dt->start_minute;
	em = dt->end_minute;
	dmask = dt->days;


	if ( sm < em ) reverse = FALSE;
	   else	       reverse = TRUE;

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

/* make check for given time t */
int
time_denytime_check(time_t t, struct denytime *dt)
{
int		reverse, sm,em,cm;
struct	tm	tm;
char		todaybit, dmask,yestdbit;

    if ( !dt ) return(0);

    localtime_r(&t, &tm);
    cm = tm.tm_hour * 60 + tm.tm_min;
    todaybit = 1 << tm.tm_wday;

    while(dt) {

	sm = dt->start_minute;
	em = dt->end_minute;
	dmask = dt->days;


	if ( sm < em ) reverse = FALSE;
	   else	       reverse = TRUE;

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
    if ( !strcasecmp(type, "dst_ip") )
	return(ACL_DST_IP);
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
    if ( !strcasecmp(type, "time") )
	return(ACL_TIME);
    if ( !strcasecmp(type, "content_type") )
	return(ACL_CONTENT_TYPE);
    if ( !strcasecmp(type, "username") )
	return(ACL_USERNAME);
    if ( !strcasecmp(type, "header_substr") )
	return(ACL_HEADER_SUBSTR);
    return((char)-1);
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
case ACL_DST_IP:
case ACL_SRC_IP:
	{
	struct	acl_ip_data *acl_ip_data = (struct  acl_ip_data*)acl->data;

	if ( !acl_ip_data ) break;
	if ( acl_ip_data->unsorted ) free_net_list(acl_ip_data->unsorted);
	if ( acl_ip_data->sorted ) free(acl_ip_data->sorted);
	}
	break;
case ACL_USERNAME:
        if ( acl->data ) {
            free_string_list((struct string_list*)acl->data);
            acl->data = NULL;
        }
        break;
case ACL_TIME:
	if ( acl->data ) {
	    free_denytimes(acl->data);
	    acl->data = NULL;
	}
	break;
case ACL_HEADER_SUBSTR:
	if ( acl->data ) {
           header_substr_data_t *hsd = acl->data;
	    IF_FREE(hsd->header);
	    IF_FREE(hsd->substr);
            free(acl->data);
	    acl->data = NULL;
	}
	break;
case ACL_CONTENT_TYPE:
	if ( acl->data ) {
	    acl_ct_data_t	*ctd = (acl_ct_data_t*)acl->data;
	    IF_FREE(ctd->ct);
	}
	break;
default:
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "free_named_acl(): Try to free unknown named acl %s\n", acl->name);
    }
    if ( acl->data ) free(acl->data);
    free(acl);
}

int
parse_named_acl_data(named_acl_t *acl, char *data)
{
int	                regflags = 0;
char	                *p, *t, *tokptr;
struct	range           *ports, *range;
struct  string_list     *logins;
int	                must_free_data = FALSE;
char	                *nl;

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
	    verb_printf("Can't stat file %s: %m\n", fn);
	    return(0);
	}
	new_data_sz = sb.st_size;
	if ( new_data_sz <= 0 ) {
	    printf("Empty file %s?\n", fn);
	    return(0);
	}
	fd = open(fn, O_RDONLY);
	if ( fd < 0 ) {
	    verb_printf("Can't open file %s: %m\n", fn);
	    return(0);
	}
	data = malloc(new_data_sz+1);
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
	*(data+new_data_sz)=0;
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
	if ( (nl = strchr(data, '\n')) ) *nl = 0;
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
case ACL_TIME:
	{
	/* dayset						*/
	/* day[{,|:}day]... time:time				*/
	char		timespec[20], *tb, *tokptr, *t;
	char		dayspec[80];
	unsigned char	res = 0;
	struct denytime	dt, *result;
	int		start_m, end_m;

	if ( (nl = strchr(data, '\n')) ) *nl = 0;
	verb_printf("acl->data: `%s'\n", data);
	bzero(&dt, sizeof(dt));
	/* split on '\t '					*/
	tb = (char*)strtok_r(data, " \t", &tokptr);
	if ( !tb ) {
	    verb_printf("Wrong time acl: %s\n", data);
	    if ( must_free_data ) free(data);
	    return(0);
	}
	strncpy(dayspec, tb, sizeof(dayspec) - 2);
	dayspec[sizeof(dayspec) - 2] = 0;
	verb_printf("dayspec: `%s'\n", dayspec);
	tb = (char*)strtok_r(NULL, " \t", &tokptr);
	if ( !tb ) {
	    verb_printf("Wrong time acl: %s\n", data);
	    if ( must_free_data ) free(data);
	    return(0);
	}
	strncpy(timespec, tb, sizeof(timespec) - 2);
	timespec[sizeof(timespec) - 2] = 0;
	verb_printf("timespec: `%s'\n", timespec);
	if ( sscanf(timespec, "%d:%d", &start_m, &end_m) != 2 ) {
	    verb_printf("Wrong time acl: %s\n", data);
	    if ( must_free_data ) free(data);
	}
	dt.start_minute = 60*(start_m/100) + start_m%100;
	dt.end_minute = 60*(end_m/100) + end_m%100;
	/* now process days					*/
	tb = dayspec;
	while( (t = (char*)strtok_r(tb, ",", &tokptr)) != 0 ) {
	    char 	  fday[4],tday[4];
	    unsigned char d1, d2, i;
	    tb = NULL;
	    if ( sscanf(t,"%3s:%3s", (char*)&fday,(char*)&tday) == 2 ) {
		verb_printf("from: `%s' to `%s'\n", fday,tday);
		d1 = daybit(fday);
		d2 = daybit(tday);
		if ( TEST(d1, 0x80) || TEST(d2, 0x80) ) {
		    verb_printf("Wrong time acl: %s\n", data);
		    if ( must_free_data ) free(data);
		    return(0);
		}
		i = d1;
		d2 <<= 1;
		if ( d2 == d1 ) {
		    /* all days */
		    res |= daybit("all");
		} else {
		    while(i != d2) {
		        res |= i;
		        i <<= 1;
		        if ( i > 64 ) i = 1;
                    }
		}
	    } else {
		verb_printf("day: `%s'\n", t);
		res |= daybit(t);
	    }
	}
	dt.days = res;
	result = malloc(sizeof(*result));
	if ( result ) {
	    memcpy(result, &dt, sizeof(dt));
	    acl->data = result;
	}
	if ( must_free_data )  free(data);
	}
	return(0);
case ACL_PORT:
	verb_printf("acl->data: `%s'\n", data);
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
case ACL_USERNAME:
	verb_printf("acl->data: `%s'\n", data);
	/* split on ',' */
	p = data;
	logins = calloc(1, sizeof(*logins));
	if ( !logins ) {
	    if ( must_free_data ) free(data);
	    return(0);
	}
	while( (t = (char*)strtok_r(p, ", \n", &tokptr)) ) {

	    p = NULL;
	    /*printf("Token: %s\n", t);*/
            add_to_string_list(&logins, t);
	}
	acl->data = logins;
	if ( must_free_data ) free(data);
	return(0);
case ACL_METHOD:
	if ( (nl = strchr(data, '\n')) ) *nl = 0;
	printf("acl->data: `%s'\n", data);
	if ( data ) acl->data = strdup(data);
	if ( must_free_data ) free(data);
	return(0);
case ACL_CONTENT_TYPE:
	if ( (nl = strchr(data, '\n')) ) *nl = 0;
	printf("acl->data: `%s'\n", data);
	if ( data ) {
	    acl_ct_data_t *ctd = malloc(sizeof(*ctd));
	    if ( ctd ) {
		ctd->ct = strdup(data);
		ctd->len = strlen(data);
		acl->data = ctd;
	    }
	    if ( must_free_data ) free(data);
	}
	return(0);
case ACL_USERCHARSET:
	if ( (nl = strchr(data, '\n')) ) *nl = 0;
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
	    ucsd->name[sizeof(ucsd->name)-1] = 0;
	    acl->data = ucsd;
	}
	if ( must_free_data ) free(data);
	return(0);
case ACL_DSTDOM:
	{
	struct	domain_list	*new, *next;
	/* domain domain domain ...			*/
	    acl->data = NULL;
	    verb_printf("acl->data: `%s'\n", data);
	    /* split on ' ' */
	    p = data;
	    while( (t = (char*)strtok_r(p, ", \n", &tokptr)) != 0 ) {

		p = NULL;
		verb_printf("Token: %s\n", t);
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
case ACL_HEADER_SUBSTR:
	{
	/*  Header SP substring \n	*/
            char                        *hdr, *subs = NULL;
            header_substr_data_t        *hsd;
            int                         data_len = strlen(data);

	    acl->data = NULL;
	    verb_printf("acl->data: `%s'\n", data);
	    /* split on ' ' */
            hdr = (char*)strtok_r(data, ", \n", &tokptr);
            if ( hdr ) {
                verb_printf("ACL_HEADER_SUBSTR: header: %s\n", hdr);
                hsd = calloc(1, sizeof(*hsd));
                if ( hsd ) {
                    hsd->header = strdup(hdr);
                    p = hdr + strlen(hdr) + 1;
                    while ( (p < (data + data_len)) && isspace(*p) ) p++;
                    if ( *p ) {
                        verb_printf("ACL_HEADER_SUBSTR: substr: %s\n", p);
                        hsd->substr = strdup(p);
                    }
                    acl->data = hsd;
                }
            } else {
                verb_printf("Can't locate hdr in '%s'\n", data);
            }
	}
	if ( must_free_data ) free(data);
	return(0);
case ACL_DST_IP:
        dst_ip_acl_present = TRUE;
case ACL_SRC_IP:
	/* IP IP IP					*/
	/* IP in format a.b.c.d or a.b.c/l		*/
	{
	  char			*tptr, *t, *p;
	  struct cidr_net	*networks = NULL, *last = NULL;
	  int			networks_num = 0;

	    verb_printf("SRC/DST_IP: %s\n", data);
	    t = data;
	    while ( (p = (char*)strtok_r(t, "\t \n", &tptr)) != 0 ) {
	      char		*slash = NULL, masklen, *tt, *pp, *ttptr;
	      int		net = 0, i = 24;
	      struct		cidr_net *new;
	      struct	sockaddr_in	hostsa;

		t = NULL;
		verb_printf("SRC: %s\n", p);
		if ( (slash = strchr(p, '/')) != 0 ) {
		    masklen = atoi(slash+1);
		    *slash = 0;
		} else {
		    masklen = 32;
		}
		tt = p;
		bzero(&hostsa, sizeof(hostsa));
		if ( !slash && !str_to_sa(p, (struct sockaddr*)&hostsa) ) {
		    net = hostsa.sin_addr.s_addr;
		} else
		while ( (pp = (char*)strtok_r(tt,".", &ttptr)) != 0 ) {
		    tt = NULL;

		    net |= (atol(pp) << i);
		    i -= 8;
		}
		verb_printf("NET: %0x/%d\n", net, masklen);
		new = malloc(sizeof(*new));
		if ( !new ) continue;
		bzero(new, sizeof(*new));
		new->network = net;
		new->masklen = masklen;
		if ( !masklen )
			new->mask = 0;
		    else {
			if ( (signed)masklen < 0 || masklen > 32 ) {
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
	my_xlog(OOPS_LOG_SEVERE|OOPS_LOG_PRINT, "parse_named_acl_data(): Unknown acl type %d in parse_named_acl_data\n", acl->type);
    }
    if ( must_free_data ) free(data);
    return(0);
}

inline
static int
obj_match_named_acl(struct mem_obj *obj, struct request *rq, named_acl_t *acl)
{
    if ( !obj || !acl || !acl->data ) return(FALSE);

    switch(acl->type) {
	case ACL_CONTENT_TYPE:
	    /* compare content type with document content-type */
	    {
		char		*document_type;
		acl_ct_data_t	*acl_ct_data =  (acl_ct_data_t*)acl->data;

		if ( !obj->headers ) return(FALSE);
		document_type = attr_value(obj->headers, "Content-Type");
		if ( document_type && acl_ct_data->ct && acl_ct_data->len ) {
		    if ( !strncasecmp(acl_ct_data->ct, document_type, acl_ct_data->len) )
			return(TRUE);
		}
	    }
	    break;
	default:
	    return (rq_match_named_acl(rq, acl));
	    break;
    }
    return(FALSE);
}

static int
time_match_named_acl(time_t t, named_acl_t *acl)
{
    if ( !acl ) return(FALSE);
    switch(acl->type) {
    case ACL_TIME:
	if ( acl->data && time_denytime_check(t, (struct denytime*)acl->data) )
		return(TRUE);
	return(FALSE);
    default:;
    }
    return(TRUE);
}

static int
rq_match_named_acl(struct request *rq, named_acl_t *acl)
{
int				length = 0;
char				*url;
struct	urlregex_acl_data	*urd;
u_charset_t			*ucsd;
header_substr_data_t            *hsd;

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
	snprintf(url, length, "%s://%s%s", rq->url.proto, rq->url.host, rq->url.path);
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
	    if ( !agent_cs || !agent_cs->Name) return(FALSE);
	    if ( agent_cs == ucsd->cs ) return(TRUE);
	    return( !strcmp(agent_cs->Name, ucsd->name) );
	}
	break;
case ACL_DST_IP:
	{
	struct acl_ip_data *acl_ip_data = (struct acl_ip_data *)acl->data;
	struct  cidr_net   *net;
	int		   i;
	struct	in_addr	   *addr = &(rq->dst_sa.sin_addr);

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

case ACL_USERNAME:
        if ( !acl->data ) return(FALSE);
        {
            struct string_list *logins;
            char               *user = rq->proxy_user;

            if ( !user ) return(FALSE);
            logins = (struct string_list*)acl->data;
            while ( logins != NULL ) {
                if ( logins->string && !strcmp(user, logins->string) ) return(TRUE);
                logins = logins->next;
            }
            return(FALSE);
        }
	break;
case ACL_TIME:
	if ( acl->data && denytime_check((struct denytime*)acl->data) )
		return(TRUE);
	break;

case ACL_HEADER_SUBSTR:
	hsd = (header_substr_data_t*)acl->data;
	if ( !hsd || !hsd->header || !hsd->substr ) return(FALSE);
	{
	    char	*value = attr_value(rq->av_pairs, hsd->header);
            if ( !value ) return(FALSE);
            if ( strstr(value, hsd->substr) ) return(TRUE);
            return(FALSE);
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
struct	urlregex_acl_data	*urd;
struct	url			parsed_url;

    if ( !url || !acl) return(FALSE);

    bzero(&parsed_url, sizeof(parsed_url));
    parse_raw_url(url, &parsed_url);
    if ( !parsed_url.port ) parsed_url.port = 80;

    switch(acl->type) {
case ACL_DSTDOMREGEX:
	if ( !parsed_url.host ) {
	    free_url(&parsed_url);
	    return(FALSE);
	}
	urd = (struct  urlregex_acl_data*)acl->data;
	if (regexec(&urd->preg, parsed_url.host, 0,  NULL, 0)) {
	    free_url(&parsed_url);
	    return(FALSE);
	}
	free_url(&parsed_url);
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
	    if ( best )  {
		free_url(&parsed_url);
		return(TRUE);
	    }
	}
	free_url(&parsed_url);
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
	free_url(&parsed_url);
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
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "free_named_acls(): Release acl %s\n", &curr->name);
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
static named_acl_t*
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

int
obj_check_acl_access(acl_chk_list_hdr_t *acl_access, struct mem_obj *obj, struct request *rq)
{
acl_chk_list_hdr_t *curr = acl_access;

    while(curr) {
	if ( obj_check_acl_list((acl_chk_list_t*)curr, obj, rq) == TRUE ) {
	    return(TRUE);
	}
	curr = curr->next_list;
    }
    return(FALSE);
}

int
time_check_acl_access(acl_chk_list_hdr_t *acl_access, time_t t)
{
acl_chk_list_hdr_t *curr = acl_access;

    while(curr) {
	if ( time_check_acl_list((acl_chk_list_t*)curr, t) == TRUE ) {
	    return(TRUE);
	}
	curr = curr->next_list;
    }
    return(FALSE);
}

/* return TRUE if request pass list	*/
inline
static int
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

/* return TRUE if time pass list	*/
inline
static int
time_check_acl_list(acl_chk_list_t *list, time_t t)
{
int	res;

    while(list) {
	if ( list->acl ) {
	    res = time_match_named_acl(t, list->acl);
	    res ^= list->sign;
	    if ( res == FALSE ) return(FALSE);
	}
	list = list->next;
    }
    return(TRUE);
}

/* return TRUE if object pass list	*/
inline
static int
obj_check_acl_list(acl_chk_list_t *list, struct mem_obj *obj, struct request *rq)
{
int	res;

    while(list) {
	if ( list->acl ) {
	    res = obj_match_named_acl(obj, rq, list->acl);
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

static void
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

    newhdr = xmalloc(sizeof(*newhdr), "parse_acl_access(): 1");
    if ( !newhdr ) return;

    bzero(newhdr, sizeof(*newhdr));
    verb_printf("parse_acl_access(): PARSING ACL: %s\n", string);
    t = string;
    while ( (p = (char*)strtok_r(t, "\t ", &tptr)) != 0 ) {
	t = NULL;

	sign = 0;
	if ( *p == '!' ) {
	    sign = 1;
	    p++;
	}
	acl = acl_by_name(p);
	if ( acl ) {
	    if ( !first ) {
		new = xmalloc(sizeof(*new), "parse_acl_access(): 2");
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
	    verb_printf("parse_acl_access(): Unknown acl `%s'\n", p);
	    goto error;
	}
    }
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
	    verb_printf("parse_networks_acl(): Unknown acl `%s' or bad type (only src_ip/dst_ip allowed).\n", p);
	    goto error;
	}
	string_list = string_list->next;
    }
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

int
use_peer(struct request *rq, struct peer *peer)
{
    if ( !rq || !peer || !peer->peer_access )
	return(FALSE);
    return(check_acl_access(peer->peer_access, rq));
}
