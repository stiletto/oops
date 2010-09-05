/*
Copyright (C) 1999, 2000 Igor Khasilev, igor@paco.net
Copyright (C) 2000 Andrey Igoshin, ai@vsu.ru

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
#include	"modules.h"

char	*days[] = {"Sun", "Mon","Tue","Wed","Thu","Fri","Sat"};
char	*months[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
void	flush_log(void);
int	lookup_dns_cache(char* name, struct dns_cache_item *items, int counter);
int	free_charset(struct charset *charsets);
int	find_bind_acl(struct request *rq);
int	readt(int, char*, int, int);
int	my_gethostbyname(char *name);
char	*my_gethostbyaddr(int);
void	get_hash_stamp(char*, int*, int*);

void
CTIME_R(time_t *a, char *b, size_t l)
{
#if	defined(HAVE_CTIME_R)
#if	defined(SOLARIS)
	ctime_r(a, b, l);
#else
	ctime_r(a, b);
#endif /* SOLARIS */
#else
	struct	tm	tm;
	localtime_r(a, &tm);
#if	defined(HAVE_SNPRINTF)
	snprintf(b, l, "%s, %02d %s %d %02d:%02d:%02d\n",
		 days[tm.tm_wday], tm.tm_mday,
		 months[tm.tm_mon], tm.tm_year+1900,
		 tm.tm_hour, tm.tm_min, tm.tm_sec);
#else
	if ( l >=25 )
	    sprintf(b, "%s, %02d %s %d %02d:%02d:%02d\n",
		 days[tm.tm_wday], tm.tm_mday,
		 months[tm.tm_mon], tm.tm_year+1900,
		 tm.tm_hour, tm.tm_min, tm.tm_sec);
	else
	    printf("%d\n", *a);
#endif
#endif /* HAVE_CTIME_R */
}

void
verb_printf(char *form, ...)
{
va_list		ap;
char		fbuf[256], *s = fbuf, *pe;
int		l, le;
int		err = ERRNO;
ERRBUF ;

    if ( !verbose_startup ) return;

    strncpy(fbuf, form, sizeof(fbuf)-1);
    while((s = strstr(s, "%m")) != NULL) {
	pe = STRERROR_R(err, ERRBUFS);
	le = strlen(pe);
	l = strlen(s);
	if ( ((s - fbuf) + le + l) < sizeof(fbuf) ) {
	    memmove(s + le, s + 2, l - 2);
	    memcpy(s, pe, le);
	}
    }

    va_start(ap, form);
    vprintf(fbuf, ap);
    va_end(ap);

    set_errno(err);

    return;
}

void
my_xlog(int lvl, char *form, ...)
{
va_list		ap;
char		ctbuf[80], *c;
time_t		now;
void		*self;
char		fbuf[256], *s = fbuf, *pe;
int		l, le;
int		err = ERRNO;
ERRBUF ;

    if ( !TEST(lvl, verbosity_level) ) return;

    now = global_sec_timer;

    CTIME_R(&now, ctbuf, sizeof(ctbuf)-1);

    c = strchr(ctbuf, '\n');
    if ( c ) *c = ' ';

    strncpy(fbuf, form, sizeof(fbuf)-1);
    while((s = strstr(s, "%m")) != NULL) {
	pe = STRERROR_R(err, ERRBUFS);
	le = strlen(pe);
	l = strlen(s);
	if ( ((s - fbuf) + le + l) < sizeof(fbuf) ) {
	    memmove(s + le, s + 2, l - 2);
	    memcpy(s, pe, le);
	}
    }

    self = (void*)pthread_self();

    va_start(ap, form);

    if ( TEST(lvl, ~ LOG_PRINT) ) {
	    char	*b1;
	    int		b1len;

#if	defined(HAVE_SNPRINTF)
	    b1len = strlen(ctbuf) + 20;
	    b1 = malloc(b1len);
	    if ( b1 ) {
		char	buf[256];

		snprintf(b1, b1len-1, "%s [%p]", ctbuf, self);
		vsnprintf(buf, sizeof(buf)-1, fbuf, ap);
		put_str_in_filebuff(b1, &logbuff);
		put_str_in_filebuff(buf, &logbuff);
		free(b1);
	    }
#else
		/* we can do nothing, just fprintf to file	*/
		pthread_mutex_lock(&logbuff.lock);
		if ( logbuff.File ) {
		    fprintf(logbuff.File, "%s [%p]", ctbuf, self);
		    vfprintf(logbuff.File, fbuf, ap);
		}
		pthread_mutex_unlock(&logbuff.lock);
#endif
    }

    if ( TEST(lvl, LOG_PRINT) )
	vprintf(fbuf, ap);

    va_end(ap);

    short_flushout_fb(&logbuff);

    set_errno(err);

    return;
}

void
flush_log(void)
{
    flushout_fb(&logbuff);
}

void
log_access(int elapsed, struct request *rq, struct mem_obj *obj)
{
char			*s = NULL, *urlp = NULL, *sbuf = NULL;
char			*meth, *tag, *content, *hierarchy, *source, ctbuf[40];
struct	url		*url;
struct	sockaddr_in	*sa;
int			code, size, maxlen;
char			*proto, *host, *path, *user;

    if ( !rq ) return;

    check_log_mods(elapsed, rq, obj);

    meth	= rq->method;
    tag		= rq->tag;
    hierarchy	= rq->hierarchy;
    size	= rq->received;
    code	= rq->code;

    if ( obj && obj->headers && (content = attr_value(obj->headers, "Content-Type")) ) {
	char *p;
	strncpy(ctbuf, content, sizeof(ctbuf)-1);
	p = &ctbuf[0];
	ctbuf[sizeof(ctbuf)-1] = 0;
	while (*p) {
	    if ( IS_SPACE(*p) || *p==';' ) {
		*p = 0;
		break;
	    }
	    p++;
	}
	content = ctbuf;
    } else {
	content = "text/html";
    }
    source = rq->source;
    sa = &rq->client_sa;
    url = &rq->url;
    user = rq->proxy_user;

    if ( !meth ) 	meth = "NULL";
    if ( !tag  ) 	tag  = "NULL";
    if ( !hierarchy )   hierarchy = "NULL";
    if ( !content )	content = "NULL";
    if ( !source )	source = "NULL";
    if ( !url )		return;
    if ( !user )	user = "-";

    proto = url->proto;
    host = url->host;
    path = url->path;
    if ( !proto ) proto = "NULL";
    if ( !host ) host = "NULL";
    if ( !path ) path = "/";

    if ( proto && host && path ) {
	maxlen = strlen(proto)+strlen(host)+strlen(path)+5;
	urlp = malloc(maxlen);
    }
    if ( urlp ) sprintf(urlp,"%s://%s%s", proto, host, path);
    s = my_inet_ntoa(sa);
    if ( s ) maxlen += strlen(s);
    sbuf = malloc(maxlen + strlen(meth) + strlen(tag) + strlen(hierarchy)
    			 + strlen(content) + strlen(source)
    			 + strlen(user) + 128);
    if ( sbuf ) {
	sprintf(sbuf, "%u.000 %d %s %s/%d %d %s %-.128s %s %s/%s %s\n", (unsigned)global_sec_timer, elapsed, s,
	tag, code, size, meth, urlp, user,
	hierarchy, source,
	content);
	put_str_in_filebuff(sbuf, &accesslogbuff);
	xfree(sbuf);
    }
    if ( s )	xfree(s);
    if ( urlp ) xfree(urlp);
    short_flushout_fb(&accesslogbuff);
}


void
do_exit(int code)
{
   flush_log();
   exit(code);
}

char*
sa_to_str(struct sockaddr_in *sa)
{
    if ( ns_configured > 0 ) {
	return(NULL);
    } else {
#if	defined(HAVE_GETHOSTBYNAME_R)
#endif
	return(NULL);
    }
}

int
str_to_sa(char *val, struct sockaddr *sa)
{
	if ( (((struct sockaddr_in*)sa)->sin_addr.s_addr = inet_addr(val)) != -1 ) {
		/* it is */
		struct	sockaddr_in *sin = (struct sockaddr_in*)sa;
		sin->sin_family = AF_INET;
#if	!defined(SOLARIS) && !defined(LINUX) && !defined(OSF) && !defined(_WIN32)
		sin->sin_len	= sizeof(*sin);
#endif
		return(0);
	} else {
	    int		ad;
		/* try to resolve name */
		if ( ns_configured > 0 )
			ad = my_gethostbyname(val);
		    else {
#if	defined(HAVE_GETHOSTBYNAME_R)
			struct hostent	*he;
			struct hostent	he_b;
#if     defined(LINUX)
        		struct hostent	*he_x;
#elif   defined(_AIX)
			struct hostent_data     he_d;
#endif /* _AIX */
			char		he_strb[2048];
			int		he_errno;
#if	!defined(SOLARIS)
			int		rc = 0;
#endif

#if	defined(LINUX)
			rc = gethostbyname_r(val, &he_b, he_strb, sizeof(he_strb),
				&he_x,
				&he_errno);
			if ( !rc ) he = &he_b;
			    else   he = NULL;
#elif  defined(_AIX)
			rc = gethostbyname_r(val, &he_b, &he_d);
			if ( !rc ) he = &he_b;
			    else   he = NULL;
#else
			he = gethostbyname_r(val, &he_b, he_strb, sizeof(he_strb), &he_errno);
#endif
			if ( !he ) {
			    my_xlog(LOG_DNS|LOG_DBG, "str_to_sa(): %s is not a hostname, not an IP addr\n", val);
			    return(1);
			}
			ad = (*(struct in_addr*)*he->h_addr_list).s_addr;
#else
			fprintf(stderr, "ERROR: You have to define nameservers in your\n");
			fprintf(stderr, "       config file, as your OS don\'t have MT-safe\n");
			fprintf(stderr, "       version of gethostbyname()\n");
			fprintf(stderr, "       Now exiting.\n");
			exit(1);
#endif
		}
		if ( !ad ) {
			my_xlog(LOG_DNS|LOG_DBG, "str_to_sa(): %s is not a hostname, not an IP addr\n", val);
			return(1);
		}
		((struct sockaddr_in*)sa)->sin_addr.s_addr = ad;
		((struct sockaddr_in*)sa)->sin_family = AF_INET;
#if	!defined(SOLARIS) && !defined(LINUX) && !defined(OSF) && !defined(_WIN32)
		((struct sockaddr_in*)sa)->sin_len = sizeof(struct sockaddr_in);
#endif
	}
	return(0);
}

int
bind_server_so(int server_so, struct request *rq)
{
int	r;
int	ba_addr;

    if ( rq && ( ba_addr = find_bind_acl(rq) ) ) {
	struct	sockaddr_in	sa;
	sa.sin_addr.s_addr = ba_addr;
	sa.sin_family = AF_INET;
#if     !defined(SOLARIS) && !defined(LINUX) && !defined(OSF) && !defined(_WIN32)
	sa.sin_len = sizeof(sa);
#endif
	r = bind(server_so, (struct sockaddr*)&sa, sizeof(sa));
	if ( r ) {
	    my_xlog(LOG_SEVERE, "bind_server_so(): Can't bind to bind_acl result: %m\n");
	} else
	    return(r);
    }
    if ( !connect_from_sa_p )
	return(0);
    r = bind(server_so, (struct sockaddr*)connect_from_sa_p, sizeof(struct sockaddr_in));
    if ( r ) {
	my_xlog(LOG_SEVERE, "bind_server_so(): Can't bind: %m\n");
    }
    return(r);
}

void
init_domain_name(void)
{
char	*t = NULL, tmpname[MAXHOSTNAMELEN+1];
int	ip_addr;

    tmpname[0] = 0;
    domain_name[0] = 0;
    gethostname(tmpname, sizeof(tmpname));
    strncpy(host_name, tmpname, sizeof(host_name)-1);
    if ( (t = strchr(host_name, '.')) != 0 ) {
	strncpy(domain_name, t, sizeof(domain_name)-1);
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "init_domain_name(): 1: host_name = `%s' domain_name = `%s'\n",
		host_name, domain_name);
	return;
    }
    if ( bind_addr ) {
	int ip_addr;
	if ( (ip_addr = inet_addr(bind_addr)) == -1 ) {
	    if ( (t = strchr(bind_addr, '.')) != 0 ) {
		strncpy(domain_name, t, sizeof(domain_name)-1);
		if ( host_name[0] != 0 && !strchr(host_name, '.') )
		    strncat(host_name, domain_name, sizeof(host_name) - strlen(host_name)-1);
		else
		    strncpy(host_name, bind_addr, sizeof(host_name)-1);
		my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "init_domain_name(): 2: host_name = `%s' domain_name = `%s'\n",
			host_name, domain_name);
		return;
	    }
	}
    }
    if ( connect_from[0] != 0 ) {
	if ( (ip_addr = inet_addr(connect_from)) == -1 ) {
	    if ( (t = strchr(connect_from, '.')) != 0 ) {
		strncpy(domain_name, t, sizeof(domain_name)-1);
		if ( host_name[0] != 0 && !strchr(host_name, '.') )
		    strncat(host_name, domain_name, sizeof(host_name) - strlen(host_name)-1);
		else
		    strncpy(host_name, connect_from, sizeof(host_name)-1);
		my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "init_domain_name(): 3: host_name = `%s' domain_name = `%s'\n",
			host_name, domain_name);
		return;
	    }
	}
    }
#if	defined(HAVE_GETDOMAINNAME)
    if ( !getdomainname(&tmpname[0], sizeof(tmpname)) ) {
	strcpy(domain_name, ".");
	strncat(domain_name, tmpname, sizeof(domain_name)-2);
    }
#endif
    if ( !domain_name[0] && host_name[0] ) {
	if ( (t = strchr(host_name, '.')) != 0 )
		strncpy(domain_name, t, sizeof(domain_name)-1);
    }
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "init_domain_name(): 4: host_name = `%s' domain_name = `%s'\n",
	    host_name, domain_name);
}

static u_short	q_id = 0;
char*
my_gethostbyaddr(int addr)
{
struct	dnsqh {
#if	defined(__IBMC__) && defined(_AIX)
	u_int           id:16;
	u_int           flags:16;
	u_int           qdcount:16;
	u_int           ancount:16;
	u_int           nscount:16;
	u_int           arcount:16;
#else
	u_short		id:16;
	u_short		flags:16;
	u_short		qdcount:16;
	u_short		ancount:16;
	u_short		nscount:16;
	u_short		arcount:16;
#endif
} *qh, *ah;
u_char		dnsq[512];
u_char		dnsa[512];
    
    ah = qh = NULL;
    bzero(dnsq, sizeof(dnsq));
    bzero(dnsa, sizeof(dnsa));
    return(NULL);
}

int
my_gethostbyname(char *name)
{
struct	dnsqh {
#if	defined(__IBMC__) && defined(_AIX)
	u_int           id:16;
	u_int           flags:16;
	u_int           qdcount:16;
	u_int           ancount:16;
	u_int           nscount:16;
	u_int           arcount:16;
#else
	u_short		id:16;
	u_short		flags:16;
	u_short		qdcount:16;
	u_short		ancount:16;
	u_short		nscount:16;
	u_short		arcount:16;
#endif
} *qh, *ah;
u_char		dnsq[512];
u_char		dnsa[512];
int		dns_so, rq_len, r, resend_cnt, resend_tmo, gota=0;
u_short		*qdcount = (u_short*)dnsq + 2, acount;
u_char		*q_section = dnsq + 12;
struct		sockaddr_in	dns_sa;
u_char		*p, *s, *d, *t, *limit;
u_short		type, class, ttl, rdl, flags;
unsigned	result = 0, results = 0;
unsigned	answers[MAX_DNS_ANSWERS], *current=answers;
struct in_addr	addr;
u_char		tmpname[MAXHOSTNAMELEN+1];

    s = (u_char*)name;d = &tmpname[0];
    while ( *s && ((d-&tmpname[0])<MAXHOSTNAMELEN)) {
	*d = tolower(*s);
	s++;d++;
    }
    *d = 0;
    if ( (d - tmpname) <= 0 )
	return(result);
    d--;
    /* remove last '.' if need */
    if ( *d == '.' )
	*d = 0;
    if ( (result = lookup_dns_cache((char*)tmpname, NULL, 0)) != 0 )
	return(result);
    bzero(answers, sizeof(answers));

    /* check if this is full name */
    if ( !strchr(name, '.') ) {
	if ( domain_name[0] ) /* join */ {
	    strcpy((char*)tmpname, name);
	    strncat((char*)tmpname, domain_name, sizeof(tmpname)-strlen((char*)tmpname) -1 );
	    name=(char*)tmpname;
	}
	if ( (result = lookup_dns_cache((char*)tmpname, NULL, 0)) != 0 )
	    return(result);
    }


    dns_so = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( dns_so == -1 ) {
	my_xlog(LOG_DNS|LOG_SEVERE, "my_gethostbyname(): Can't create DNS socket: %m\n");
	return(0);
    }
    bzero(&dns_sa, sizeof(dns_sa));
    dns_sa.sin_family = AF_INET;
#if	!defined(SOLARIS) && !defined(LINUX) && !defined(OSF) && !defined(_WIN32)
    dns_sa.sin_len = sizeof(dns_sa);
#endif
    rwl_rdlock(&config_lock);
    dns_sa.sin_addr.s_addr = ns_sa[0].sin_addr.s_addr;
    rwl_unlock(&config_lock);
    dns_sa.sin_port	   = htons(53);
    bzero(dnsq, sizeof(dnsq));

    qh = (struct dnsqh *) dnsq;
    qh->id = htons(++q_id);
    qh->flags = htons(0x0100);
    *qdcount = htons(1);
    d = q_section;
    s = (u_char*)tmpname;
    while( (p = (u_char*)strchr((char*)s, '.')) != 0 ) {
	*p = 0;
	*d++ = (u_char)strlen((char*)s);
	t = s; while(*t) *d++=*t++;
	s=++t;
	*p = '.';
    }
    /* last component */
    *d++ = strlen((char*)s);
    t = s; while(*t) *d++=*t++;
    *d++ = 0;
    *d++=0;*d++ = 1;
    *d++=0;*d++ = 1;
    rq_len = d - dnsq;
    resend_cnt = 10;
    resend_tmo = 1;

resend:
    r = sendto(dns_so, (char*)dnsq, rq_len, 0, (struct sockaddr*)&dns_sa, sizeof(dns_sa));
    if ( r == -1 ) {
	my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): Can't send to DNS server: %m\n");
	CLOSE(dns_so);
	return(0);
    } else
	my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): DNS rq sent.\n");
    if ( (ns_configured > 1) && (wait_for_read(dns_so, 500) == FALSE) ) {
	int i;
	/* if we have another nameservers, which we can try to send rq */
	for (i=1;i<ns_configured;i++) {
	    r = sendto(dns_so, (char*)dnsq, rq_len, 0, (struct sockaddr*)&ns_sa[i], sizeof(struct sockaddr_in));
	    if ( r == -1 ) {
		my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): Can't send to DNS server: %m\n");
	    } else
		my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): DNS rq sent.\n");
	}
    }
    /* wait for response */
    r = readt(dns_so, (char*)dnsa, sizeof(dnsa), resend_tmo);
    resend_tmo <<= 1;
    if ( resend_tmo > 30 ) resend_tmo = 30;
    switch(r) {
    case(-2): /* timeout */
	my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): Timeout reading DNS answer: %m\n");
	if (--resend_cnt) goto resend;
	break;
    case(-1): /* error 		*/
	my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): Error reading DNS answer: %m\n");
	break;
    case (0): /* ????? 		*/
	my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): Emty DNS answer\n");
	break;
    default:  /* parse data 	*/
	my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): got %d bytes answer\n", r);
	ah = (struct dnsqh *)dnsa;
	flags = ntohs(ah->flags);
	acount = ntohs(ah->ancount);
	acount = MIN(acount, MAX_DNS_ANSWERS);
	limit = (u_char*)&dnsa + r;
	if ( (flags & 0x8000) && (ah->id == qh->id) && (!(flags&0xf)) ) {
	    if ( !ntohs(ah->ancount) ) {
		my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): got 0 answers.\n");
		break;
	    }
	} else {
	    my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): Failed DNS answer: qid(%x)<->aid(%x), flags:%x\n", qh->id,
	    				ah->id, flags);
	    break;
	}
	if ( ntohs(ah->qdcount) )
		s = dnsa + rq_len;
	    else
		s = (u_char*)( (struct dnsqh*)dnsa + 1 );
	/* find the end of the name */
find_IN_A:
	if ( *s & 0xc0 ) /* compressed */ {
	    s += 2;
	} else { /* search end of name */
	    while ( *s ) s++; s++;
	}
	type = (*s)  << 8; type += *(s+1); s+=2;
	class = (*s) << 8; class += *(s+1); s+=2;
	ttl = (*s) << 24; ttl += *(s+1) << 16; ttl+= *(s+2) << 8; ttl+=*(s+3);
		s+=4;
	rdl = (*s)   << 8; rdl += *(s+1); s+=2;
	if ( type != 1 || class != 1 ) /* not IN A RR */ {
	    if ( s - dnsa + rdl < sizeof(dnsa) ) {
		s += rdl;
		gota++; if ( gota > acount ) break;
		goto find_IN_A;
	    }
	    break;
	}
	result = (*s) << 24; result |= *(s+1) << 16;
	result|= *(s+2) << 8; result|=*(s+3);
	gota++;
	if ( gota > acount ) break;
	*current = ntohl(result);
	addr.s_addr = *current;
	current++;
	results++;
	s += rdl;
	if ( s >= limit )
	    break;
	goto find_IN_A;
    }
    if ( results >= 1 ) {
	struct dns_cache_item	*dns_items, *ci;
	char			*dns_name;
	unsigned int			i;

	dns_items = xmalloc(sizeof(*dns_items)*results,"my_gethostbyname(): dns_items");
	dns_name  = xmalloc(strlen(name)+1, "my_gethostbyname(): dns_name");
	if ( !dns_items || !dns_name )
	    goto dns_c_failed;
	my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): Put %d answers in dns_cache\n", results);
	strcpy(dns_name, (char*)&tmpname[0]);
	ci = dns_items; current = answers;
	for(i=0;i<results;i++,current++,ci++) {
	    ci->time = global_sec_timer;
	    ci->good = TRUE;
	    ci->address.s_addr = *current;
	}
	if ( lookup_dns_cache(dns_name, dns_items, results) ) goto dns_c_failed;

	my_xlog(LOG_DNS|LOG_DBG, "my_gethostbyname(): Done...\n");
	goto fin;

    dns_c_failed:
	if ( dns_items ) xfree(dns_items);
	if ( dns_name ) xfree(dns_name);
	goto fin;
    }

  fin:
    CLOSE(dns_so);
    addr.s_addr = answers[0];
    return(answers[0]);
}

int
lookup_dns_cache(char* name, struct dns_cache_item *items, int counter)
{
int			result = 0;
int			hash, stamp;
struct	dns_cache	*cp;
struct	dns_cache_item	*ci;
unsigned		use;

    if ( !name ) return(0);
    get_hash_stamp(name, &hash, &stamp);
    pthread_mutex_lock(&dns_cache_lock);
    cp = dns_hash[hash].first;
    while ( cp ) {
	if ( (cp->stamp == stamp) && !strcmp(name,cp->name) ) {
	    my_xlog(LOG_DNS|LOG_DBG, "lookup_dns_cache(): It's here\n");
	    break;
	}
	cp = cp->next;
    }
    if ( cp ) {
	if ( !cp->ngood && (!counter || !items ) ) {
	    pthread_mutex_unlock(&dns_cache_lock);
	    return(result);
	}
	ci = cp->items;

    find_good:
	use = cp->nlast;
	if ( (signed)use >= cp->nitems ) use = cp->nlast = 0;
	cp->nlast++;
	if ( !(ci+use)->good )
	    goto find_good;
	result = (ci+use)->address.s_addr;
	pthread_mutex_unlock(&dns_cache_lock);
	return(result);
    }
    /* not found */
    if ( !items || !counter ) {
	pthread_mutex_unlock(&dns_cache_lock);
	return(result);
    }
    /* insert	*/
    cp = xmalloc(sizeof(*cp), "lookup_dns_cache(): dns_cache");
    if ( cp ) {
	cp->next = NULL;
	cp->time = global_sec_timer;
	cp->stamp = stamp;
	cp->name = name;
	cp->nitems = cp->ngood = counter;
	cp->nlast = 0;
	cp->items = items;
	if ( !dns_hash[hash].last ) {
	    dns_hash[hash].last = dns_hash[hash].first = cp;
	} else {
	    dns_hash[hash].last->next = cp;
	    dns_hash[hash].last = cp;
	}
    } else {
	result = TRUE;
    }
    pthread_mutex_unlock(&dns_cache_lock);
    return(result);
}

void
free_dns_hash_entry(struct dns_cache* cp)
{
    if ( cp->name ) xfree(cp->name);
    if ( cp->items) xfree(cp->items);
    xfree(cp);
}

void
get_hash_stamp(char *name, int *hash, int *stamp)
{
char		*c = name;
unsigned	prod;

    *hash = *stamp = 0;
    while ( *c ) {
	prod = (unsigned)(*c)*(unsigned)(*c);
	*hash  = (*hash<<1) + prod;
	*stamp = *stamp + prod;
	c++;
    }
    *hash &= DNS_HASH_MASK;
}

int
http_date(char *date, time_t *time)
{
#define	TYPE_RFC	0
#define	TYPE_ASC	1
#define	FIELD_WDAY	1
#define	FIELD_MDAY	2
#define	FIELD_MONT	3
#define	FIELD_YEAR	4
#define	FIELD_TIME	5

char		*p, *s;
char		*ptr;
int		type = TYPE_RFC, field=FIELD_WDAY, t;
int		wday = -1, mday = -1, month = -1, secs = -1, mins = -1, hour = -1;
int		year = -1;
char		*xdate;
struct	tm	tm;

    xdate = xmalloc(strlen(date) +1, "http_date(): http_date");
    if ( !xdate )
	return(-1);
    strcpy(xdate, date);
    p = date = xdate;
    while( (s = (char*)strtok_r(p, " ", &ptr)) != 0 ) {
	p = NULL;
    parse:
	switch(field) {
	case FIELD_WDAY:
		if ( strlen(s) < 3 ) {
		    my_xlog(LOG_DBG|LOG_INFORM, "http_date(): Unparsable date: %s\n", date);
		    free(xdate);
		    return(-1);
		}
		/* Sun, Mon, Tue, Wed, Thu, Fri, Sat */
		switch ( tolower(s[2]) ) {
		case 'n': /* Sun or Mon */
			if ( tolower(s[0]) == 's' ) wday = 0;
			    else		    wday = 1;
			break;
		case 'e': /* Tue	*/
			wday = 2;
			break;
		case 'd': /* Wed	*/
			wday = 3;
			break;
		case 'u': /*Thu		*/
			wday = 4;
			break;
		case 'i': /* Fri	*/
			wday = 5;
			break;
		case 't': /* Sat	*/
			wday = 6;
			break;
		default:
			my_xlog(LOG_DBG|LOG_INFORM, "http_date(): Unparsable date: %s\n", date);
			free(xdate);
			return(-1);
		}
		if ( !strchr(s,',') ) type = TYPE_ASC;
		if ( type == TYPE_RFC )
			field = FIELD_MDAY;
		    else
			field = FIELD_MONT;
		break;
	case FIELD_MDAY:
		if ( type == TYPE_RFC ) {
		    t = 0;
		    while( *s && IS_DIGIT(*s) ) {
			t = t*10 + (*s - '0');
			s++;
		    }
		    if ( t ) mday = t;
			else {
			     my_xlog(LOG_DBG|LOG_INFORM, "http_date(): Unparsable date: %s\n", date);
			     free(xdate);
			     return(-1);
		    }
		    field = FIELD_MONT;
		    if ( *s && (*s == '-') ) {
			/* this is dd-mmm-yy format */
			s++;
			goto parse;
		    }
		    if ( *s ) {
			free(xdate);
			return(-1);
		    }
		    break;
		} else {
		    t = 0;
		    while( *s && IS_DIGIT(*s) ) {
			t = t*10 + (*s - '0');
			s++;
		    }
		    if ( *s ) {
			free(xdate);
			return(-1);
		    }
		    if ( t ) mday = t;
			else {
			     my_xlog(LOG_DBG|LOG_INFORM, "http_date(): Unparsable date: %s\n", date);
			     free(xdate);
			     return(-1);
		    }
		    field = FIELD_TIME;
		}
		break;
	case FIELD_MONT:
		/* Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec */
		if ( strlen(s) < 3 ) {
		    my_xlog(LOG_DBG|LOG_INFORM, "http_date(): Unparsable date: %s\n", date);
		    free(xdate);
		    return(-1);
		}
		switch ( tolower(s[2]) ) {
		    case 'n':
			if ( s[1] == 'a' ) month = 0;
			if ( s[1] == 'u' ) month = 5;
			break;
		    case 'b':
			month = 1;
			break;
		    case 'r':
			if ( s[1] == 'a' ) month = 2;
			if ( s[1] == 'p' ) month = 3;
			break;
		    case 'y':
			month = 4;
			break;
		    case 'l':
			month = 6;
			break;
		    case 'g':
			month = 7;
			break;
		    case 'p':
			month = 8;
			break;
		    case 't':
			month = 9;
			break;
		    case 'v':
			month = 10;
			break;
		    case 'c':
			month = 11;
			break;
		    default:
			my_xlog(LOG_DBG|LOG_INFORM, "http_date(): Unparsable date: %s\n", date);
			free(xdate);
			return(-1);
		}
		s+=3;
		if ( type == TYPE_ASC ) field = FIELD_MDAY;
		    else 		field = FIELD_YEAR;
		if ( *s && (*s=='-') ) {
		    /* this is dd-mmm-yy format */
		    s++;
		    goto parse;
		}
		break;
	case FIELD_YEAR:
		if ( type==TYPE_ASC && !IS_DIGIT(*s) ) /* here can be zonename */
		    break;
		year = atoi(s);
		if ( year == 0 ) {
		     my_xlog(LOG_DBG|LOG_INFORM, "http_date(): Unparsable date: %s\n", date);
		     free(xdate);
		     return(-1);
		}
		if ( strlen(s) <=2 )
		    year += 1900;
		if ( type == TYPE_RFC ) field = FIELD_TIME;
		     else		goto compose;
		break;
	case FIELD_TIME:
		hour = mins = secs = 0;
		while (*s && IS_DIGIT(*s) ) hour = hour*10 + ((*s++)-'0');
		if ( *s ) s++;
		while (*s && IS_DIGIT(*s) ) mins = mins*10 + ((*s++)-'0');
		if ( *s ) s++;
		while (*s && IS_DIGIT(*s) ) secs = secs*10 + ((*s++)-'0');
		if ( type == TYPE_ASC ) {
			field = FIELD_YEAR;
			break;
		}
		goto compose;
		break;
	}
    }

compose:
    bzero(&tm, sizeof(tm));
    tm.tm_sec = secs;
    tm.tm_min = mins;
    tm.tm_hour= hour;
    tm.tm_wday= wday;
    tm.tm_mday= mday;
    tm.tm_mon = month;
    tm.tm_year= year - 1900;
    free(xdate);
    tm_to_time(&tm, time);
    return(0);
}

int
tm_cmp(struct tm *tm1, struct tm *tm2)
{
    if (tm1->tm_year  < tm2->tm_year ) return(-1);
    if (tm1->tm_mon < tm2->tm_mon ) return(-1);
    if (tm1->tm_mday < tm2->tm_mday ) return(-1);
    if (tm1->tm_hour < tm2->tm_hour ) return(-1);
    if (tm1->tm_min < tm2->tm_min ) return(-1);
    if (tm1->tm_sec < tm2->tm_sec ) return(-1);
    return(1);
}

int
mk1123time(time_t time, char *buf, int size)
{
struct	tm	tm;
time_t		holder = time;
char		tbuf[80];

    gmtime_r(&holder, &tm);
    sprintf(tbuf, "%s, %02d %s %d %02d:%02d:%02d GMT",
    		days[tm.tm_wday], tm.tm_mday,
    		months[tm.tm_mon], tm.tm_year+1900,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
    strncpy(buf, tbuf, size);
    return(TRUE);
}

/* accept tm for GMT, return time */
int
tm_to_time(struct tm *tm, time_t *time)
{
struct		tm ttm;
time_t		res, dst;

    /* mktime convert from localtime, so shift tm to localtime	*/
    memcpy(&ttm, tm, sizeof(ttm));
    ttm.tm_isdst = -1;
    pthread_mutex_lock(&mktime_lock);
    res = mktime(&ttm);
    pthread_mutex_unlock(&mktime_lock);
    dst = 0;
    if ( ttm.tm_isdst > 0)
            dst = -3600;
#if	defined(SOLARIS) || defined(_AIX)
    res -= timezone + dst;
#elif	defined(_WIN32)
    res -= _timezone + dst;
#elif	defined(FREEBSD) || (defined(LINUX) && !defined(HAVE__GMTOFF__) )
    res += ttm.tm_gmtoff;
#elif	defined(HAVE__GMTOFF__)
    res += ttm.__tm_gmtoff__ - dst;
#else
    res += ttm.tm_gmtoff - dst;
#endif
    return(*time = res);
}

char*
html_escaping(char *src)
{
int	olen = strlen(src);
char	*p = src, *d, *res;
int	specials = 0;

    if ( !src ) return(NULL);
    while( p && *p ) {
    	if ( *p == '<' || *p == '>' || *p == '\"' || *p == '&' )
	    specials++;
	p++;
    }
    res = malloc(strlen(src) + 1 + specials*5 ); /* worst case */
    if ( !res ) return(NULL);

    if ( specials == 0 ) {
	memcpy(res, src, olen+1);
	return(res);
    }    
    p = src;
    d = res;
    while ( *p ) {
	if ( *p == '<' ) {
	    strcpy(d,"&lt;");d+=3;
	} else
	if ( *p == '>' ) {
	    strcpy(d,"&gt;");d+=3;
	} else
	if ( *p == '\"' ) {
	    strcpy(d,"&quot;"); d+=5;
	} else
	if ( *p == '&' ) {
	    strcpy(d,"&amp;"); d+=4;
	} else
	    *d = *p;
	p++;d++;
    }
    *d = 0;
    return(res);
}

char*
htmlize(char *src)
{
char	*res;
u_char	*s = (u_char*)src, *d;
u_char	xdig[16] = "0123456789ABCDEF";

    res = malloc(strlen(src) * 3 + 1 ); /* worst case */
    if ( !res ) return(NULL);
    d = (u_char*)res;
    while( *s ) {
	if ( *s!='/' &&
	     *s!='.' &&
	     *s!='-' &&
	     *s!='_' &&
	     *s!='~' &&
		((*s >= 0x80) || (*s <= 0x20) || !isalnum(*s) ) ) {
	    *d++ = '%';
	    *d++ = xdig[ (*s) / 16 ];
	    *d   = xdig[ (*s) % 16 ];
	} else
	    *d = *s;
	d++; s++;
    }
    *d=0;
    return(res);
}

#define	HEXTOI(arg)	(((arg)<='9')? ((arg)-'0'):(tolower(arg)-'a' + 10))
char*
dehtmlize(char *src)
{
char	*res;
u_char	*s = (u_char*)src, *d;

    res = xmalloc(strlen(src) + 1, "dehtmlize(): dehtmlize"); /* worst case */
    if ( !res ) return(NULL);
    d = (u_char*)res;
    while( *s ) {
	if ( (*s=='%') && isxdigit(*(s+1)) && isxdigit(*(s+2)) ) {
	    *d = (HEXTOI(*(s+1)) << 4) | (HEXTOI(*(s+2)));
	    s+=2;
	} else
	    *d = *s;
	d++; s++;
    }
    *d=0;
    return(res);
}

#if	!defined(_WIN32)
#if	!defined(HAVE_DAEMON)
int
daemon(int nochdir, int noclose)
{
pid_t	child;

    /* this is not complete */
    child = fork();
    if ( child < 0 ) {
	fprintf(stderr, "daemon(): Can't fork.\n");
	return(1);
    }
    if ( child > 0 ) {
	/* parent */
	exit(0);
    }
    if ( !nochdir ) {
	chdir("/");
    }
    if ( !noclose ) {
	fclose(stdout);
	fclose(stderr);
    }
    return(0);
}
#endif	/* !HAVE_DAEMON */
#else
int
daemon(int nochdir, int noclose)
{
    return(0);
}
#endif	/* !_WIN32 */

#if	defined(WITH_LARGE_FILES) && !defined(HAVE_ATOLL) && !defined(HAVE_STRTOLL)
long long
atoll(const char *s)
{
    long long	res = 0;

    if ( sscanf(s, "%lld", &res) != 1 )
	res = (long long)0;

    return res;
}
#endif	/* !HAVE_ATOLL && !HAVE_STRTOLL */

#if    !defined(HAVE_BZERO)
void
bzero(void *p, size_t len)
{
    char       *c = p;
    size_t     n;

    if (len == 0) return;
    for (n = 0; n < len; n++) c[n] = 0;
}
#endif	/* !HAVE_BZERO */

#if	!defined(HAVE_STRERROR_R) && !defined(_WIN32)
int
strerror_r(int err, char *errbuf, size_t lerrbuf)
{
    if (err < 0 || err >= sys_nerr) {
#if	defined(HAVE_SNPRINTF)
	snprintf(errbuf, lerrbuf, "Unknown error: (%d)", err);
#else
	char	b[80];
	sprintf(b, "Unknown error: (%d)", err);
	if ( lerrbuf > 0 ) strncpy(errbuf, b, lerrbuf-1);
#endif  /* HAVE_SNPRINTF */
	return(-1);
    }
    else
	strncpy(errbuf, strerror(err), lerrbuf);

    return(0);
}
#endif	/* !HAVE_STRERROR_R && !_WIN32 */

char *
STRERROR_R(int err, char *errbuf, size_t lerrbuf)
{
#if	defined(LINUX)
    return(strerror_r(err, errbuf, lerrbuf));
#else
    if ( strerror_r(err, errbuf, lerrbuf) == -1 )
	my_xlog(LOG_DBG, "STRERROR_R(): strerror_r() returned (-1), errno = %d\n", err);
    return(errbuf);
#endif
}

void
increase_hash_size(struct obj_hash_entry* hash, int size)
{
int	rc; 
    if ( !hash ) {
	my_xlog(LOG_SEVERE, "increase_hash_size(): hash == NULL in increase_hash_size\n");
	return;
    }
    if ( size < 0 ) {
	my_xlog(LOG_SEVERE, "increase_hash_size(): size<=0 in increase_hash_size\n");
	do_exit(1);
	return;
    }
    if ( !(rc = pthread_mutex_lock(&hash->size_lock)) ) {
	hash->size += size;
	if ( hash->size < 0 ) {
    	    my_xlog(LOG_SEVERE, "increase_hash_size(): increase: hash_size has negative value: %d!\n", hash->size);
	    do_exit(1);
	}
	pthread_mutex_unlock(&hash->size_lock);
    } else {
	my_xlog(LOG_SEVERE, "increase_hash_size(): Can't lock hash entry for increase size\n");
    }
}

void
decrease_hash_size(struct obj_hash_entry* hash, int size)
{
int	rc;

    if ( !hash ) {
	return;
    }
    if ( size < 0 ) {
	my_xlog(LOG_SEVERE, "decrease_hash_size(): size<0 in decrease_hash_size\n");
	do_exit(1);
	return;
    }
    total_alloc -= size;
    if ( !(rc=pthread_mutex_lock(&hash->size_lock)) ) {
	hash->size -= size;
	if ( hash->size < 0 ) {
    	    my_xlog(LOG_SEVERE, "decrease_hash_size(): decrease: hash_size has negative value: %d!\n", hash->size);
	    do_exit(1);
	}
	pthread_mutex_unlock(&hash->size_lock);
    } else {
	my_xlog(LOG_SEVERE, "decrease_hash_size(): Can't lock hash entry for decrease size\n");
    }
}

void
remove_limits(void)
{
#if	!defined(_WIN32)
struct	rlimit	rl = {RLIM_INFINITY, RLIM_INFINITY};

#if	defined(RLIMIT_DATA)
	if ( !getrlimit(RLIMIT_DATA, &rl) ) {
	    rl.rlim_cur = rl.rlim_max;
	    if ( !setrlimit(RLIMIT_DATA, &rl) ) {
		printf("RLIMIT_DATA changed to maximum: %u\n", (unsigned)rl.rlim_max);
	    } else {
		printf("warning: Can't change RLIMIT_DATA\n");
	    }
	}
#endif
#if	defined(RLIMIT_NOFILE)
	if ( !getrlimit(RLIMIT_NOFILE, &rl) ) {
	    rl.rlim_cur = rl.rlim_max = OPEN_FILES_MAXIMUM;
	    if ( !setrlimit(RLIMIT_NOFILE, &rl) ) {
		printf("RLIMIT_NOFILE changed to maximum: %u\n", (unsigned)rl.rlim_max);
	    } else {
		printf("warning: Can't change RLIMIT_NOFILE\n");
	    }
	}
#endif
#if	defined(_RLIMIT_CORE)
	if ( !getrlimit(RLIMIT_CORE, &rl) ) {
	    rl.rlim_cur = 0;
	    if ( !setrlimit(RLIMIT_CORE, &rl) ) {
		printf("RLIMIT_CORE changed to minimum: %u\n", (unsigned)rl.rlim_cur);
	    } else {
		printf("warning: Can't change RLIMIT_CORE\n");
	    }
	}
#endif
#if	defined(RLIMIT_NPROC) && defined(LINUX)
	if ( !getrlimit(RLIMIT_NPROC, &rl) ) {
	    rl.rlim_cur = RLIM_INFINITY;
	    if ( !setrlimit(RLIMIT_NPROC, &rl) ) {
		printf("RLIMIT_NPROC changed to maximum: %u\n", (unsigned)rl.rlim_cur);
	    } else {
		printf("warning: Can't change RLIMIT_NPROC\n");
	    }
	}
#endif
#endif	/* !_WIN32 */
}

void
report_limits(void)
{
#if	!defined(_WIN32)
struct	rlimit	rl = {RLIM_INFINITY, RLIM_INFINITY};

#if	defined(RLIMIT_DATA)
	if ( !getrlimit(RLIMIT_DATA, &rl) ) {
	    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "report_limits(): RLIMIT_DATA: %u\n", (unsigned)rl.rlim_cur);
	}
#endif
#if	defined(RLIMIT_NOFILE)
	if ( !getrlimit(RLIMIT_NOFILE, &rl) ) {
	    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "report_limits(): RLIMIT_NOFILE: %u\n", (unsigned)rl.rlim_cur);
	}
#endif
#if	defined(RLIMIT_CORE)
	if ( !getrlimit(RLIMIT_CORE, &rl) ) {
	    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "report_limits(): RLIMIT_CORE: %u\n", (unsigned)rl.rlim_cur);
	}
#endif
#if	defined(RLIMIT_NPROC) && defined(LINUX)
	if ( !getrlimit(RLIMIT_NPROC, &rl) ) {
	    if ( !getrlimit(RLIMIT_NPROC, &rl) ) /* ??? same condition ??? */    {
		my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "report_limits(): RLIMIT_NPROC: %u\n", (unsigned)rl.rlim_cur);
	    }
	}
#endif
#endif	/* !_WIN32 */
}

int
calculate_resident_size(struct mem_obj *obj)
{
int		rs = sizeof(struct mem_obj);
struct	buff	*b = obj->container;
struct	av	*av = obj->headers;
    while( b ) {
	rs += sizeof(*b) + b->curr_size;
	b = b->next;
    }
    while( av ) {
	rs += sizeof(*av);
	if ( av->attr ) rs+=strlen(av->attr);
	if ( av->val ) rs+= strlen(av->val);
	av = av->next;
    }
    return(rs);
}

int
calculate_container_datalen(struct buff *b)
{
int		rs = 0;

    while( b ) {
	rs += b->used;
	b = b->next;
    }
    return(rs);
}

/* read/write locks	*/
void
rwl_init(rwl_t	*rwlp)
{
    pthread_mutex_init(&rwlp->m, NULL);
    pthread_cond_init(&rwlp->readers_ok, NULL);
    pthread_cond_init(&rwlp->writer_ok, NULL);
    rwlp->rwlock = 0;
    rwlp->waiting_writers = 0;
}

void
rwl_destroy(rwl_t *rwlp)
{
    pthread_mutex_destroy(&rwlp->m);
    pthread_cond_destroy(&rwlp->readers_ok);
    pthread_cond_destroy(&rwlp->writer_ok);
}

/* acquire read lock */
void
rwl_rdlock(rwl_t *rwlp)
{
    if ( !pthread_mutex_lock(&rwlp->m) ) {
	while( rwlp->rwlock < 0 || rwlp->waiting_writers )
	    pthread_cond_wait(&rwlp->readers_ok, &rwlp->m);
	rwlp->rwlock++;
	pthread_mutex_unlock(&rwlp->m);
    } else
	my_xlog(LOG_SEVERE, "rwl_rdlock(): Can't rdlock\n");
}

/* acquire write lock */
void
rwl_wrlock(rwl_t *rwlp)
{
    if ( !pthread_mutex_lock(&rwlp->m) ) {
	while (rwlp->rwlock != 0 ) {
	    rwlp->waiting_writers++;
	    pthread_cond_wait(&rwlp->writer_ok, &rwlp->m);
	    rwlp->waiting_writers--;
	}
	rwlp->rwlock = -1;
	pthread_mutex_unlock(&rwlp->m);
    } else
	my_xlog(LOG_SEVERE, "rwl_wrlock(): Can't rwlock\n");
}

/* unlock rwlock */
void
rwl_unlock(rwl_t *rwlp)
{
    int ww, wr;

    pthread_mutex_lock(&rwlp->m);
    if ( rwlp->rwlock < 0 )
	rwlp->rwlock = 0;
    else
	rwlp->rwlock--;
    ww = ( rwlp->waiting_writers && (rwlp->rwlock == 0) ) ;
    wr = ( rwlp->waiting_writers == 0 );
    pthread_mutex_unlock(&rwlp->m);
    if ( ww )
	pthread_cond_signal(&rwlp->writer_ok);
    else if ( wr )
	pthread_cond_broadcast(&rwlp->readers_ok);
}

void
my_sleep(int sec)
{
#if	defined(OSF)
    /* DU don't want to sleep in poll when number of descriptors is 0 */
    sleep(sec);
#elif	defined(_WIN32)
    XXX Sleep(sec*1000);
#else
    (void)poll_descriptors(0, NULL, sec*1000);
#endif
}

void
my_msleep(int msec)
{
#if	defined(OSF)
    /* DU don't want to sleep in poll when number of descriptors is 0 */
    usleep(msec*1000);
#elif	defined(_WIN32)
    XXX Sleep(msec*1000);
#else
    (void)poll_descriptors(0, NULL, msec);
#endif
}

int
poll_descriptors(int n, struct pollarg *args, int msec)
{
int	rc = -1;

    if ( n > 0 ) {

#if	defined(HAVE_POLL) && !defined(LINUX) && !defined(FREEBSD)
	struct	pollfd	pollfd[MAXPOLLFD], *pollptr,
			    *pollfdsaved = NULL, *pfdc;
	struct	pollarg *pa;
	int		i;

	if ( msec < 0 ) msec = -1;
	if ( n > MAXPOLLFD ) {
	    pollfdsaved = pollptr = xmalloc(n*sizeof(struct pollfd), "poll_descriptors(): 1");
	    if ( !pollptr ) return(-1);
	} else
	    pollptr = pollfd;
	/* copy args to poll argument */
	pfdc = pollptr;
	bzero(pollptr, n*sizeof(struct pollfd));
	pa = args;
	for(i=0;i<n;i++) {
	    if ( pa->fd>0)
		pfdc->fd = pa->fd;
	      else
		pfdc->fd = -1;
	    pfdc->revents = 0;
	    if ( pa->request & FD_POLL_RD ) pfdc->events |= POLLIN|POLLHUP;
	    if ( pa->request & FD_POLL_WR ) pfdc->events |= POLLOUT|POLLHUP;
	    if ( !(pfdc->events & (POLLIN|POLLOUT) ) )
		pfdc->fd = -1;
	    pa->answer = 0;
	    pa++;
	    pfdc++;
	}
	rc = poll(pollptr, n, msec);
	if ( rc <= 0 ) {
	    if ( pollfdsaved ) xfree(pollfdsaved);
	    return(rc);
	}
	/* copy results back */
	pfdc = pollptr;
	pa = args;
	for(i=0;i<n;i++) {
	    if ( pfdc->revents & (POLLIN) ) pa->answer  |= FD_POLL_RD;
	    if ( pfdc->revents & (POLLOUT) ) pa->answer |= FD_POLL_WR;
	    if ( pfdc->revents & (POLLHUP|POLLERR) ) pa->answer |= FD_POLL_HU;
	    pa++;
	    pfdc++;
	}
	if ( pollfdsaved ) xfree(pollfdsaved);
	return(rc);
#else
	fd_set	rset, wset;
	int	maxfd = 0,i, have_read = 0, have_write = 0;
	struct	pollarg *pa;
	struct	timeval	tv, *tvp = &tv;

   restart:
	if ( msec >= 0 ) {
	    tv.tv_sec =  msec/1000 ;
	    tv.tv_usec = (msec%1000)*1000 ;
	} else {
	    tvp = NULL;
	}
	FD_ZERO(&rset);
	FD_ZERO(&wset);
	pa = args;
	for(i=0;i<n;i++) {
	    if ( pa->request & FD_POLL_RD ) {
		have_read = 1;
		FD_SET(pa->fd, &rset);
		maxfd = MAX(maxfd, pa->fd);
	    }
	    if ( pa->request & FD_POLL_WR ) {
		have_write = 1;
		FD_SET(pa->fd, &wset);
		maxfd = MAX(maxfd, pa->fd);
	    }
	    pa->answer = 0;
	    pa++;
	}

	rc = select(maxfd+1,
		    (have_read  ? &rset : NULL),
		    (have_write ? &wset : NULL),
		    NULL, tvp);

	if ( rc <= 0 ) {
#if	defined(FREEBSD)
	    if ( (rc < 0) && (ERRNO == EINTR) )
		goto restart;
#endif	/* FREEBSD */
	    return(rc);
	}
	/* copy results back */
	pa = args;
	for(i=0;i<n;i++) {
	    if ( pa->request & FD_POLL_RD ) {
		/* was request on read */
		if ( FD_ISSET(pa->fd, &rset) )
			pa->answer |= FD_POLL_RD;
	    }
	    if ( pa->request & FD_POLL_WR ) {
		/* was request on write */
		if ( FD_ISSET(pa->fd, &wset) )
			pa->answer |= FD_POLL_WR;
	    }
	    pa++;
	}
	return(rc);
#endif

    } else {

#if	defined(HAVE_POLL) && !defined(LINUX) && !defined(FREEBSD)
	rc = poll(NULL, 0, msec);
#else
	struct timeval	tv;

   restart0:
	tv.tv_sec =  msec/1000 ;
	tv.tv_usec = (msec%1000)*1000 ;
	rc = select(1, NULL, NULL, NULL, &tv);
#if	defined(FREEBSD)
	if ( (rc < 0) && (ERRNO == EINTR) )
		goto restart0;
#endif	/* FREEBSD */
#endif

    }
    return(rc);
}

#if	defined(FREEBSD)
/* Under FreeBSD all threads get poll/select interrupted (even in
   threads with signals blocked, so we need version of poll_descriptors
   which can detect interrupts, and version which ignore interrupts
   This function don't ignore and must be called from main thread
   only.
 */
int
poll_descriptors_S(int n, struct pollarg *args, int msec)
{
int	rc = -1;

    if ( n > 0 ) {
	fd_set	rset, wset;
	int	maxfd = 0,i, have_read = 0, have_write = 0;
	struct	pollarg *pa;
	struct timeval	tv, *tvp = &tv;


	if ( msec >= 0 ) {
	    tv.tv_sec =  msec/1000 ;
	    tv.tv_usec = (msec%1000)*1000 ;
	} else {
	    tvp = NULL;
	}
	FD_ZERO(&rset);
	FD_ZERO(&wset);
	pa = args;
	for(i=0;i<n;i++) {
	    if ( pa->request & FD_POLL_RD ) {
		have_read = 1;
		FD_SET(pa->fd, &rset);
		maxfd = MAX(maxfd, pa->fd);
	    }
	    if ( pa->request & FD_POLL_WR ) {
		have_write = 1;
		FD_SET(pa->fd, &wset);
		maxfd = MAX(maxfd, pa->fd);
	    }
	    pa->answer = 0;
	    pa++;
	}

	rc = select(maxfd+1,
		    (have_read  ? &rset : NULL),
		    (have_write ? &wset : NULL),
		    NULL, tvp);

	if ( rc <= 0 )
	    return(rc);
	/* copy results back */
	pa = args;
	for(i=0;i<n;i++) {
	    if ( pa->request & FD_POLL_RD ) {
		/* was request on read */
		if ( FD_ISSET(pa->fd, &rset) )
			pa->answer |= FD_POLL_RD;
	    }
	    if ( pa->request & FD_POLL_WR ) {
		/* was request on write */
		if ( FD_ISSET(pa->fd, &wset) )
			pa->answer |= FD_POLL_WR;
	    }
	    pa++;
	}
	return(rc);
    } else {
	struct timeval	tv;

	tv.tv_sec =  msec/1000 ;
	tv.tv_usec = (msec%1000)*1000 ;
	rc = select(1, NULL, NULL, NULL, &tv);
    }
    return(rc);
}
#endif	/* FREEBSD */

char*
my_inet_ntoa(struct sockaddr_in * sa)
{
char * res = xmalloc(20, "my_inet_ntoa(): 1");
uint32_t	ia = ntohl(sa->sin_addr.s_addr);
uint32_t	a, b, c, d;

    if ( !res ) return(NULL);
    a =  ia >> 24;
    b = (ia & 0x00ff0000) >> 16;
    c = (ia & 0x0000ff00) >> 8;
    d = (ia & 0x000000ff);
    sprintf(res, "%d.%d.%d.%d",
	(unsigned)(ia >> 24),
	(unsigned)((ia & 0x00ff0000) >> 16),
	(unsigned)((ia & 0x0000ff00) >> 8),
	(unsigned)((ia & 0x000000ff)));
    return(res);
}

void
free_container(struct buff *buff)
{
struct buff *next;

    while(buff) {
	next = buff->next;
	/*my_xlog(LOG_DBG, "free_container(): Free buffer: %d of %d, next: %p\n", buff->size, buff->curr_size, buff->next);*/
	if ( buff->data ) free(buff->data);
	free(buff);
	buff = next;
    }
}

void
analyze_header(char *p, struct server_answ *a)
{
char	*t;

    my_xlog(LOG_HTTP|LOG_DBG, "analyze_header(): ---> `%s'.\n", p);
    if ( !a->status_code ) {
	/* check HTTP/X.X XXX */
	if ( !strncasecmp(p, "HTTP/", 5) ) {
	    int	httpv_major, httpv_minor;
	    if ( sscanf(p+5, "%d.%d", &httpv_major, &httpv_minor) == 2 ) {
		a->httpv_major = httpv_major;
		a->httpv_minor = httpv_minor;
	    }
	    t = strchr(p, ' ');
	    if ( !t ) {
		my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "analyze_header(): Wrong_header: %s\n", p);
		return;
	    }
	    a->status_code = atoi(t);
	    my_xlog(LOG_DBG, "analyze_header(): Status code: %d\n", a->status_code);
	}
	return;
    }
    if ( !strncasecmp(p, "X-oops-internal-request-time: ", 30) ) {
	char        *x;

	x=p + 30;
	while( *x && IS_SPACE(*x) ) x++;
	a->request_time = atoi(x);
	return;
    }
    if ( !strncasecmp(p, "X-oops-internal-response-time: ", 31) ) {
	char        *x;

	x=p + 31;
	while( *x && IS_SPACE(*x) ) x++;
	a->response_time = atoi(x);
	return;
    }
    if ( !strncasecmp(p, "X-oops-internal-content-length: ", 32) ) {
	char        *x;

	x=p + 31;
	while( *x && IS_SPACE(*x) ) x++;
	a->x_content_length = atoi(x);
	return;
    }
    if ( !strncasecmp(p, "X-oops-internal-alt-expires: ", 29) ) {
	char        *x;

	x=p + 29;
	while( *x && IS_SPACE(*x) ) x++;
	a->times.expires = atoi(x);
	SET(a->flags, ANSW_EXPIRES_ALTERED | ANSW_HAS_EXPIRES);
	return;
    }
    if ( !strncasecmp(p, "Content-length: ", 16) ) {
	char        *x;
	/* length */
	x=p + 16; /* strlen("content-length: ") */
	while( *x && IS_SPACE(*x) ) x++;
	a->content_len = atoi(x);
	return;
    }
    if ( !strncasecmp(p, "Date: ", 6) ) {
	char        *x;
	/* length */
	x=p + 6; /* strlen("date: ") */
	while( *x && IS_SPACE(*x) ) x++;
	a->times.date  = global_sec_timer;
	if (http_date(x, &a->times.date) ) my_xlog(LOG_DBG|LOG_INFORM, "analyze_header(): Can't parse date: %s\n", x);
	return;
    }
    if ( !strncasecmp(p, "Last-Modified: ", 15) ) {
	char        *x;
	/* length */
	x=p + 15; /* strlen("date: ") */
	while( *x && IS_SPACE(*x) ) x++;
	if (http_date(x, &a->times.last_modified) ) my_xlog(LOG_DBG|LOG_INFORM, "analyze_header(): Can't parse date: %s\n", x);
	    else
		a->flags |= ANSW_LAST_MODIFIED;
	return;
    }
    if ( !strncasecmp(p, "Pragma: ", 8) ) {
	char        *x;
	/* length */
	x=p + 8; /* strlen("Pragma: ") */
	if ( strstr(x, "no-cache") ) a->flags |= ANSW_NO_STORE;
	return;
    }
    if ( !strncasecmp(p, "Age: ", 5) ) {
	char        *x;
	/* length */
	x=p + 5; /* strlen("Age: ") */
	a->times.age = atoi(x);
	return;
    }
    if ( !strncasecmp(p, "Cache-Control: ", 15) ) {
	char        *x;
	/* length */
	x=p + 15; /* strlen("Cache-Control: ") */
	while( *x && IS_SPACE(*x) ) x++;
	if ( strstr(x, "no-store") )
		a->flags |= ANSW_NO_STORE;
	if ( strstr(x, "no-cache") )
		a->flags |= ANSW_NO_STORE;
	if ( strstr(x, "private") )
		a->flags |= ANSW_NO_STORE;
	if ( strstr(x, "must-revalidate") )
		a->flags |= ANSW_MUST_REVALIDATE;
	if ( !strncasecmp(x, "proxy-revalidate", 15) )
		a->flags |= ANSW_PROXY_REVALIDATE;
	if ( sscanf(x, "max-age = %d", (int*)&a->times.max_age) == 1 )
		a->flags |= ANSW_HAS_MAX_AGE;
    }
    if ( !strncasecmp(p, "Connection: ", 12) ) {
	char        *x;
	/* length */
	x = p + 12; /* strlen("Connection: ") */
	while( *x && IS_SPACE(*x) ) x++;
	if ( !strncasecmp(x, "keep-alive", 10) )
		a->flags |= ANSW_KEEP_ALIVE;
	if ( !strncasecmp(x, "close", 5) )
		a->flags &= ~ANSW_KEEP_ALIVE;
    }
    if (    !TEST(a->flags, ANSW_HAS_EXPIRES) 
         && !strncasecmp(p, "Expires: ", 9) ) {
	char        *x;
	/* length */
	x = p + 9; /* strlen("Expires: ") */
	while( *x && IS_SPACE(*x) ) x++;
	a->times.expires  = time(NULL);
	if (http_date(x, &a->times.expires)) {
		my_xlog(LOG_DBG|LOG_INFORM, "analyze_header(): Can't parse date: %s\n", x);
		return;
	}
	a->flags |= ANSW_HAS_EXPIRES;
	return;
    }
}

struct av*
lookup_av_by_attr(struct av *avp, char *attr)
{
struct av	*res = NULL;

    if ( !attr ) return(NULL);

    while( avp ) {
	if ( avp->attr && !strncasecmp(avp->attr, attr, strlen(attr)) ) {
	    res = avp;
	    break;
	}
	avp = avp->next;
    }
    return(res);
}

char*
attr_value(struct av *avp, char *attr)
{
char	*res = NULL;

    if ( !attr ) return(NULL);

    while( avp ) {
	if ( avp->attr && !strncasecmp(avp->attr, attr, strlen(attr)) ) {
	    res = avp->val;
	    break;
	}
	avp = avp->next;
    }
    return(res);
}

int
put_av_pair(struct av **pairs, char *attr, char *val)
{
struct	av	*new = NULL, *next;
char		*new_attr=NULL, *new_val = NULL;

    new = xmalloc(sizeof(*new), "put_av_pair(): for av pair");
    if ( !new ) goto failed;
    bzero(new, sizeof(*new));
    new_attr=xmalloc( strlen(attr)+1, "put_av_pair(): for new_attr" );
    if ( !new_attr ) goto failed;
    strcpy(new_attr, attr);
    new_val=xmalloc( strlen(val)+1, "put_av_pair(): for new_val" );
    if ( !new_val ) goto failed;
    strcpy(new_val, val);
    new->attr = new_attr;
    new->val = new_val;
    if ( !*pairs ) {
	*pairs = new;
    } else {
	next = *pairs;
	while (next->next) next=next->next;
	next->next=new;
    }
    return(0);

failed:
    if ( new ) xfree(new);
    if ( new_attr ) xfree(new_attr);
    if ( new_val ) xfree(new_val);
    return(1);
}

int
add_header_av(char* avtext, struct mem_obj *obj)
{
struct	av	*new = NULL, *next;
char		*attr = avtext, *sp = avtext, *val, holder;
char		*new_attr = NULL, *new_val = NULL;
char		nullstr[1];

    if ( *sp == 0 ) return(-1);
    while( *sp && IS_SPACE(*sp) ) sp++;
    while( *sp && !IS_SPACE(*sp) && (*sp != ':') ) sp++;
    if ( !*sp ) {
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "add_header_av(): Invalid header string: '%s'\n", avtext);
	nullstr[0] = 0;
	sp = nullstr;
    }
    if ( *sp == ':' ) sp++;
    holder = *sp;
    *sp = 0;
    if ( !strlen(attr) ) return(-1);
    new = xmalloc(sizeof(*new), "add_header_av(): for av pair");
    if ( !new ) goto failed;
    new_attr = xmalloc( strlen(attr)+1, "add_header_av(): for new_attr" );
    if ( !new_attr ) goto failed;
    strcpy(new_attr, attr);
    *sp = holder;
    val = sp; while( *val && IS_SPACE(*val) ) val++;
    /*if ( !*val ) goto failed;*/
    new_val = xmalloc( strlen(val) + 1, "add_header_av(): for new_val");
    if ( !new_val ) goto failed;
    strcpy(new_val, val);
    new->attr = new_attr;
    new->val  = new_val;
    new->next = NULL;
    if ( !obj->headers ) {
	obj->headers = new;
    } else {
	next = obj->headers;
	while (next->next) next=next->next;
	next->next=new;
    }
    return(0);

failed:
    *sp = holder;
    if ( new ) free(new);
    if ( new_attr ) free(new_attr);
    if ( new_val ) free(new_val);
    return(-1);
}

int
check_server_headers(struct server_answ *a, struct mem_obj *obj, struct buff *b, struct request *rq)
{
char	*start, *beg, *end, *p;
char	holder, its_here = 0, off = 2;
char	*p1 = NULL;

    if ( !b || !b->data ) return(0);
    beg = b->data;
    end = b->data + b->used;

go:
    if ( a->state & GOT_HDR ) return(0);
    start = beg + a->checked;
    if ( !a->checked ) {
	p = memchr(beg, '\n', end-beg);
	holder = '\n';
	if ( !p ) {
	    p = memchr(beg, '\r', end-beg);
	    holder = '\r';
	}
	if ( !p ) return(0);
	if ( *p == '\n' ) {
	    if ( *(p-1) == '\r' ) {
		p1 = p-1;
		*p1 = 0;
	    }
	}
	*p = 0;
	a->checked = strlen(start);
	/* this is HTTP XXX yyy "header", which we will never rewrite */
	analyze_header(start, a);
	if ( add_header_av(start, obj) ) {
	    *p = holder;
	    if ( p1 ) {*p1 = '\r'; p1=NULL;}
	    return(-1);
	}
	*p = holder;
	if ( p1 ) {*p1 = '\r'; p1=NULL;}
	goto go;
    }
    if ( (end - start >= 2) && !memcmp(start, "\n\n", 2) ) {
	its_here = 1;
	off = 2;
    }
    if ( (end - start >= 3) && !memcmp(start, "\r\n\n", 3) ) {
	its_here = 1;
	off = 3;
    }
    if ( (end - start >= 3) && !memcmp(start, "\n\r\n", 3) ) {
	its_here = 1;
	off = 3;
    }
    if ( (end - start >= 4) && !memcmp(start, "\r\n\r\n", 4) ) {
	its_here = 1;
	off = 4;
    }
    if ( its_here ) {
	struct buff	*body;
	int		all_siz;

	obj->insertion_point = start-beg;
	obj->tail_length = off;
	a->state |= GOT_HDR ;
	obj->httpv_major = a->httpv_major;
	obj->httpv_minor = a->httpv_minor;
	obj->content_length = a->content_len;
	b->used = ( start + off ) - beg;	/* trunc first buf to header siz	*/
	/* if requested don't cache documents without "Last-Modified" */
	if ( dont_cache_without_last_modified
		&& !TEST(a->flags, ANSW_LAST_MODIFIED) ) {
	    SET(obj->flags, ANSW_NO_STORE|ANSW_NO_CACHE);
	}
	/* allocate data storage */
	if ( a->content_len ) {
	    if ( a->content_len > maxresident ) {
		/*
		 -  This object will not be stored, we will receive it in
		 -  small parts, in syncronous mode
		 -  allocate as much as we need now...
		*/
		all_siz = ROUND_CHUNKS(end-start-off);
		/*
		 - mark object as 'not for store' and 'don't expand container'
		*/
		a->flags |= (ANSW_NO_STORE | ANSW_SHORT_CONTAINER);
	    } else /* obj is not too large */
		all_siz = a->content_len;
	} else /* no Content-Len: */
	    all_siz = ROUND_CHUNKS(end-start-off);
	body = alloc_buff(all_siz);
	if ( !body ) {
	    return(-1);
	}
	b->next = body;
	obj->hot_buff = body;
	attach_data(start+off, end-start-off, obj->hot_buff);
	return(0);
    }
    p = start;
    while( (p < end) && ( *p == '\r' || *p == '\n' ) ) p++;
    if ( p < end && *p ) {
	char *t = memchr(p, '\n', end-p);
	char *tmp, *saved_tmp;

	holder = '\n';
	if ( !t ) {
	    t = memchr(p, '\r', end-p);
	    holder = '\r';
	}
	if ( !t ) return(0);
	if ( *t == '\n' ) {
	    if ( *(t-1) == '\r' ) {
		p1 = t-1;
		*p1 = 0;
	    }
	}
	*t = 0;
	saved_tmp = tmp = strdup(p);
	if ( !tmp )
	    return(-1);
	do_redir_rewrite_header(&tmp, rq, NULL);
	analyze_header(tmp, a);
	if ( add_header_av(tmp, obj) ) {
	    free(tmp);
	    return(-1);
	}
	if ( saved_tmp != tmp ) {
	    /* header was changed */
	    if ( obj ) SET(obj->flags, ANSW_HDR_CHANGED);
	}
	free(tmp);
	*t = holder;
	if ( p1 ) { *p1 = '\r'; t=p1; p1 = NULL;}
	a->checked = t - beg;
	goto go;
    }
    return(0);
}

struct	buff*
alloc_buff(int size)
{
char		*t, *d;
struct buff	*b;

    if ( size <=0 ) return(NULL);
    t = xmalloc(sizeof(struct buff), "alloc_buff(): 1");
    if ( !t ) return(NULL);
    bzero(t, sizeof(struct buff));
    d = xmalloc(size, "alloc_buff(): 2");
    if ( !d ) {
	free(t);
	return(NULL);
    }
    b = (struct buff*)t;
    b->data = d;
    b->curr_size = size;
    b->used = 0;
    return(b);
}

/* store in hot_buff, allocate buffs if need*/
int
store_in_chain(char *src, int size, struct mem_obj *obj)
{
struct buff *hot = obj->hot_buff, *new;

    if (!hot) {
	my_xlog(LOG_SEVERE, "store_in_chain(): hot == NULL!\n");
	return(-1);
    }
    if (!obj) {
	my_xlog(LOG_SEVERE, "store_in_chain(): obj == NULL!\n");
	return(-1);
    }
    if ( size < 0 ) {
	my_xlog(LOG_SEVERE, "store_in_chain(): size = %d!\n", size);
	return(-1);
    }
    if ( hot->used + size <= hot->curr_size ) {
	memcpy( hot->data + hot->used, src, size);
	hot->used += size;
    } else {
	int	moved, to_move;
	/* copy part */
	memcpy(hot->data + hot->used, src, hot->curr_size - hot->used);
	moved=hot->curr_size - hot->used;
	hot->used = hot->curr_size;
	to_move = size - moved;
	/* allocate  */
	new = alloc_buff(ROUND_CHUNKS(to_move));
	if ( !new ) return(-1);
	/* copy rest */
	memcpy(new->data, src+moved, to_move);
	new->used = to_move;
	hot->next = new;
	obj->hot_buff = new;
    }
    return(0);
}

int
attach_av_pair_to_buff(char* attr, char *val, struct buff *buff)
{
    if ( !attr || !val || !buff )return(-1);

    if ( *attr ) {
	attach_data(attr, strlen(attr), buff);
	attach_data(" ", 1, buff);
	attach_data(val, strlen(val), buff);
    }
    attach_data("\r\n", 2, buff);
    return(0);
}

/* concatenate bata in continuous buffer */
int
attach_data(char* src, int size, struct buff *buff)
{
char	*t;
int	tot;

    if ( size <= 0 ) return(-1);
    if ( !buff->data ) {
	t = xmalloc(((size / CHUNK_SIZE) + 1) * CHUNK_SIZE, "attach_data(): 1");
	if (!t) return(-1);
	buff->data = t;
	memcpy(t, src, size);
	buff->curr_size = ((size / CHUNK_SIZE) + 1) * CHUNK_SIZE;
	buff->used = size;
	return(0);
    }
    if ( buff->used + size <= buff->curr_size ) {
	memcpy(buff->data+buff->used, src, size);
	buff->used += size;
    } else {
	tot = buff->used + size;
	tot = ((tot / CHUNK_SIZE) + 1) * CHUNK_SIZE;
	t = xmalloc(tot, "attach_data(): 2");
	if (!t ) {
	    my_xlog(LOG_SEVERE, "attach_data(): No mem in attach data.\n");
	    return(-1);
	}
	memcpy(t, buff->data, buff->used);
	memcpy(t+buff->used, src, size);
	free(buff->data);buff->data = t;
	buff->used += size;
	buff->curr_size = tot;
    }
    return(0);
}


#undef	malloc

struct	malloc_buf {
	int			state;
	int			size;
	int			current_size;
	void			*data;
	char			*descr;
	struct	malloc_buf	*next;
};
struct	malloc_bucket {
	struct	malloc_buf	*first;
	struct	malloc_buf	*last;
};

#define	BU_FREE	1
#define	BU_BUSY	2

#if	defined(MALLOCDEBUG)
struct	malloc_bucket	m = {NULL, NULL};
int			malloc_mutex_inited=0;

void
list_all_mallocs()
{
struct malloc_bucket	*b = &m;
struct malloc_buf	*buf=b->first;
char			*x;
int			num = 0;
    while(buf) {
	num++;
	if ( buf->state==BU_BUSY ) {
	    x = buf->data + buf->current_size;
	    if ( *x     != 'd' ) {my_xlog(LOG_SEVERE, "list_all_mallocs(): cb, Destroyed: `%s'\n",buf->data); do_exit(0);}
	    if ( *(x+1) != 'e' ) {my_xlog(LOG_SEVERE, "list_all_mallocs(): cb, Destroyed: `%s'\n",buf->data); do_exit(0);}
	    if ( *(x+2) != 'a' ) {my_xlog(LOG_SEVERE, "list_all_mallocs(): cb, Destroyed: `%s'\n",buf->data); do_exit(0);}
	    if ( *(x+3) != 'd' ) {my_xlog(LOG_SEVERE, "list_all_mallocs(): cb, Destroyed: `%s'\n",buf->data); do_exit(0);}
	    my_xlog(LOG_SEVERE, "list_all_mallocs(): Busy block: %s\n", buf->descr);
	    if (!strcmp(buf->descr, "string"))
		my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "list_all_mallocs(): <%s>\n", buf->data);
	} else {
	    int i = buf->size;
	    x=buf->data;
	    for(;i;i--,x++) if (*x) {
		my_xlog(LOG_SEVERE, "list_all_mallocs(): free buffer `%s' destroyed\n", buf->descr);
		do_exit(0);
	    };
	}
	buf=buf->next;
    }
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "list_all_mallocs(): Total bufs: %d\n", num);
}

void
check_all_buffs()
{
struct malloc_bucket	*b = &m;
struct malloc_buf	*buf=b->first;
char			*x;

    while(buf) {
	if ( buf->state==BU_BUSY ) {
	    x = buf->data + buf->current_size;
	    if ( *x     != 'd' ) {my_xlog(LOG_SEVERE, "check_all_buffs(): cb, Destroyed: `%s'\n",buf->data); do_exit(0);}
	    if ( *(x+1) != 'e' ) {my_xlog(LOG_SEVERE, "check_all_buffs(): cb, Destroyed: `%s'\n",buf->data); do_exit(0);}
	    if ( *(x+2) != 'a' ) {my_xlog(LOG_SEVERE, "check_all_buffs(): cb, Destroyed: `%s'\n",buf->data); do_exit(0);}
	    if ( *(x+3) != 'd' ) {my_xlog(LOG_SEVERE, "check_all_buffs(): cb, Destroyed: `%s'\n",buf->data); do_exit(0);}
	} else {
	    int i = buf->size;
	    x=buf->data;
	    for(;i;i--,x++) if (*x) {
		my_xlog(LOG_SEVERE, "check_all_buffs(): free buffer `%s' destroyed.\n", buf->descr);
		do_exit(0);
	    };
	}
	buf=buf->next;
    }
}
#endif

void *
xmalloc(size_t size, char *d)
{
#if	!defined(MALLOCDEBUG)
char	*p;

	if ( size < 0 ) {
	    my_xlog(LOG_DBG, "xmalloc(): Alloc %d for %s\n", size, d);
	    do_exit(1);
	}
	p = malloc(size);
	return(p);
#else

struct malloc_bucket	*b;
struct malloc_buf	*buf;

    if ( !malloc_mutex_inited ) {
	pthread_mutex_init(&malloc_mutex, NULL);
	malloc_mutex_inited = 1;
    }
    if ( !d ) {
	my_xlog(LOG_SEVERE, "xmalloc(): Invalid malloc call.\n");
    }
    my_xlog(LOG_DBG, "xmalloc(): %d for %s\n", size, d);
    pthread_mutex_lock(&malloc_mutex);
    check_all_buffs();
    b = &m;
    buf = b->first;
    while ( buf ) {
	if ( (buf->state == BU_FREE) && (buf->size >= size) )
		break;
	buf = buf->next;
    }
    if ( buf ) {
	char	*x;
	int	i = buf->size;
	x=buf->data;
	for(;i;i--,x++) if (*x) {
		my_xlog(LOG_SEVERE, "xmalloc(): free buffer `%s' destroyed.\n", buf->descr);
		do_exit(0);
	};
	buf->current_size  = size;
	buf->descr = d?d:"EMPTY";
	buf->state = BU_BUSY;
	x = buf->data+size;
	*x	= 'd';
	*(x+1)	= 'e';
	*(x+2)	= 'a';
	*(x+3)	= 'd';
	pthread_mutex_unlock(&malloc_mutex);
	my_xlog(LOG_DBG, "xmalloc(): returning old %p\n", buf->data);
	return(buf->data);
    } else {
	char *x;
	buf = malloc(sizeof(*buf));
	if ( b->last )  b->last->next = buf;
	    else	b->last=b->first=buf;
	b->last = buf;
	buf->size  = size;
	buf->current_size = size;
	buf->descr = d?d:"EMPTY";
	buf->state = BU_BUSY;
	buf->data = malloc(size+4);
	buf->next=NULL;
	x = buf->data+size;
	*x	= 'd';
	*(x+1)	= 'e';
	*(x+2)	= 'a';
	*(x+3)	= 'd';
	pthread_mutex_unlock(&malloc_mutex);
	my_xlog(LOG_DBG, "xmalloc(): returning new %p\n", buf->data);
	return(buf->data);
    }
#endif
}

void
xfree(void *ptr)
{
#if	defined(MALLOCDEBUG)
struct malloc_bucket	*b = &m;
struct malloc_buf	*buf=b->first;
char			*x;
#endif


#if	!defined(MALLOCDEBUG)
#undef	free
	free(ptr);
	return;
#else

    pthread_mutex_lock(&malloc_mutex);
    printf("xfree(): free %p\n", ptr);
    while(buf) {
	if ( buf->data == ptr ) {
	    my_xlog(LOG_DBG, "xfree(): free %s\n", buf->descr);
	    x = buf->data + buf->current_size;
	    if ( *x     != 'd' ) {my_xlog(LOG_SEVERE, "xfree(): Destroyed: %s\n",buf->data); do_exit(0);}
	    if ( *(x+1) != 'e' ) {my_xlog(LOG_SEVERE, "xfree(): Destroyed: %s\n",buf->data); do_exit(0);}
	    if ( *(x+2) != 'a' ) {my_xlog(LOG_SEVERE, "xfree(): Destroyed: %s\n",buf->data); do_exit(0);}
	    if ( *(x+3) != 'd' ) {my_xlog(LOG_SEVERE, "xfree(): Destroyed: %s\n",buf->data); do_exit(0);}
	    buf->state= BU_FREE;
	    bzero(buf->data, buf->size);
	    printf("xfree(): freed %p %d bytes\n", buf->data, buf->size);
	    pthread_mutex_unlock(&malloc_mutex);
	    return;
	}
	buf=buf->next;
    }
    printf("xfree(): Freeing not allocated.\n");
    do_exit(0);
#endif
}

struct string_list *add_to_string_list(struct string_list **list,char *string)
{
struct	string_list	*new;

    new = malloc(sizeof *new);
    if ( !new ) return(NULL);
    new->next = *list;
    *list = new;
    new->string = malloc(strlen(string)+1);
    if ( new->string ) {
	strcpy(new->string, string);
    }
    return(new);
}

void
free_string_list(struct string_list * list)
{
struct	string_list	*curr, *next;

    curr = list;
    while (curr ) {
	next = curr->next;
	if ( curr->string ) free(curr->string);
	free(curr);
	curr = next;
    }
}

struct search_list *add_to_search_list(struct search_list **list,char *off, int len)
{
struct	search_list	*new;

    new = malloc(sizeof *new);
    if ( !new ) return(NULL);
    new->next = *list;
    *list = new;
    new->len = len;
    new->off = off;
    return(new);
}

void
free_search_list(struct search_list * list)
{
struct	search_list	*curr, *next;

    curr = list;
    while (curr ) {
	next = curr->next;
	free(curr);
	curr = next;
    }
}


struct mime_types_ {
    char	*ext;
    char	*type;
} mime_types [] = {
    {"gif",	"image/gif"},
    {"jpeg",	"image/jpeg"},
    {"jpg",	"image/jpeg"},
    {"jpe",	"image/jpeg"},
    {"html",	"text/html"},
    {"htm",	"text/html"},
    {"txt",	"text/plain"},
    {"png",	"image/png"},
    {"Z",	"application/x-compress"},
    {"gz",	"application/x-gzip"},
    {NULL,	NULL}
};

char*
lookup_mime_type(char *path)
{
struct mime_types_ *mt = mime_types;
char		   *ext;

    my_xlog(LOG_DBG|LOG_INFORM, "lookup_mime_type(): Looking up mimetype for %s\n", path);
    /* extract ext from path */
    ext = strrchr(path, '.');
    if ( ext ) ext++;
    if ( ext && *ext ) while ( mt->ext ) {
	if ( !strcasecmp(ext,mt->ext) ) {
	    my_xlog(LOG_HTTP|LOG_DBG, "lookup_mime_type(): type: %s\n", mt->type);
	    return(mt->type);
	}
	mt++;
    }
    return("application/octet-stream");
}

#define	      BASE64_VALUE_SZ	256
int	      base64_value[BASE64_VALUE_SZ];
unsigned char alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
void
base_64_init()
{
int i;

    for (i = 0; i < BASE64_VALUE_SZ; i++)
	base64_value[i] = -1;

    for (i = 0; i < 64; i++)
	base64_value[(int) alphabet[i]] = i;
    base64_value['='] = 0;

}

char*
base64_encode(char *src) {
int		bits, char_count, len;
char		*res, *o_char, *lim, *o_lim;
unsigned char 	c;

    if ( !src ) return(NULL);
    len = strlen(src);
    lim = src+len;

    res = xmalloc((len*4)/3+4, "base64_encode(): 1");
    if ( !res )
	return(NULL);
    o_char = res;
    o_lim  = res + (len*4)/3 + 1 ;
    char_count = 0;
    bits = 0;
    while ( (src < lim) && (o_char < o_lim) ) {
	c = *(src++);
	bits += c;
	char_count++;
	if (char_count == 3) {
	    *(o_char++) = alphabet[bits >> 18];
	    *(o_char++) = alphabet[(bits >> 12) & 0x3f];
	    *(o_char++) = alphabet[(bits >> 6) & 0x3f];
	    *(o_char++) = alphabet[bits & 0x3f];
	    bits = 0;
	    char_count = 0;
	} else {
	    bits <<= 8;
	}
    }
    if (char_count != 0) {
	bits <<= 16 - (8 * char_count);
	*(o_char++) = alphabet[bits >> 18];
	*(o_char++) = alphabet[(bits >> 12) & 0x3f];
	if (char_count == 1) {
	    *(o_char++) = '=';
	    *(o_char++) = '=';
	} else {
	    *(o_char++) = alphabet[(bits >> 6) & 0x3f];
	    *(o_char++) = '=';
	    *(o_char) = 0;
	}
    }
    return(res);
}

char *
base64_decode(char *p)
{
char		*result;
int		j;
unsigned int	k;
int		c, base_result_sz;
long		val;

    if (!p)
	return NULL;

    base_result_sz = strlen(p);
    result = xmalloc(base_result_sz+1,"base64_decode(): 1");

    val = c = 0;
    for (j = 0; *p && j + 3 < base_result_sz; p++) {
	k = (int) *p % BASE64_VALUE_SZ;
	if (base64_value[k] < 0)
	    continue;
	val <<= 6;
	val += base64_value[k];
	if (++c < 4)
	    continue;
	result[j++] = (char) (val >> 16);
	result[j++] = (val >> 8) & 0xff;
	result[j++] = val & 0xff;
	val = c = 0;
    }
    result[j] = 0;
    return result;
}

struct charset*
lookup_charset_by_name(struct charset *charsets, char *name)
{
struct	charset	*result = charsets;

    while( result ) {
	if ( result->Name && !strcasecmp(result->Name, name) )
	    return(result);
	result = result->next;
    }
    return(NULL);
}

struct charset*
lookup_charset_by_Agent(struct charset *charsets, char *agent)
{
struct	charset		*result = charsets;
struct	string_list	*list;

    while( result ) {
	if ( result->CharsetAgent ) {
	    list = result->CharsetAgent;
	    while ( list ) {
		if ( strstr( agent, list->string) )
		    return(result);
		list = list->next;
	    }
	}
	result = result->next;
    }
    return(NULL);
}

struct charset*
add_new_charset(struct charset **charsets, char *name)
{
struct	charset *result;
char		*newname;

    result = xmalloc(sizeof(*result), "add_new_charset(): new charset");
    if ( !result ) return(NULL);
    newname = xmalloc(strlen(name)+1, "");
    if ( !newname ) {
	xfree(result);
	return(NULL);
    }
    bzero(result, sizeof(*result));
    result->next = *charsets;
    *charsets = result;
    strcpy(newname, name);
    result->Name = newname;
    return(result);
}

int
free_charsets(struct charset *charsets)
{
struct	charset *next;

    while ( charsets ) {
	next = charsets->next;
	free_charset(charsets);
	charsets = next;
    }
    return(0);
}

int
free_charset(struct charset *charset)
{

    if ( charset->Name ) xfree(charset->Name);
    if ( charset->CharsetAgent ) free_string_list(charset->CharsetAgent);
    if ( charset->Table ) xfree(charset->Table);
    xfree(charset);
    return(0);
}

void
free_output_obj(struct output_object *obj)
{
    if ( !obj )
	return;
    free_avlist(obj->headers);
    free_container(obj->body);
    free(obj);
    return;
}

void
free_avlist(struct av *av)
{
struct	av *next;

    while ( av ) {
	next = av->next;
	free(av->attr);
	free(av->val);
	free(av);
	av = next;
    }
}

void
process_output_object(int so, struct output_object *obj, struct request *rq)
{
int		rc = 0, r, send_hot_pos;
unsigned int	sended, ssended;
struct	av	*av;
struct	timeval	tv;
struct	buff	*send_hot_buff;
struct	pollarg	pollarg;
int	mod_flags = 0;

    if ( !obj || !rq ) return;
    rc = check_output_mods(so, obj, rq, &mod_flags);
    if ( (rc != MOD_CODE_OK) || TEST(mod_flags, MOD_AFLAG_OUT) )
	return ;

    if ( !obj || !rq ) return;
    /* first send headers */
    av = obj->headers;
    while(av) {
	send_av_pair(so, av->attr, av->val);
	av = av->next;
    }
    send_av_pair(so, "", "");
    if ( !obj->body ) return;
    send_hot_buff = obj->body;
    sended = send_hot_pos = 0;

send_it:
    tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
/*    r = select(so+1, NULL, &wset, NULL, &tv);*/
    pollarg.fd = so;
    pollarg.request = FD_POLL_WR;
    r = poll_descriptors(1, &pollarg, READ_ANSW_TIMEOUT*1000);
    if ( r <= 0 ) goto done;
    ssended = sended;
    if ( send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, NULL, 0, NULL, NULL) )
	goto done;
    if ( rq->flags & RQ_HAS_BANDWIDTH) update_transfer_rate(rq, sended-ssended);
    if ( sended >= obj->body->used )
	goto done;
    goto send_it;

done:
    return;
}

char
daybit(char *day)
{
char	res;

    if ( !strcasecmp(day, "sun") ) res =   1; else
    if ( !strcasecmp(day, "mon") ) res =   2; else
    if ( !strcasecmp(day, "tue") ) res =   4; else
    if ( !strcasecmp(day, "wed") ) res =   8; else
    if ( !strcasecmp(day, "thu") ) res =  16; else
    if ( !strcasecmp(day, "fri") ) res =  32; else
    if ( !strcasecmp(day, "sat") ) res =  64; else
    if ( !strcasecmp(day, "all") ) res = 127; else
    res = (char)-1;
    return(res);
}

/* insert additional (oops-internal) headers in object */
int
insert_header(char *attr, char *val, struct mem_obj *obj)
{
char		tbuf[10], *fmt, *a, *v;
int		size_incr, a_len,v_len;
struct av	*avp, *new_av;

    if ( !obj || !obj->container ) return(1);
    if ( !obj->insertion_point || obj->tail_length<=0 ) return(1);
    if ( !attr || !val ) return(1);

    memcpy(tbuf, obj->container->data + obj->insertion_point, obj->tail_length);
    a_len = strlen(attr);
    v_len = strlen(val);
    fmt = malloc(2 + a_len + 1 + v_len + 1);
    if ( !fmt ) return(1);
    sprintf(fmt,"\r\n%s %s", attr, val);
    size_incr = strlen(fmt);
    obj->container->used -= obj->tail_length;
    attach_data(fmt, size_incr, obj->container);
    attach_data(tbuf, obj->tail_length, obj->container);
    obj->insertion_point += size_incr;
    obj->size += size_incr;
    free(fmt);
    if ( !obj->headers )
	return(0);
    new_av = malloc(sizeof(*new_av));
    if ( !new_av )
	return(0);
    a = strdup(attr);
    v = strdup(val);
    if ( !a || !v || !new_av ) {
	if (new_av ) free(new_av);
	if ( a ) free(a);
	if ( v ) free(v);
	return(0);
    }
    bzero(new_av, sizeof(*new_av));
    new_av->attr = a;
    new_av->val  = v;
    avp = obj->headers;
    while( avp && avp->next ) avp = avp->next;
    if ( avp ) avp->next = new_av;
    return(0);
}

char*
fetch_internal_rq_header(struct mem_obj *obj, char *header)
{
struct av	*obj_hdr;
unsigned int	offset = sizeof("X-oops-internal-rq");
    if ( !obj || !obj->headers || !header ) return(NULL);
    obj_hdr = obj->headers;
    while ( obj_hdr ) {
	if ( obj_hdr->attr ) {
	    if (
	         (obj_hdr->attr[0] == 'X') &&
		 (obj_hdr->attr[1] == '-') &&
		 (obj_hdr->attr[2] == 'o') &&
		 (obj_hdr->attr[3] == 'o') && 
		 (strlen(obj_hdr->attr) >= offset) &&
		 (!strcasecmp(obj_hdr->attr+offset, header)) ) {
		return(obj_hdr->val);
	    }
	}
	obj_hdr = obj_hdr->next;
    }
    return(NULL);
}

int
tcp_port_in_use(u_short port, struct in_addr *addr)
{
struct	listen_so_list	*ls = listen_so_list;

    while ( ls ) {
	if ( ls->port && (ls->port == port)
	     && (   (ls->addr.s_addr == INADDR_ANY) /* we binded on all addrs */
	          ||(ls->addr.s_addr == addr->s_addr)
	        )
	   ) return(ls->so);
	ls = ls->next;
    }
    return(0);

}

void
memcpy_to_lower(char *d, char *s, size_t size)
{
    if ( !s || !d || (size <= 0) ) return;
    while(size) {
	*d = tolower(*s);
	d++;s++;size--;
    }
}

struct l_string_list *
alloc_l_string_list(void)
{
struct l_string_list *new;
    new = malloc(sizeof(*new));
    if ( new ) {
	bzero(new, sizeof(*new));
	pthread_mutex_init(&new->lock, NULL);
    }
    return(new);
}


struct l_string_list *
lock_l_string_list(struct l_string_list *l_list)
{
    if ( l_list ) {
	pthread_mutex_lock(&l_list->lock);
	l_list->refs++;
	pthread_mutex_unlock(&l_list->lock);
	return(l_list);
    }
    return(NULL);
}

void
leave_l_string_list(struct l_string_list *l_list)
{
    if ( l_list ) {
	pthread_mutex_lock(&l_list->lock);
	if ( (l_list->refs == 1) ) {
		pthread_mutex_destroy(&l_list->lock);
		free_string_list(l_list->list);
		free(l_list);
	} else {
	    l_list->refs--;
	    pthread_mutex_unlock(&l_list->lock);
	}
    }
}

void
free_refresh_patterns(refresh_pattern_t *r_p)
{
refresh_pattern_t	*next;

    if ( !r_p ) return;
    while ( r_p ) {
	next = r_p->next;
	free(r_p);
	r_p = next;
    }
}

void
set_refresh_pattern(struct request *rq, refresh_pattern_t *list)
{

    if ( !rq ) return;
    while( list ) {
	if ( rq_match_named_acl_by_index(rq, list->named_acl_index) == TRUE ) {
	    rq->refresh_pattern = *list;
	    rq->refresh_pattern.valid = 1;
	    break;
	}
	list = list->next;
    }
}

int
find_bind_acl(struct request *rq)
{
bind_acl_t	*curr;

    if ( !rq ) return(0);
    curr = bind_acl_list;
    while(curr) {
	if ( check_acl_access(curr->acl_list, rq) == TRUE ) {
	    if ( curr->addr.s_addr == INADDR_ANY ) {
		struct	sockaddr_in	sa;
		bzero(&sa, sizeof(sa));
		if ( curr->name && !str_to_sa(curr->name, (struct sockaddr*)&sa) )
		    curr->addr.s_addr = sa.sin_addr.s_addr;
	    }
	    return(curr->addr.s_addr);
	}
	curr = curr->next;
    }
    return(0);
}

void
parse_bind_acl(char *string)
{
char		*bind_addr, *p, *acls;
bind_acl_t	*new, *next;

    if ( !string ) return;
    while(*string && IS_SPACE(*string)) string++;
    new = calloc(1, sizeof(*new));
    if ( !new )
	return;
    bind_addr = strdup(string);
    if ( !bind_addr ) return;
    p = bind_addr;
    while ( *p && !IS_SPACE(*p) ) p++;
    if ( !*p ) {
	free(bind_addr);
	verb_printf("parse_bind_acl(): Invalid bind_acl line\n");
	return;
    }
    *p = 0;
    if ( bind_addr ) new->name = strdup(bind_addr);
    acls = ++p;
    parse_acl_access(&new->acl_list, acls);
    free(bind_addr);
    printf("parse_bind_acl(): String: %s\n", string);
    if ( !bind_acl_list ) {
	bind_acl_list = new;
	return;
    }
    next = bind_acl_list;
    while ( next->next )
	next = next->next;
    next->next = new;
}

void
parse_refresh_pattern(refresh_pattern_t **list, char *p)
{
char		*t, *f, *tok_ptr;
char		*aclname = NULL, *minp = NULL, *lmp = NULL, *maxp = NULL;
int		acl_index = 0, min = 0, max = 0, lm = 0;
refresh_pattern_t *new, *curr;

    if ( !list || !p )
	return;
    /* ACL_NAME MIN LMT% MAX */
    /* split */
    t = p;
    while( (f = (char*)strtok_r(t, " \t", &tok_ptr)) != 0 ) {
	t = NULL;
	if ( !aclname ) {
	    aclname = f ;
	    acl_index = acl_index_by_name(aclname);
	    if ( !acl_index ) {
		verb_printf("parse_refresh_pattern(): acl `%s' not found.\n", aclname);
		return;
	    }
	    continue;
	}
	if ( !minp ) {
	    minp = f;
	    min = atoi(minp);
	    continue;
	}
	if ( !lmp ) {
	    lmp = f;
	    lm = atoi(lmp);
	    continue;
	}
	if ( !maxp ) {
	    maxp = f;
	    max = atoi(maxp);
	    continue;
	}
	if ( minp && maxp && lmp ) break;
    }
    if ( !minp || !maxp || !lmp )
	return;
    new = malloc(sizeof(*new));
    if ( !new ) return;
    bzero(new, sizeof(*new));
    if ( min > max ) min = max;
    new->min = min;
    new->max = max;
    new->lmt = lm;
    new->named_acl_index = acl_index;
    if ( !*list ) {
	*list = new;
	return;
    }
    curr = *list;
    while ( curr->next )
	curr = curr->next;
    curr->next = new;
}

void
set_euser(char *user)
{
#if	!defined(_WIN32)
int		rc;
struct passwd	*pwd = NULL;
uid_t		uid = 0;
gid_t		gid = 0;

    if ( !user ) {
	uid = getuid();
	gid = getgid();
    } else {
	if ( (pwd = getpwnam(user)) != 0 ) {
	    uid = pwd->pw_uid;
	    gid = pwd->pw_gid;
	} else
	    printf("set_euser(): Can't getpwnam `%s'.\n", oops_user);
    }
    rc = setegid(gid);
    if ( rc == -1 )
	verb_printf("set_euser(): Can't setegid(): %m\n");
    rc = seteuid(uid);
    if ( rc == -1 )
	verb_printf("set_euser(): Can't seteuid(): %m\n");
#endif /* !_WIN32 */
}

int
init_filebuff(filebuff_t *fb)
{
    if ( !fb )
	return(1);
    fb->fd == -1;
    fb->buff = NULL;
#if	!defined(HAVE_SNPRINTF)
    fb->File = NULL;
#endif
    pthread_mutex_init(&fb->lock, NULL);
    dataq_init(&fb->queue);
    return(1);
}

int
reopen_filebuff(filebuff_t *fb, char *filename, int flag)
{
    if ( !fb || !filename )
	return(1);
    pthread_mutex_lock(&fb->lock);
#if	defined(HAVE_SNPRINTF)
    if ( fb->fd != -1 ) close(fb->fd);
    fb->fd = open(filename, O_WRONLY|O_APPEND|O_CREAT, 0660);
    if ( flag ) {
	/* if buffered and we still have no container	*/
	if ( fb->buff == NULL )
	    fb->buff = alloc_buff(FILEBUFFSZ);
    } else {
	/* unbuffered but we have container - free it	*/
	if ( fb->buff ) {
	    free_container(fb->buff);
	    fb->buff = NULL;
	}
    }
#else
    fb->File = fopen(filename,"a");
    fb->fd = -1;
    if ( fb->File ) {
	fb->fd = fileno(fb->File);
	setbuf(fb->File, NULL);
    }
    flag = 0;
#endif
    pthread_mutex_unlock(&fb->lock);
    fb->buffered = flag;
    return(1);
}

void
close_filebuff(filebuff_t *fb)
{
    if ( fb == NULL ) return;
    flushout_fb(fb);
    if ( fb->fd != -1 ) {
	close(fb->fd);
	fb->fd = -1;
    }
    pthread_mutex_lock(&fb->lock);
    if (fb->buff) free_container(fb->buff);
    fb->buff = NULL;
    pthread_mutex_unlock(&fb->lock);
}

void
flushout_fb(filebuff_t *fb)
{
struct	buff	*b;

    if ( fb == NULL ) return;
    while ( dataq_dequeue_no_wait(&fb->queue, (void **)&b) == 0 ) {
	if ( fb->fd != -1 ) write(fb->fd, b->data, b->used);
	free_container(b);
    }
    pthread_mutex_lock(&fb->lock);
    if ( fb->buff && fb->buff->data ) {
	if ( fb->fd != -1 ) write(fb->fd, fb->buff->data, fb->buff->used);
	fb->buff->used = 0;
    }
    pthread_mutex_unlock(&fb->lock);
}

void
short_flushout_fb(filebuff_t *fb)
{
struct	buff	*b;
int		i = 0;
    if ( fb == NULL ) return;
    while ( dataq_dequeue_no_wait(&fb->queue, (void **)&b) == 0 ) {
	if ( fb->fd != -1 ) write(fb->fd, b->data, b->used);
	free_container(b);
	if ( ++i >= 5 ) break;
    }
}

void
put_str_in_filebuff(char *str, filebuff_t *fb)
{
int		strl;
struct	buff	*b = NULL;

    if ( !str || !fb ) return;
    pthread_mutex_lock(&fb->lock);
    if ( (fb->buffered == 0) || (fb->buff == NULL) ) {
	pthread_mutex_unlock(&fb->lock);
	if ( fb->fd != -1 ) write(fb->fd, str, strlen(str));
	return;
    }
    strl = strlen(str);
    if ( fb->buff->used + strl >= fb->buff->curr_size ) {
	b = fb->buff;
	fb->buff = alloc_buff(MAX(strl, FILEBUFFSZ));
	if ( fb->buff ) attach_data(str, strl, fb->buff);
    } else {
	attach_data(str, strl, fb->buff);
    }
    pthread_mutex_unlock(&fb->lock);
    /* place this buff to queue	*/
    if ( b != NULL ) dataq_enqueue(&fb->queue, b);
}
