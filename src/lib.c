/*
*/
#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<errno.h>
#include	<string.h>
#include	<strings.h>
#include	<stdarg.h>
#include	<netdb.h>
#include	<ctype.h>

#include	<sys/stat.h>
#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/socketvar.h>
#include	<sys/resource.h>

#include	<netinet/in.h>

#include	<arpa/inet.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"
#include	"modules.h"

FILE	*logf, *accesslogf;
void	flush_log();

int	readt(int, char*, int, int);
int	my_gethostbyname(char *name);
void	get_hash_stamp(char*, int*, int*);
void
my_log(char *form, ...)
{
va_list	ap;
char		ctbuf[80], *c;
time_t		now;
void		*self;

    rwl_wrlock(&log_lock);
    if ( !logf ) {
        rwl_unlock(&log_lock);
    	return;
    }
    now = time(NULL);
#if	defined(SOLARIS)
    ctime_r(&now, ctbuf, sizeof(ctbuf)-1);
#else
#if	defined(LINUX)
    ctime_r(&now, ctbuf);
#else
    sprintf(ctbuf, "%u\n", now);
#endif
#endif
    c = strchr(ctbuf, '\n');
    if ( c ) *c = ' ';
    va_start(ap, form);
    self = (void*)pthread_self();
    fprintf(logf, "%s [%p]", ctbuf, self);
    vfprintf(logf, form, ap);
    rwl_unlock(&log_lock);
    va_end(ap);
    return;
}

void
flush_log()
{
    if ( !logf ) return;
    rwl_rdlock(&log_lock);
    fseek(logf, 0, SEEK_END);
    fflush(logf);
    rwl_unlock(&log_lock);
}

void
log_access(int elapsed, struct sockaddr_in *sa, char *tag,
	int code, int size, char *meth, struct url *url, char* hierarchy,
	char *content, char *source)
{
char	*s;
    if ( !accesslogf ) return;
    pthread_mutex_lock(&accesslog_lock);
    s = my_inet_ntoa(sa);
    if ( s ) fprintf(accesslogf, "%u %d %s %s/%d %d %s %s://%s%s - %s/%s %s\n", (unsigned)time(NULL), elapsed, s,
	tag, code, size, meth, url->proto, url->host, url->path, hierarchy, source,
	content);
    pthread_mutex_unlock(&accesslog_lock);
    if ( s ) xfree(s);
}

void
do_exit(int code)
{
   flush_log();
   exit(code);
}

int
str_to_sa(char *val, struct sockaddr *sa)
{
/*	if ( inet_aton(val, &(((struct sockaddr_in*)sa)->sin_addr)) ) {*/
	if ( (((struct sockaddr_in*)sa)->sin_addr.s_addr = inet_addr(val)) != -1 ) {
		/* it is */
		struct	sockaddr_in *sin = (struct sockaddr_in*)sa;
		sin->sin_family = AF_INET;
#if	!defined(SOLARIS) && !defined(LINUX)
		sin->sin_len	= sizeof(*sin);
#endif
		return(0);
	} else {
	struct	hostent	*he;
	int		ad;
		/* try to resolve name */
		if ( ns_configured > 0 )
			ad = my_gethostbyname(val);
		    else {
			he = gethostbyname(val);
			if ( !he ) {
			    my_log("%s is not a hostname, not an IP addr\n", val);
			    return(1);
			}
			ad = (*(struct in_addr*)*he->h_addr_list).s_addr;
		}
		if ( !ad ) {
			my_log("%s is not a hostname, not an IP addr\n", val);
			return(1);
		}
		((struct sockaddr_in*)sa)->sin_addr.s_addr = ad;
		((struct sockaddr_in*)sa)->sin_family = AF_INET;
#if	!defined(SOLARIS) && !defined(LINUX)
		((struct sockaddr_in*)sa)->sin_len = sizeof(struct sockaddr_in);
#endif
	}
	return(0);
}

int
bind_server_so(int server_so)
{
int r;
    if ( !connect_from_sa_p )
	return(0);
    r = bind(server_so, (struct sockaddr*)connect_from_sa_p, sizeof(struct sockaddr_in));
    if ( r ) {
	my_log("Cant bind: %s\n", strerror(errno));
    }
    return(r);
}

u_short	q_id = 0;
int
my_gethostbyname(char *name)
{
struct	dnsqh {
	u_short		id:16;
	u_short		flags:16;
	u_short		qdcount:16;
	u_short		ancount:16;
	u_short		nscount:16;
	u_short		arcount:16;
} *qh, *ah;
u_char		dnsq[512];
u_char		dnsa[512];
u_char		compr_name[256];
int		dns_so, rq_len, r, resend_cnt, resend_tmo, gota=0;
u_short		*qdcount = (u_short*)dnsq + 2, acount;
u_char		*q_section = dnsq + 12;
struct		sockaddr_in	dns_sa;
u_char		*p, *s, *d, *t, *limit;
u_short		type, class, ttl, rdl, flags;
unsigned	result, results=0;
unsigned	answers[MAX_DNS_ANSWERS], *current=answers;
struct	in_addr	addr;
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
    if ( result = lookup_dns_cache(tmpname, NULL, 0) )
	return(result);
    bzero(answers, sizeof(answers));

    /* check if ths is full name */
    if ( !strchr(name, '.') ) {
	gethostname((char*)dnsa, sizeof(dnsa));
	t = (u_char*)strchr((char*)dnsa, '.');
	if ( t ) /* join */ {
	    strcpy((char*)compr_name, name);
	    strncat((char*)compr_name, (char*)t++, sizeof(compr_name)-strlen((char*)compr_name) -1 );
	    name=(char*)compr_name;
	}
    }
    dns_so = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( dns_so == -1 ) {
	my_log("Can't create NDS socket: %s\n", strerror(errno));
	return(0);
    }
    dns_sa.sin_family = AF_INET;
#if	!defined(SOLARIS) && !defined(LINUX)
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
    while( (p = (u_char*)strchr((char*)s, '.')) ) {
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
    resend_cnt = 5;
    resend_tmo = 1;
resend:
    r = sendto(dns_so, (char*)dnsq, rq_len, 0, (struct sockaddr*)&dns_sa, sizeof(dns_sa));
    if ( r == -1 ) {
	my_log("Can't send to DNS server: %s\n", strerror(errno));
	close(dns_so);
	return(0);
    }
    if ( (ns_configured > 1) && (wait_for_read(dns_so, 500) == FALSE) ) {
	int i;
	/* if we have another nameservers, which we can try to send rq */
	for (i=1;i<ns_configured;i++)
	    sendto(dns_so, (char*)dnsq, rq_len, 0, (struct sockaddr*)&ns_sa[i], sizeof(struct sockaddr_in));
    }
    /* wait for responce */
    r = readt(dns_so, (char*)dnsa, sizeof(dnsa), resend_tmo);resend_tmo <<= 1;
    switch(r) {
    case(-2): /* timeout */
	if (--resend_cnt) goto resend;
	break;
    case(-1): /* error 		*/
	my_log("Error reading DNS answer: %s\n", strerror(errno));
	break;
    case (0): /* ????? 		*/
	my_log("Emty DNS answer\n");
	break;
    default:  /* parse data 	*/
	ah = (struct dnsqh *)dnsa;
	flags = ntohs(ah->flags);
	acount = ntohs(ah->ancount);
	acount = MIN(acount, MAX_DNS_ANSWERS);
	limit = (u_char*)&dnsa + r;
	if ( (flags & 0x8000) && (ah->id == qh->id) && (!(flags&0xf)) ) {
	    if ( !ntohs(ah->ancount) ) break;
	} else {
	    my_log("Failed DNS answer: qid(%x)<->aid(%x), flags:%x\n", qh->id,
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
	my_log("Added %s for %s\n", inet_ntoa(addr), tmpname);
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
	int			i;

	dns_items = xmalloc(sizeof(*dns_items)*results,"dns_items");
	dns_name  = xmalloc(strlen(name)+1, "dns_name");
	if ( !dns_items || !dns_name )
	    goto dns_c_failed;
	my_log("Put %d answers in dns_cache\n", results);
	strcpy(dns_name, (char*)&tmpname[0]);
	ci = dns_items; current = answers;
	for(i=0;i<results;i++,current++,ci++) {
	    ci->time = global_sec_timer;
	    ci->good = TRUE;
	    ci->address.s_addr = *current;
	}
	if ( lookup_dns_cache(dns_name, dns_items, results) ) goto dns_c_failed;

	my_log("Done...\n");
	goto fin;

    dns_c_failed:
	if ( dns_items ) xfree(dns_items);
	if ( dns_name ) xfree(dns_name);
	goto fin;
    }
  fin:
    close(dns_so);
    addr.s_addr = answers[0];
    my_log("returned %s\n", inet_ntoa(addr));
    return(answers[0]);
}

int
lookup_dns_cache(char* name, struct dns_cache_item *items, int counter)
{
int			result = 0;
int			hash,stamp;
char			*c = name;
struct	dns_cache	*cp;
struct	dns_cache_item	*ci;
unsigned		use;

    if ( !name ) return(0);
    get_hash_stamp(name, &hash, &stamp);
    pthread_mutex_lock(&dns_cache_lock);
    cp = dns_hash[hash].first;
    while ( cp ) {
	if ( (cp->stamp == stamp) && !strcmp(name,cp->name) ) {
	    my_log("It's here\n");
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
	if ( use >= cp->nitems ) use = cp->nlast = 0;
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
    cp = xmalloc(sizeof(*cp), "dnc_cache");
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

    xdate = xmalloc(strlen(date) +1, "http_date");
    if ( !xdate )
	return(-1);
    strcpy(xdate, date);
    p = date = xdate;
    while( (s = (char*)strtok_r(p, " ", &ptr)) ) {
	p = NULL;
    parse:
	switch(field) {
	case FIELD_WDAY:
		if ( strlen(s) < 3 ) {
		    my_log("Unparsable date: %s\n", date);
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
			my_log("Unparsable date: %s\n", date);
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
		    while( *s && isdigit(*s) ) {
			t = t*10 + (*s - '0');
			s++;
		    }
		    if ( t ) mday = t;
			else {
			     my_log("Unparsable date: %s\n", date);
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
		    while( *s && isdigit(*s) ) {
			t = t*10 + (*s - '0');
			s++;
		    }
		    if ( *s ) {
			free(xdate);
			return(-1);
		    }
		    if ( t ) mday = t;
			else {
			     my_log("Unparsable date: %s\n", date);
			     free(xdate);
			     return(-1);
		    }
		    field = FIELD_TIME;
		}
		break;
	case FIELD_MONT:
		/* Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec */
		if ( strlen(s) < 3 ) {
		    my_log("Unparsable date: %s\n", date);
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
			my_log("Unparsable date: %s\n", date);
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
		year = atoi(s);
		if ( year == 0 ) {
		     my_log("Unparsable date: %s\n", date);
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
		while (*s && isdigit(*s) ) hour = hour*10 + ((*s++)-'0');
		if ( *s ) s++;
		while (*s && isdigit(*s) ) mins = mins*10 + ((*s++)-'0');
		if ( *s ) s++;
		while (*s && isdigit(*s) ) secs = secs*10 + ((*s++)-'0');
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
int		rc;
time_t		holder = time;

    gmtime_r(&holder, &tm);
    rc = strftime(buf, size, "%a, %d %b %Y %H:%M:%S GMT", &tm);
    return(rc);
}

/* accept tm for GMT, return time */
int
tm_to_time(struct tm *tm, time_t *time)
{
struct		tm ttm;

    /* mktime convert from localtime, so shift tm to localtime	*/
    memcpy(&ttm, tm, sizeof(ttm));
    ttm.tm_isdst = -1;
#if defined(SOLARIS)
    ttm.tm_sec -= timezone;
#else
#ifdef	HAVE__GMTOFF__
    ttm.tm_sec -= ttm.__tm_gmtoff__;
#else
    ttm.tm_sec -= ttm.tm_gmtoff;
#endif
#endif
    return((*time = mktime(&ttm)));
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
u_char	*s=(u_char*)src, *d;
u_char	xdig[16] = "0123456789ABCDEF";

    res = malloc(strlen(src) * 3 + 1 ); /* worst case */
    if ( !res ) return(NULL);
    d = (u_char*)res;
    while( *s ) {
	if ( *s!='/' &&
	     *s!='.' &&
	     *s!='-' &&
	     *s!='_' &&
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
u_char	*s=(u_char*)src, *d;

    res = xmalloc(strlen(src) + 1, "dehtmlize"); /* worst case */
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

#if	defined(NEED_DAEMON)
int
daemon(int nochdir, int noclose)
{
    return(0);
}
#endif

void
increase_hash_size(struct hash_entry* hash, int size)
{
int	rc; 
    if ( !hash ) {
	my_log("hash == NULL in increase_hash_size\n");
	return;
    }
    if ( size < 0 ) {
	my_log("size<=0 in increase_hash_size\n");
	exit(1);
	return;
    }
    if ( !(rc = pthread_mutex_lock(&hash->size_lock)) ) {
	hash->size += size;
	if ( hash->size < 0 ) {
    	    my_log("increase: hash_size has negative value: %d!\n", hash->size);
	    exit(1);
	}
	pthread_mutex_unlock(&hash->size_lock);
    } else {
	my_log("Can't lock hash entry for increase size\n");
    }
}

void
decrease_hash_size(struct hash_entry* hash, int size)
{
int	rc;

    if ( !hash ) {
	return;
    }
    if ( size < 0 ) {
	my_log("size<0 in decrease_hash_size\n");
	exit(1);
	return;
    }
    total_alloc -= size;
    if ( !(rc=pthread_mutex_lock(&hash->size_lock)) ) {
	hash->size -= size;
	if ( hash->size < 0 ) {
    	    my_log("decrease: hash_size has negative value: %d!\n", hash->size);
	    exit(1);
	}
	pthread_mutex_unlock(&hash->size_lock);
    } else {
	my_log("Can't lock hash entry for decrease size\n");
    }
}

void
remove_limits()
{
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
	    rl.rlim_cur = rl.rlim_max;
	    if ( !setrlimit(RLIMIT_NOFILE, &rl) ) {
		printf("RLIMIT_NOFILE changed to maximum: %u\n", (unsigned)rl.rlim_max);
	    } else {
		printf("warning: Can't change RLIMIT_NOFILE\n");
	    }
	}
#endif
#if	defined(RLIMIT_CORE)
	if ( !getrlimit(RLIMIT_CORE, &rl) ) {
	    rl.rlim_cur = 0;
	    if ( !setrlimit(RLIMIT_CORE, &rl) ) {
		printf("RLIMIT_CORE changed to minimum: %u\n", (unsigned)rl.rlim_cur);
	    } else {
		printf("warning: Can't change RLIMIT_NOFILE\n");
	    }
	}
#endif
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
	my_log("Cant rdlock\n");
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
	my_log("Cant rwlock\n");
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
struct timeval	tv;

    tv.tv_sec =  sec ;
    tv.tv_usec = 0 ;
    select(1, NULL, NULL, NULL, &tv);
}

char*
my_inet_ntoa(struct sockaddr_in * sa)
{
char * res = xmalloc(20, "my_inet_ntoa");
uint32_t	ia = ntohl(sa->sin_addr.s_addr);
uint32_t	a,b,c,d;

    if ( !res ) return(NULL);
    a =  ia >> 24;
    b = (ia & 0x00ff0000) >> 16;
    c = (ia & 0x0000ff00) >> 8;
    d = (ia & 0x000000ff);
    sprintf(res, "%d.%d.%d.%d",
	ia >> 24,
	(ia & 0x00ff0000) >> 16,
	(ia & 0x0000ff00) >> 8,
	(ia & 0x000000ff));
    return(res);
}

void
free_container(struct buff *buff)
{
struct buff *next;

    while(buff) {
	next = buff->next;
	/*my_log("Free buffer: %d of %d, next:%p\n", buff->size, buff->curr_size, buff->next);*/
	if ( buff->data ) free(buff->data);
	free(buff);
	buff = next;
    }
    
}


void
analyze_header(char *p, struct server_answ *a)
{
char	*t;
time_t	now = time(NULL);

    /*my_log("--->'%s'\n", p);*/
    if ( !a->status_code ) {
	/* check HTTP/X.X XXX */
	if ( !strncasecmp(p, "HTTP/", 5) ) {
	    t = strchr(p, ' ');
	    if ( !t ) {
		my_log("Wrong_header: %s\n", p);
		return;
	    }
	    a->status_code = atoi(t);
	/*    my_log("Status code: %d\n", a->status_code);*/
	}
	return;
    }
    if ( !strncasecmp(p, "Content-length: ", 16) ) {
	char        *x;
	/* length */
	x=p + 16; /* strlen("content-length: ") */
	while( *x && isspace(*x) ) x++;
	a->content_len = atoi(x);
	return;
    }
    if ( !strncasecmp(p, "Date: ", 6) ) {
	char        *x;
	/* length */
	x=p + 6; /* strlen("date: ") */
	while( *x && isspace(*x) ) x++;
	a->times.date = now;
	if (http_date(x, &a->times.date) ) my_log("Can't parse date: %s\n", x);
	return;
    }
    if ( !strncasecmp(p, "Last-Modified: ", 15) ) {
	char        *x;
	/* length */
	x=p + 15; /* strlen("date: ") */
	while( *x && isspace(*x) ) x++;
	if (http_date(x, &a->times.last_modified) ) my_log("Can't parse date: %s\n", x);
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
	while( *x && isspace(*x) ) x++;
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
    if ( !strncasecmp(p, "Expires: ", 9) ) {
	char        *x;
	/* length */
	x=p + 9; /* strlen("Expires: ") */
	while( *x && isspace(*x) ) x++;
	a->times.expires = now;
	if (http_date(x, &a->times.expires)) {
		my_log("Can't parse date: %s\n", x);
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
char		*new_attr, *new_val;

    new = xmalloc(sizeof(*new), "for av pair");
    if ( !new ) goto failed;
    bzero(new, sizeof(*new));
    new_attr=xmalloc( strlen(attr)+1, "for new_attr" );
    if ( !new_attr ) goto failed;
    strcpy(new_attr, attr);
    new_val=xmalloc( strlen(val)+1, "for new_val" );
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
struct	av	*new=NULL, *next;
char		*attr=avtext, *sp=avtext, *val,holder;
char		*new_attr=NULL, *new_val=NULL;

    while( *sp && !isspace(*sp) && (*sp != ':') ) sp++;
    if ( !*sp ) {
	my_log("Invalid header string: %s\n", avtext);
	return(-1);
    }
    if ( *sp ==':' ) sp++;
    holder = *sp;
    *sp = 0;
    new = xmalloc(sizeof(*new), "for av pair");
    if ( !new ) goto failed;
    new_attr=xmalloc( strlen(attr)+1, "for new_attr" );
    if ( !new_attr ) goto failed;
    strcpy(new_attr, attr);
    *sp = holder;
    val = sp; while( *val && isspace(*val) ) val++;
    /*if ( !*val ) goto failed;*/
    new_val = xmalloc( strlen(val) + 1, "for val");
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
check_server_headers(struct server_answ *a, struct mem_obj *obj, struct buff *b)
{
char	*start, *beg, *end, *p;
char	holder, its_here=0, off;
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
	struct buff	*new = NULL, *old = NULL, *body;
	int		all_siz;

	a->state |= GOT_HDR ;
	obj->content_length = a->content_len;
	b->used = ( start + off ) - beg;	/* trunc first buf to header siz	*/
	if ( end - start - off >= CHUNK_SIZE ){	/* it is worth to realloc buff with	*/
					     	/* header to smaller			*/
	    new = alloc_buff(b->used);
	    if ( new ) {
		memcpy(new->data, b->data, b->used);
		new->used = b->used;
		old = b;
		obj->container = b = new;
	    } else {
		my_log("Cannot allocate mem for container\n");
		return(-1);
	    }
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
	    if ( old ) {
		if (old->data) free(old->data);
		free(old);
	    }
	    return(-1);
	}
	b->next = body;
	obj->hot_buff = body;
	attach_data(start+off, end-start-off, obj->hot_buff);
	if ( old ) {
	    if (old->data) free(old->data);
	    free(old);
	}
	return(0);
    }
    p = start;
    while( (p < end) && ( *p == '\r' || *p == '\n' ) ) p++;
    if ( p < end && *p ) {
	char *t = memchr(p, '\n', end-p);
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
	analyze_header(p, a);
	if ( add_header_av(p, obj) ) {
	    return(-1);
	}
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
    t = xmalloc(sizeof(struct buff), "alloc_buff1");
    if ( !t ) return(NULL);
    bzero(t, sizeof(struct buff));
    d = xmalloc(size, "alloc_buff2");
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

    if (!hot) return(-1);
    if ( size < 0 ) return(-1);
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



/* concatenate bata in continuous buffer */
int
attach_data(char* src, int size, struct buff *buff)
{
char	*t;
int	tot;

    if ( size <= 0 ) return(-1);
    if ( !buff->data ) {
	t = xmalloc(((size / CHUNK_SIZE) + 1) * CHUNK_SIZE, "attach_data1");
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
	t = xmalloc(tot, "attach_data2");
	if (!t ) {
	    my_log("No mem in attach data\n");
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
	    if ( *x     != 'd' ) {my_log("cb, Destroyed: '%s'\n",buf->data); do_exit(0);}
	    if ( *(x+1) != 'e' ) {my_log("cb,Destroyed: '%s'\n",buf->data); do_exit(0);}
	    if ( *(x+2) != 'a' ) {my_log("cb,Destroyed: '%s'\n",buf->data); do_exit(0);}
	    if ( *(x+3) != 'd' ) {my_log("cb,Destroyed: '%s'\n",buf->data); do_exit(0);}
	    my_log("Busy block: %s\n", buf->descr);
	    if (!strcmp(buf->descr, "string"))
		my_log("<%s>\n", buf->data);
	} else {
	    int i = buf->size;
	    x=buf->data;
	    for(;i;i--,x++) if (*x) {
		my_log("free buffer '%s' destroyed\n", buf->descr);
		do_exit(0);
	    };
	}
	buf=buf->next;
    }
    my_log("Total bufs: %d\n", num);
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
	    if ( *x     != 'd' ) {my_log("cb, Destroyed: '%s'\n",buf->data); do_exit(0);}
	    if ( *(x+1) != 'e' ) {my_log("cb,Destroyed: '%s'\n",buf->data); do_exit(0);}
	    if ( *(x+2) != 'a' ) {my_log("cb,Destroyed: '%s'\n",buf->data); do_exit(0);}
	    if ( *(x+3) != 'd' ) {my_log("cb,Destroyed: '%s'\n",buf->data); do_exit(0);}
	} else {
	    int i = buf->size;
	    x=buf->data;
	    for(;i;i--,x++) if (*x) {
		my_log("free buffer '%s' destroyed\n", buf->descr);
		do_exit(0);
	    };
	}
	buf=buf->next;
    }
}
#endif

void*
xmalloc(size_t	size, char *d)
{
#if	!defined(MALLOCDEBUG)
char	*p;

	if ( size < 0 ) {
	    my_log("Alloc %d for %s\n", size, d);
	    exit(1);
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
	my_log("Invalid malloc call\n");
    }
    my_log("xmalloc: %d for %s\n", size, d);
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
		my_log("free buffer '%s' destroyed\n", buf->descr);
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
	my_log("returning old %p\n", buf->data);
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
	my_log("returning new %p\n", buf->data);
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
    printf("free %p\n", ptr);
    while(buf) {
	if ( buf->data == ptr ) {
	    my_log("free %s\n", buf->descr);
	    x = buf->data + buf->current_size;
	    if ( *x     != 'd' ) {my_log("Destroyed: %s\n",buf->data); do_exit(0);}
	    if ( *(x+1) != 'e' ) {my_log("Destroyed: %s\n",buf->data); do_exit(0);}
	    if ( *(x+2) != 'a' ) {my_log("Destroyed: %s\n",buf->data); do_exit(0);}
	    if ( *(x+3) != 'd' ) {my_log("Destroyed: %s\n",buf->data); do_exit(0);}
	    buf->state= BU_FREE;
	    bzero(buf->data, buf->size);
	    printf("freed %p %d bytes\n", buf->data, buf->size);
	    pthread_mutex_unlock(&malloc_mutex);
	    return;
	}
	buf=buf->next;
    }
    printf("Freeing not allocated\n");
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

    my_log("Looking up mimetype for %s\n", path);
    /* extract ext from path */
    ext = strrchr(path, '.');
    if ( ext ) ext++;
    if ( ext && *ext ) while ( mt->ext ) {
	if ( !strcasecmp(ext,mt->ext) ) {
	    my_log("type: %s\n", mt->type);
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

    res = xmalloc((len*4)/3+4, "b64e");
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
	}
    }
    return(res);
}
char *
base64_decode(char *p)
{
char *result;
int j;
unsigned int k;
int c, base_result_sz;
long val;

    if (!p)
	return NULL;

    base_result_sz = strlen(p);
    result = xmalloc(base_result_sz+1,"");

    val = c = 0;
    for (j = 0; *p && j + 3 < base_result_sz; p++) {
	k = (int) *p % BASE64_VALUE_SZ;
	if (base64_value[k] < 0)
	    continue;
	val <<= 6;
	val += base64_value[k];
	if (++c < 4)
	    continue;
	result[j++] = val >> 16;
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

    result = xmalloc(sizeof(*result), "new charset");
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
}
free_output_obj(struct output_object *obj)
{
struct	av	*headers, *next_av;
struct	buff	*body, *next_b;

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
int		rc = 0,r, sended, ssended, to_send, send_hot_pos;
struct	av	*av;
struct	timeval	tv;
struct	buff	*send_hot_buff;
fd_set		wset;

#ifdef	MODULES
int	mod_flags = 0;

    if ( !obj || !rq ) return;
    rc = check_output_mods(so, obj, rq, &mod_flags);
    if ( (rc != MOD_CODE_OK) || TEST(mod_flags, MOD_AFLAG_OUT) )
	return ;
#endif

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
send_it:;
    FD_ZERO(&wset);
    FD_SET(so, &wset);
    tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
    r = select(so+1, NULL, &wset, NULL, &tv);
    if ( r <= 0 ) goto done;
    ssended = sended;
    if ( send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, NULL, 0) )
	goto done;
    if ( rq->flags & RQ_HAS_BANDWIDTH) update_transfer_rate(rq, sended-ssended);
    if ( sended >= obj->body->used )
	goto done;
    goto send_it;
done:;

    return;
}
