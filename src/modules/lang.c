#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<stdarg.h>
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

#include	<netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include	"../oops.h"
#include	"../modules.h"

char	module_type   = MODULE_OUTPUT ;
char	module_name[] = "lang" ;
char	module_info[] = "National languages handling module" ;

static	struct charset	*charsets;
static	rwl_t		lang_config_lock;
static	int		writet_cs(int, char *, int, struct charset*, int);
static	char		default_charset[64];

static	void		recode_buff(struct buff*, struct charset*);

#define	WRLOCK_LANG_CONFIG	rwl_wrlock(&lang_config_lock)
#define	RDLOCK_LANG_CONFIG	rwl_rdlock(&lang_config_lock)
#define	UNLOCK_LANG_CONFIG	rwl_unlock(&lang_config_lock)

int
mod_load()
{
    verb_printf("Lang started\n");
    if ( charsets ) {
	free_charsets(charsets);
	charsets = NULL;
    }
    default_charset[0] = 0;
    rwl_init(&lang_config_lock);
    return(MOD_CODE_OK);
}
int
mod_unload()
{
    WRLOCK_LANG_CONFIG ;
    verb_printf("Lang stopped\n");
    return(MOD_CODE_OK);
}

int
mod_config_beg()
{
    WRLOCK_LANG_CONFIG ;
    if ( charsets ) {
	free_charsets(charsets);
	charsets = NULL;
    }
    default_charset[0] = 0;
    UNLOCK_LANG_CONFIG ;
}

int
mod_config_end()
{

}

int
mod_config(char *config)
{
char	*p = config;

    WRLOCK_LANG_CONFIG ;
    while( *p && isspace(*p) ) p++;
    if ( !strncasecmp(p, "CharsetAgent", 12) ) {
	char		*ptr, *agent, *t;
	struct	charset	*cs = NULL;

	p+=12; t = p;
	while( agent = (char*)strtok_r(t, " ", &ptr) ) {
	    t = NULL;
	    if ( !cs && !(cs = lookup_charset_by_name(charsets, agent))) {
		cs = add_new_charset(&charsets, agent);
		if ( !cs ) {
		    verb_printf("Can't create charset\n");
		    goto done;
		}
		continue;
	    }
	    if ( cs ) add_to_string_list(&cs->CharsetAgent, agent);
	}
	if ( cs ) {
	    struct string_list *list = cs->CharsetAgent;

	    while(list) {
		verb_printf("Agent: %s\n", list->string);
		list = list->next;
	    }
	}
    } else
    if ( !strncasecmp(p, "default_charset", 15) ) {
	p += 15;
	while (*p && isspace(*p) ) p++;
	strncpy(default_charset, p, sizeof(default_charset)-1);
    } else
    if ( !strncasecmp(p, "CharsetRecodeTable", 18) ) {
	char		charset[80], path[MAXPATHLEN];
	struct charset	*cs;
	FILE		*Tf;

	if ( sscanf(p+18, " %80s %128s", &charset, &path) == 2 ) {
	    verb_printf("<<recodetable for %s: %s>>\n", charset, path);
	    if ( !(cs=lookup_charset_by_name(charsets, charset)) ) {
		cs = add_new_charset(&charsets, charset);
		if ( !cs ) {
		    verb_printf("Can't create charset\n");
		    goto done;
		}
	    }
	    /* load table */
	    if ( cs->Table ) xfree(cs->Table);
	    cs->Table = malloc(128);
	    if ( cs->Table ) {
		int i;
		for(i=0;i<128;i++)
		    cs->Table[i] = i+128 ;
	    }
	    Tf = fopen(path, "r");
	    if ( Tf ) {
		int	f,t;
		while( !feof(Tf) ) {
		  char buf[80];
		    buf[0] = 0;
		    fgets(buf, sizeof(buf), Tf);
		    if ( sscanf(buf, "%x%x", &f, &t) == 2 ) {
			if ( f >= 128 ) 
			    cs->Table[((unsigned)f & 0xff)-128] = (unsigned) t;
		    }
		}
		fclose(Tf);
	    } else
		verb_printf("Can't open %s: \n", strerror(errno));
	}
    }
done:
    UNLOCK_LANG_CONFIG ;
    return(MOD_CODE_OK);
}

int
writet_cs(int so, char *buf, int size, struct charset *cs, int tmo)
{
unsigned char	*tmpb, *s, *d;
int		i;

    if ( !cs || !cs->Table ) return(writet(so, buf, size, tmo));
    tmpb = malloc(size);
    if ( !tmpb ) return(writet(so, buf, size, tmo));
    /* recode */
    for(s=(unsigned char*)buf,d=(unsigned char*)tmpb,i=0;i<size;i++,s++,d++) {
	if ( *s>=128 ) {
	    *d=cs->Table[*s-128];
	} else {
	    *d=*s;
	}
    }
    writet(so, (char*)tmpb, size, tmo);
    xfree(tmpb);
}

/* change content of object, actually not send it */
int
output(int so, struct output_object *obj, struct request *rq, int *flags)
{
char		*content_type, *agent = NULL, *p, *charset_name, *new_conttype;
struct	charset	*cs = NULL;
struct	av	*ct_av = NULL;

    if ( !rq || !obj || !obj->body || !obj->headers )
	return(MOD_CODE_OK);
    ct_av = lookup_av_by_attr(obj->headers, "Content-Type");
    if ( !ct_av )
	return(MOD_CODE_OK);
    content_type = ct_av->val;
    if ( !content_type )
	return(MOD_CODE_OK);
    p = content_type;
    while( *p && isspace(*p) ) p++;
    if ( strncasecmp(p, "text/html", 9) && strncasecmp(p, "text/plain", 10) )
	return(MOD_CODE_OK);
    /* parse parameters and return if charset is already here */
    while ( (p=strchr(p, ';')) ) {
	p++;
	while( *p && isspace(*p) ) p++;
	if ( !strncasecmp(p, "charset=", 8) )
		return(MOD_CODE_OK);
    }

    if ( rq->av_pairs ) agent = attr_value(rq->av_pairs, "User-Agent");
    if ( !agent )
	return(MOD_CODE_OK);

    RDLOCK_LANG_CONFIG ;
    if ( agent && charsets )
	cs = lookup_charset_by_Agent(charsets, agent);
    if ( cs ) charset_name = cs->Name;
	else  charset_name = default_charset;
    if ( !charset_name || !*charset_name ) {
	UNLOCK_LANG_CONFIG ;
	return(MOD_CODE_OK);
    }
    /* set up charset */
    new_conttype = malloc(10+strlen(content_type)+strlen(charset_name)+1);
    if ( new_conttype ) {
	sprintf(new_conttype,"%s; charset=%s", content_type, charset_name);
	xfree(ct_av->val);
	ct_av->val = new_conttype;
	if ( cs ) {
	    recode_buff(obj->body, cs);
	}
    }
    UNLOCK_LANG_CONFIG ;

    return(MOD_CODE_OK);
}

void
recode_buff(struct buff *buff, struct charset *cs)
{
unsigned char	*s;
int		 i;

    if ( !buff || !buff->data || !cs || !cs->Table) return;
    while(buff) {
	s = (unsigned char*)buff->data;
	for(i=0;i<buff->used;i++,s++) {
	    if ( *s >= 128 )
		*s = cs->Table[*s-128];
	}
	buff = buff->next;
    }
}
