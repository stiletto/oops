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

#define	MODULE_NAME	"lang"
#define	MODULE_INFO	"National languages handling module"

#if	defined(MODULES)
char		module_type   = MODULE_OUTPUT ;
char		module_name[] = MODULE_NAME ;
char		module_info[] = MODULE_INFO ;
int		mod_load(void);
int		mod_unload(void);
int		mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run(void);
int		output(int so, struct output_object *obj, struct request *rq, int *flags);
int		compare_u_agents(char*, char*);
#define		MODULE_STATIC
#else
static	char	module_type   = MODULE_OUTPUT ;
static	char	module_name[] = MODULE_NAME ;
static	char	module_info[] = MODULE_INFO ;
static	int	mod_load(void);
static	int	mod_unload(void);
static	int	mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run(void);
static	int	output(int so, struct output_object *obj, struct request *rq, int *flags);
static	int	compare_u_agents(char*, char*);
#define		MODULE_STATIC	static
#endif

struct	output_module lang = {
	{
	NULL, NULL,
	MODULE_NAME,
	mod_load,
	mod_unload,
	mod_config_beg,
	mod_config_end,
	mod_config,
	NULL,
	MODULE_OUTPUT,
	MODULE_INFO,
	mod_run
	},
	output,
	compare_u_agents
};

static	pthread_rwlock_t	lang_config_lock;
static	char			default_charset[64];

static	void		recode_buff(struct buff*, struct charset*);

#define	WRLOCK_LANG_CONFIG	pthread_rwlock_wrlock(&lang_config_lock)
#define	RDLOCK_LANG_CONFIG	pthread_rwlock_rdlock(&lang_config_lock)
#define	UNLOCK_LANG_CONFIG	pthread_rwlock_unlock(&lang_config_lock)

MODULE_STATIC
int
mod_run(void)
{
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_load(void)
{
    if ( charsets ) {
	free_charsets(charsets);
	charsets = NULL;
    }
    default_charset[0] = 0;
    pthread_rwlock_init(&lang_config_lock, NULL);

    printf("Lang started\n");

    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_unload(void)
{
    WRLOCK_LANG_CONFIG ;
    verb_printf("Lang stopped\n");
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_beg(int i)
{
    WRLOCK_LANG_CONFIG ;
    if ( charsets ) {
	free_charsets(charsets);
	charsets = NULL;
    }
    default_charset[0] = 0;
    UNLOCK_LANG_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_end(int i)
{
charset_t	*cs;

    WRLOCK_LANG_CONFIG ;
    if ( default_charset[0]
      && (cs = add_new_charset(&charsets, default_charset)) ) {

	cs->Table = malloc(128);
	if ( cs->Table ) {
	    int i;
	    for(i=0;i<128;i++)
		cs->Table[i] = i+128;
	}
    }
    UNLOCK_LANG_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config(char *config, int i)
{
char	*p = config;

    WRLOCK_LANG_CONFIG ;
    while( *p && IS_SPACE(*p) ) p++;
    if ( !strncasecmp(p, "CharsetAgent", 12) ) {
	char		*ptr, *agent, *t;
	struct	charset	*cs = NULL;

	p+=12; t = p;
	while( (agent = (char*)strtok_r(t, " ", &ptr)) ) {
	    /* t is not NULL only on first item which must be charset name. 	*/
	    /* there was when we add charset name as agentname on second string	*/
	    /* Fixed by Peter S. Voronov					*/
	    if ( t && !cs && !(cs = lookup_charset_by_name(charsets, agent))) {
		cs = add_new_charset(&charsets, agent);
		if ( !cs ) {
		    verb_printf("Can't create charset\n");
		    goto done;
		}
		t = NULL ;
		continue;
	    }
	    if ( cs && !t) add_to_string_list(&cs->CharsetAgent, agent);
	    t = NULL ;
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
	while (*p && IS_SPACE(*p) ) p++;
	strncpy(default_charset, p, sizeof(default_charset)-1);
    } else
    if ( !strncasecmp(p, "CharsetRecodeTable", 18) ) {
	char		charset[80], path[MAXPATHLEN];
	struct charset	*cs;
	FILE		*Tf;

	if ( sscanf(p+18, " %80s %128s", (char*)&charset, (char*)&path) == 2 ) {
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
		int	f, t;
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
		verb_printf("Can't open %m: \n");
	}
    }
done:
    UNLOCK_LANG_CONFIG ;
    return(MOD_CODE_OK);
}

/* change content of object, actually not send it */
MODULE_STATIC
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
    while( *p && IS_SPACE(*p) ) p++;
    if ( strncasecmp(p, "text/html", 9) && strncasecmp(p, "text/plain", 10) )
	return(MOD_CODE_OK);
    /* parse parameters and return if charset is already here */
    while ( (p = strchr(p, ';')) ) {
	p++;
	while( *p && IS_SPACE(*p) ) p++;
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

MODULE_STATIC
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

MODULE_STATIC
int
compare_u_agents(char *a1, char *a2)
{
int	res = TRUE;

    if ( !a1 || !a2 ) return(TRUE);
    RDLOCK_LANG_CONFIG ;
    if ( !charsets )
	goto done;
    if ( lookup_charset_by_Agent(charsets, a1) != lookup_charset_by_Agent(charsets, a2) )
	res = FALSE;
 done:
    UNLOCK_LANG_CONFIG ;
    return(res);
}
