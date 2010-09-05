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

#define	ACTION_IGNORE		1
#define	ACTION_BYCHARSET	2

struct	header_action {
	struct	header_action	*next;
	char			*header;
	int			action;
	char			*data;
};

struct	header_action	*actions = NULL;
struct	header_action	*default_action = NULL;

#define	MODULE_NAME	"vary"
#define	MODULE_INFO	"Processing \'Vary:\' header"

#if	defined(MODULES)
char		module_type   = MODULE_HEADERS ;
char		module_name[] = MODULE_NAME ;
char		module_info[] = MODULE_INFO ;
int		mod_load();
int		mod_unload();
int		mod_config_beg(), mod_config_end(), mod_config(), mod_run();
int		match_headers(struct mem_obj *obj, struct request *rq, int *flags);
#else
static	char	module_type   = MODULE_HEADERS ;
static	char	module_name[] = MODULE_NAME ;
static	char	module_info[] = MODULE_INFO ;
static  int     mod_load();
static  int     mod_unload();
static  int     mod_config_beg(), mod_config_end(), mod_config(), mod_run();
static	int	match_headers(struct mem_obj *obj, struct request *rq, int *flags);
#endif

struct	headers_module	vary_header = {
	{
	NULL, NULL,
	MODULE_NAME,
	mod_load,
	mod_unload,
	mod_config_beg,
	mod_config_end,
	mod_config,
	NULL,
	MODULE_HEADERS,
	MODULE_INFO,
	mod_run
	},
	match_headers
};

#define	WRLOCK_VARY_CONFIG	rwl_wrlock(&vary_config_lock)
#define	RDLOCK_VARY_CONFIG	rwl_rdlock(&vary_config_lock)
#define	UNLOCK_VARY_CONFIG	rwl_unlock(&vary_config_lock)

rwl_t	vary_config_lock;

void	free_action(struct header_action*);

int
mod_run()
{
    return(MOD_CODE_OK);
}

int
mod_load()
{
    printf("Vary: started\n");
    rwl_init(&vary_config_lock);
    actions = NULL;
    return(MOD_CODE_OK);
}
int
mod_unload()
{
    WRLOCK_VARY_CONFIG ;
    printf("Vary: stopped\n");
    return(MOD_CODE_OK);
}

void
free_act_list(struct header_action *act)
{
struct	header_action	*a, *n;

    a = act;
    while ( a ) {
	n = a->next;
	free_action(a);
	a = n;
    }
}

int
mod_config_beg()
{
    WRLOCK_VARY_CONFIG ;
    if ( actions ) {
	free_act_list(actions);
	actions = NULL;
    }
    if ( default_action ) {
	free_act_list(default_action);
	default_action = NULL;
    }
    UNLOCK_VARY_CONFIG ;
    return(MOD_CODE_OK);
}

int
mod_config_end()
{

    WRLOCK_VARY_CONFIG ;
    UNLOCK_VARY_CONFIG ;
    return(MOD_CODE_OK);
}

int
mod_config(char *config)
{
char			*p = config, *header, *action, act = 0;
struct	header_action	*new;

    WRLOCK_VARY_CONFIG ;

    while( *p && IS_SPACE(*p) ) p++;
    /* first field must be header name */
    header = p;
    while ( *p && !IS_SPACE(*p) ) p++;
    if ( *p ) {
	*p = 0;
	verb_printf("header: `%s'.\n", header);
	/* now we must have action */
	p++;
	while( *p && IS_SPACE(*p) ) p++;
	action = p;
	verb_printf("action: `%s'.\n", action);
	if ( *p ) {
	    if ( !strcasecmp(action, "ignore") )
		act = ACTION_IGNORE;
	    else
	    if ( !strcasecmp(action, "by_charset") )
		act = ACTION_BYCHARSET;
	    else
		printf("mod_vary: Unknown action: %s\n", action);
	}
	if ( act ) {
	    new = malloc(sizeof(*new));
	    if ( new ) {
		bzero(new, sizeof(*new));
		new->header = malloc(strlen(header)+2);
		if ( new->header ) sprintf(new->header, "%s:", header);
		new->action = act;
		if ( !strcmp(header, "*") ) {
		    /* insert default action */
		    if ( default_action ) free_act_list(default_action);
		    default_action = new;
		} else {
		    new->next = actions;
		    actions = new;
		}
	    }
	}
    }
    UNLOCK_VARY_CONFIG ;
    return(MOD_CODE_OK);
}


/* if we don't have header in request - don't match
	(except if there was ho such header in old request)
   if we have header and it is not match rules - don't match
*/

int
match_headers(struct mem_obj *obj, struct request *rq, int *flags)
{
struct	header_action	*curr = actions;
char			*old_value = NULL, *req_value = NULL;
int			matched = TRUE, agents_equal;

    RDLOCK_VARY_CONFIG ;

    while ( curr ) {

	if ( curr->action == ACTION_IGNORE ) {
	    curr = curr->next;
	    continue;
	}

	/* if object have this header saved from prev.request - fetch it */
	old_value = fetch_internal_rq_header(obj, curr->header);
	req_value = attr_value(rq->av_pairs, curr->header);
	if ( !req_value && old_value) /* ho such header in request */ {
	    matched = FALSE;
	    break;
	}
	if ( !old_value ) {
	    curr = curr->next;
	    continue;
	}
	switch ( curr->action ) {
	case(ACTION_BYCHARSET):
		agents_equal = Compare_Agents(old_value, req_value);
		if ( !agents_equal ) {
		    matched = FALSE;
		    break;
		}
		break;
	default:
		break;
	}
	curr = curr->next;
    }

    UNLOCK_VARY_CONFIG ;
    if ( matched )
	return(MOD_CODE_OK);
    return(MOD_CODE_ERR);
}

void
free_action(struct header_action *a)
{
    if ( a->data ) free(a->data);
    if ( a->header ) free(a->header);
    free(a);
}
