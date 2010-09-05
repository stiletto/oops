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


#ifdef	MODULES

#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<stdarg.h>
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

#include <dlfcn.h>
#include <glob.h>

#include "oops.h"
#include "modules.h"

struct	log_module		*log_first = NULL;
struct	err_module		*err_first = NULL;
struct	auth_module		*auth_first = NULL;
struct	output_module		*output_first = NULL;
struct	redir_module		*redir_first = NULL;
struct	listener_module		*listener_first = NULL;
struct	headers_module		*headers_first = NULL;
struct	pre_body_module		*pre_body_first = NULL;

struct	output_module		*lang_mod = NULL;

void	insert_module(struct general_module*, struct general_module**);

struct	general_module *
module_by_name(char *name)
{
struct general_module	*res;
    res = (struct general_module*)log_first;
    while( res ) {
	if ( !strcasecmp(res->name, name) )
	    return(res);
	res = res->next;
    }
    res = (struct general_module*)err_first;
    while( res ) {
	if ( !strcasecmp(res->name, name) )
	    return(res);
	res = res->next;
    }
    res = (struct general_module*)auth_first;
    while( res ) {
	if ( !strcasecmp(res->name, name) )
	    return(res);
	res = res->next;
    }
    res = (struct general_module*)redir_first;
    while( res ) {
	if ( !strcasecmp(res->name, name) )
	    return(res);
	res = res->next;
    }
    res = (struct general_module*)output_first;
    while( res ) {
	if ( !strcasecmp(res->name, name) )
	    return(res);
	res = res->next;
    }
    res = (struct general_module*)listener_first;
    while( res ) {
	if ( !strcasecmp(res->name, name) )
	    return(res);
	res = res->next;
    }
    res = (struct general_module*)headers_first;
    while( res ) {
	if ( !strcasecmp(res->name, name) )
	    return(res);
	res = res->next;
    }
    res = (struct general_module*)pre_body_first;
    while( res ) {
	if ( !strcasecmp(res->name, name) )
	    return(res);
	res = res->next;
    }
    return(res);
}

struct	auth_module *
auth_module_by_name(char *name)
{
struct general_module	*res;
    res = (struct general_module*)auth_first;
    while( res ) {
	if ( !strcasecmp(res->name, name) )
	    return((struct auth_module*)res);
	res = res->next;
    }
    return((struct auth_module*)res);
}

struct	redir_module *
redir_module_by_name(char *name)
{
struct general_module	*res;
    res = (struct general_module*)redir_first;
    while( res ) {
	if ( !strcasecmp(res->name, name) )
	    return((struct redir_module*)res);
	res = res->next;
    }
    return((struct redir_module*)res);
}

int
check_auth(int so, struct request *rq, struct group *group, int *flag)
{
int			rc = MOD_CODE_OK;
struct	auth_module	*module;
struct	l_string_list	*gr_mods = group->auth_mods;
struct	string_list	*mod_list = NULL;

    if ( gr_mods ) mod_list = gr_mods->list;

    while( mod_list && (rc == MOD_CODE_OK) ) {
	module = NULL;
	if ( mod_list->string ) module = auth_module_by_name(mod_list->string);
	if ( module && module->auth ) {
	    rc = module->auth(so, group, rq, flag);
	}
	mod_list = mod_list->next;
    }
    return(rc);
}

int
check_redirect(int so, struct request *rq, struct group *group, int *flag)
{
int			rc = MOD_CODE_OK;
struct	redir_module	*module;
struct	l_string_list	*gr_mods = group->redir_mods;
struct	string_list	*mod_list = NULL;

    if ( gr_mods ) mod_list = gr_mods->list;
     
    if ( flag ) *flag = 0;
    while( mod_list && (rc == MOD_CODE_OK) ) {
	module = NULL;
	if ( mod_list->string ) module = redir_module_by_name(mod_list->string);
	if ( module && module->redir ) {
	    rc = module->redir(so, group, rq, flag);
	}
	if ( flag && TEST(*flag, (MOD_AFLAG_BRK|MOD_AFLAG_OUT)) )
	    return(MOD_CODE_ERR);
	mod_list = mod_list->next;
    }
    return(rc);
}

int
check_redir_connect(int *so, struct request *rq, int *flag)
{
int			rc = MOD_CODE_OK;
struct	redir_module	*module;
struct	l_string_list	*gr_mods = rq->redir_mods;
struct	string_list	*mod_list = NULL;

    if ( gr_mods ) mod_list = gr_mods->list;
     
    if ( !so ) return(rc);
    if ( flag ) *flag = 0;
    *so = -1;
    while( mod_list && (rc == MOD_CODE_OK) && (*so == -1) ) {
	module = NULL;
	if ( mod_list->string ) module = redir_module_by_name(mod_list->string);
	if ( module && module->redir_connect ) {
	    rc = module->redir_connect(so, rq, flag);
	}
	if ( flag && TEST(*flag, (MOD_AFLAG_BRK|MOD_AFLAG_OUT)) )
	    return(MOD_CODE_ERR);
	mod_list = mod_list->next;
    }
    return(rc);
}

int
do_redir_rewrite_header(char **hdr, struct request *rq, int *flag)
{
int			rc = MOD_CODE_OK;
struct	redir_module	*module;
struct	l_string_list	*gr_mods;
struct	string_list	*mod_list = NULL;

    if ( !rq ) return(rc);
    if ( flag ) *flag = 0;
    gr_mods = rq->redir_mods;
    if ( gr_mods ) mod_list = gr_mods->list;

    while( mod_list && (rc == MOD_CODE_OK) ) {
	module = NULL;
	if ( mod_list->string ) module = redir_module_by_name(mod_list->string);
	if ( module && module->redir_rewrite_header ) {
	    rc = module->redir_rewrite_header(hdr, rq, flag);
	}
	if ( flag && TEST(*flag, (MOD_AFLAG_BRK|MOD_AFLAG_OUT)) )
	    return(MOD_CODE_ERR);
	mod_list = mod_list->next;
    }
    return(rc);
}

int
check_headers_match(struct mem_obj *obj, struct request *rq, int *flags)
{
int			rc = MOD_CODE_OK;
struct headers_module	*mod = headers_first;

    if ( flags ) *flags = 0;
    while ( mod && (rc == MOD_CODE_OK) ) {
	if ( mod->match_headers ) rc = mod->match_headers(obj, rq, flags);
	mod = (struct headers_module*) mod->general.next;
    }
    return(rc);
}

int
pre_body(int so, struct mem_obj *obj, struct request *rq, int *flags)
{
int			rc = MOD_CODE_OK;
struct pre_body_module	*mod = pre_body_first;

    if ( flags ) *flags = 0;
    while ( mod && (rc == MOD_CODE_OK) ) {
	if ( mod->pre_body ) rc = mod->pre_body(so, obj, rq, flags);
	mod = (struct pre_body_module*) mod->general.next;
    }
    return(rc);
}

int
load_modules()
{
void			*modh;
char			*mod_type, *mod_info, **paths, *module_path;
glob_t			globbuf;
int			gc, rc;
char			modules_path[MAXPATHLEN+1];
char			glob_mask[MAXPATHLEN+1];
struct	stat		statb;
struct	log_module	*log_module;
struct	err_module	*err_module;
struct	auth_module	*auth_module;
struct	redir_module	*redir_module;
struct	output_module	*output_module;
struct	listener_module	*listener_module;
struct	headers_module	*headers_module;
struct	pre_body_module	*pre_body_module;

char			*nptr;

    sprintf(modules_path, "./modules");
    rc = stat(modules_path, &statb);
    if ( !rc && TEST(statb.st_mode, S_IFDIR) )
	goto load_mods;
    else
	sprintf(modules_path, "%s/modules", OOPS_HOME);
load_mods:
    printf("Loading modules from %s\n", modules_path);
    sprintf(glob_mask, "%s/*.so", modules_path);
    global_mod_chain = NULL;
    bzero(&globbuf, sizeof(globbuf));
    if ( glob(glob_mask, 0, NULL, &globbuf) ) {
	printf("can't glob on %s\n", modules_path);
	return(1);
    }
    for( gc = globbuf.gl_pathc, paths=globbuf.gl_pathv; gc;gc--,paths++) {
	module_path = *paths;
	printf("Loading module %s\n", module_path);
	modh = dlopen(module_path, RTLD_NOW);
	if ( modh ) {
	    mod_type = (char*)dlsym(modh, "module_type");
	    mod_info = (char*)dlsym(modh, "module_info");
	    if (mod_info) printf("Module: %s ", mod_info);
	    switch(*mod_type) {
	      case MODULE_LOG:
		printf("(Logger)\n");
		/* allocate module structure */
		log_module = (struct log_module*)xmalloc(sizeof(*log_module), "for log_module");
		if ( !log_module ) {
		    dlclose(modh);
		}
		bzero(log_module, sizeof(*log_module));
		log_module->general.handle = modh;
		log_module->general.load   = (mod_load_t*)dlsym(modh, "mod_load");
		log_module->general.unload = (mod_load_t*)dlsym(modh, "mod_unload");
		log_module->general.config = (mod_load_t*)dlsym(modh, "mod_config");
		log_module->general.config_beg = (mod_load_t*)dlsym(modh, "mod_config_beg");
		log_module->general.config_end = (mod_load_t*)dlsym(modh, "mod_config_end");
		nptr = (char*)dlsym(modh, "module_name");
		*MOD_NAME(log_module) = 0;
		if ( nptr )
		    strncpy(MOD_NAME(log_module), nptr, MODNAMELEN-1);
		if ( mod_info )
		    strncpy(MOD_INFO(log_module), mod_info, MODINFOLEN-1);
		  else
		    MOD_INFO(log_module)[0] = 0;
		if ( log_module->general.load )
			(*log_module->general.load)();
		log_module->general.type = MODULE_LOG;
		insert_module((struct general_module*)log_module,
			      (struct general_module**)&log_first);
		break;
	      case MODULE_ERR:
		printf("(Error handling)\n");
		/* allocate module structure */
		err_module = (struct err_module*)xmalloc(sizeof(*err_module), "for err_module");
		if ( !err_module ) {
		    dlclose(modh);
		}
		bzero(err_module, sizeof(*err_module));
		MOD_HANDLE(err_module) = modh;
		MOD_LOAD(err_module)   = (mod_load_t*)dlsym(modh, "mod_load");
		MOD_UNLOAD(err_module) = (mod_load_t*)dlsym(modh, "mod_unload");
		MOD_CONFIG(err_module) = (mod_load_t*)dlsym(modh, "mod_config");
		MOD_CONFIG_BEG(err_module) = (mod_load_t*)dlsym(modh, "mod_config_beg");
		MOD_CONFIG_END(err_module) = (mod_load_t*)dlsym(modh, "mod_config_end");
		*MOD_NAME(err_module) = 0;
		nptr = (char*)dlsym(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(err_module), nptr, MODNAMELEN-1);
		if ( mod_info )
		    strncpy(MOD_INFO(err_module), mod_info, MODINFOLEN-1);
		  else
		    MOD_INFO(err_module)[0] = 0;

		err_module->err	   = (mod_load_t*)dlsym(modh, "err");
		if ( MOD_LOAD(err_module) )
			(*MOD_LOAD(err_module))();
		err_module->general.type = MODULE_ERR;
		insert_module((struct general_module*)err_module,
			      (struct general_module**)&err_first);
		break;
	      case MODULE_AUTH:
		printf("(Auth module)\n");
		/* allocate module structure */
		auth_module = (struct auth_module*)xmalloc(sizeof(*auth_module), "for auth_module");
		if ( !auth_module ) {
		    dlclose(modh);
		}
		bzero(auth_module, sizeof(*auth_module));
		MOD_HANDLE(auth_module) = modh;
		MOD_LOAD(auth_module)   = (mod_load_t*)dlsym(modh, "mod_load");
		MOD_UNLOAD(auth_module) = (mod_load_t*)dlsym(modh, "mod_unload");
		MOD_CONFIG(auth_module) = (mod_load_t*)dlsym(modh, "mod_config");
		MOD_CONFIG_BEG(auth_module) = (mod_load_t*)dlsym(modh, "mod_config_beg");
		MOD_CONFIG_END(auth_module) = (mod_load_t*)dlsym(modh, "mod_config_end");
		*MOD_NAME(auth_module) = 0;
		nptr = (char*)dlsym(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(auth_module), nptr, MODNAMELEN-1);
		if ( mod_info )
		    strncpy(MOD_INFO(auth_module), mod_info, MODINFOLEN-1);
		  else
		    MOD_INFO(auth_module)[0] = 0;

		auth_module->auth = (mod_load_t*)dlsym(modh, "auth");
		if ( MOD_LOAD(auth_module) )
			(*MOD_LOAD(auth_module))();
		auth_module->general.type = MODULE_AUTH;
		insert_module((struct general_module*)auth_module,
			      (struct general_module**)&auth_first);
		break;
	      case MODULE_REDIR:
		printf("(Redirect module)\n");
		/* allocate module structure */
		redir_module = (struct redir_module*)xmalloc(sizeof(*redir_module), "for redir_module");
		if ( !redir_module ) {
		    dlclose(modh);
		}
		bzero(redir_module, sizeof(*redir_module));
		MOD_HANDLE(redir_module) = modh;
		MOD_LOAD(redir_module)   = (mod_load_t*)dlsym(modh, "mod_load");
		MOD_UNLOAD(redir_module) = (mod_load_t*)dlsym(modh, "mod_unload");
		MOD_CONFIG(redir_module) = (mod_load_t*)dlsym(modh, "mod_config");
		MOD_CONFIG_BEG(redir_module) = (mod_load_t*)dlsym(modh, "mod_config_beg");
		MOD_CONFIG_END(redir_module) = (mod_load_t*)dlsym(modh, "mod_config_end");
		*MOD_NAME(redir_module) = 0;
		nptr = (char*)dlsym(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(redir_module), nptr, MODNAMELEN-1);
		if ( mod_info )
		    strncpy(MOD_INFO(redir_module), mod_info, MODINFOLEN-1);
		  else
		    MOD_INFO(redir_module)[0] = 0;

		redir_module->redir = (mod_load_t*)dlsym(modh, "redir");
		redir_module->redir_connect = (mod_load_t*)dlsym(modh, "redir_connect");
		redir_module->redir_rewrite_header = (mod_load_t*)dlsym(modh, "redir_rewrite_header");
		if ( MOD_LOAD(redir_module) )
			(*MOD_LOAD(redir_module))();
		redir_module->general.type = MODULE_REDIR;
		insert_module((struct general_module*)redir_module,
			      (struct general_module**)&redir_first);
		break;
	      case MODULE_OUTPUT:
		printf("(Output module)\n");
		/* allocate module structure */
		output_module = (struct output_module*)xmalloc(sizeof(*output_module), "for output_module");
		if ( !output_module ) {
		    dlclose(modh);
		}
		bzero(output_module, sizeof(*output_module));
		MOD_HANDLE(output_module) = modh;
		MOD_LOAD(output_module)   = (mod_load_t*)dlsym(modh, "mod_load");
		MOD_UNLOAD(output_module) = (mod_load_t*)dlsym(modh, "mod_unload");
		MOD_CONFIG(output_module) = (mod_load_t*)dlsym(modh, "mod_config");
		MOD_CONFIG_BEG(output_module) = (mod_load_t*)dlsym(modh, "mod_config_beg");
		MOD_CONFIG_END(output_module) = (mod_load_t*)dlsym(modh, "mod_config_end");
		*MOD_NAME(output_module) = 0;
		nptr = (char*)dlsym(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(output_module), nptr, MODNAMELEN-1);

		output_module->output = (mod_load_t*)dlsym(modh, "output");
		output_module->compare_u_agents = /* for lang only */
		    (mod_load_t*)dlsym(modh, "compare_u_agents");
		if ( MOD_LOAD(output_module) )
			(*MOD_LOAD(output_module))();
		if ( mod_info )
		    strncpy(MOD_INFO(output_module), mod_info, MODINFOLEN-1);
		  else
		    MOD_INFO(output_module)[0] = 0;
		output_module->general.type = MODULE_OUTPUT;
		insert_module((struct general_module*)output_module,
			      (struct general_module**)&output_first);
		break;
	      case MODULE_LISTENER:
		printf("(Listener module)\n");
		/* allocate module structure */
		listener_module = (struct listener_module*)xmalloc(sizeof(*listener_module), "for listener_module");
		if ( !listener_module ) {
		    dlclose(modh);
		}
		bzero(listener_module, sizeof(*listener_module));
		MOD_HANDLE(listener_module) = modh;
		MOD_LOAD(listener_module)   = (mod_load_t*)dlsym(modh, "mod_load");
		MOD_UNLOAD(listener_module) = (mod_load_t*)dlsym(modh, "mod_unload");
		MOD_CONFIG(listener_module) = (mod_load_t*)dlsym(modh, "mod_config");
		MOD_CONFIG_BEG(listener_module) = (mod_load_t*)dlsym(modh, "mod_config_beg");
		MOD_CONFIG_END(listener_module) = (mod_load_t*)dlsym(modh, "mod_config_end");
		*MOD_NAME(listener_module) = 0;
		nptr = (char*)dlsym(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(listener_module), nptr, MODNAMELEN-1);
		if ( mod_info )
		    strncpy(MOD_INFO(listener_module), mod_info, MODINFOLEN-1);
		  else
		    MOD_INFO(listener_module)[0] = 0;

		listener_module->process_call = (mod_load_t*)dlsym(modh, "process_call");
		if ( MOD_LOAD(listener_module) )
			(*MOD_LOAD(listener_module))();
		listener_module->general.type = MODULE_LISTENER;
		insert_module((struct general_module*)listener_module,
			      (struct general_module**)&listener_first);
		break;
	      case MODULE_HEADERS:
		printf("(Headers match module)\n");
		/* allocate module structure */
		headers_module = (struct headers_module*)xmalloc(sizeof(*headers_module), "");
		if ( !headers_module ) {
		    dlclose(modh);
		}
		bzero(headers_module, sizeof(*headers_module));
		MOD_HANDLE(headers_module) = modh;
		MOD_LOAD(headers_module)   = (mod_load_t*)dlsym(modh, "mod_load");
		MOD_UNLOAD(headers_module) = (mod_load_t*)dlsym(modh, "mod_unload");
		MOD_CONFIG(headers_module) = (mod_load_t*)dlsym(modh, "mod_config");
		MOD_CONFIG_BEG(headers_module) = (mod_load_t*)dlsym(modh, "mod_config_beg");
		MOD_CONFIG_END(headers_module) = (mod_load_t*)dlsym(modh, "mod_config_end");
		*MOD_NAME(headers_module) = 0;
		nptr = (char*)dlsym(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(headers_module), nptr, MODNAMELEN-1);
		if ( mod_info )
		    strncpy(MOD_INFO(headers_module), mod_info, MODINFOLEN-1);
		  else
		    MOD_INFO(headers_module)[0] = 0;
		headers_module->match_headers = (mod_load_t*)dlsym(modh, "match_headers");
		if ( MOD_LOAD(headers_module) )
			(*MOD_LOAD(headers_module))();
		headers_module->general.type = MODULE_HEADERS;
		insert_module((struct general_module*)headers_module,
			      (struct general_module**)&headers_first);
		break;
	      case MODULE_PRE_BODY:
		printf("(Pre-body)\n");
		/* allocate module structure */
		pre_body_module = (struct pre_body_module*)xmalloc(sizeof(*pre_body_module), "");
		if ( !pre_body_module ) {
		    dlclose(modh);
		}
		bzero(pre_body_module, sizeof(*pre_body_module));
		MOD_HANDLE(pre_body_module) = modh;
		MOD_LOAD(pre_body_module)   = (mod_load_t*)dlsym(modh, "mod_load");
		MOD_UNLOAD(pre_body_module) = (mod_load_t*)dlsym(modh, "mod_unload");
		MOD_CONFIG(pre_body_module) = (mod_load_t*)dlsym(modh, "mod_config");
		MOD_CONFIG_BEG(pre_body_module) = (mod_load_t*)dlsym(modh, "mod_config_beg");
		MOD_CONFIG_END(pre_body_module) = (mod_load_t*)dlsym(modh, "mod_config_end");
		*MOD_NAME(pre_body_module) = 0;
		nptr = (char*)dlsym(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(pre_body_module), nptr, MODNAMELEN-1);
		if ( mod_info )
		    strncpy(MOD_INFO(pre_body_module), mod_info, MODINFOLEN-1);
		  else
		    MOD_INFO(pre_body_module)[0] = 0;

		pre_body_module->pre_body = (mod_load_t*)dlsym(modh, "pre_body");
		if ( MOD_LOAD(pre_body_module) )
			(*MOD_LOAD(pre_body_module))();
		pre_body_module->general.type = MODULE_PRE_BODY;
		insert_module((struct general_module*)pre_body_module,
			      (struct general_module**)&pre_body_first);
		break;
	      default:
		printf(" (Unknown module type. Unload it)\n");
		dlclose(modh);
	    }
	} else {
	    printf("loading %s: %s\n", module_path, dlerror()); 
	}
    }
done:
    globfree(&globbuf);
    /* we will need lang */
    lang_mod = (struct output_module*)module_by_name("lang");
    return(0);
}

void
insert_module(struct general_module *mod, struct general_module **list) {
struct	general_module *first = *list;

    if (!mod || !list )
	return;
    if (!first) {
	*list = mod;
	goto gi;
    }
    while (first->next) {
	first = first->next;
    }
    first->next = mod;
gi:
    /* insert in global chain */
    first = global_mod_chain;
    if ( !first ) {
	global_mod_chain = mod;
	return;
    }
    while (first->next_global) {
	first = first->next_global;
    }
    first->next_global = mod;
}

int
check_output_mods(int so, struct output_object *obj, struct request *rq, int *mod_flags)
{
struct	output_module *omod = output_first;
int		      rc = MOD_CODE_OK;

    while ( omod && (rc == MOD_CODE_OK) && !TEST(*mod_flags, MOD_AFLAG_OUT) ) {
	rc = omod->output(so, obj, rq, mod_flags);
	omod = (struct output_module *)((struct general_module*)omod)->next;
    }
    return(rc);
}

/* can be in the form aaa.bbb.ccc.ddd:port
   or port
*/
int
parse_myports(char *string, myport_t *ports, int number)
{
char		buf[20], *p, *d, *t;
u_short		port;
myport_t	*pptr=ports;
int		nres=0, rc, one=-1, so;
struct		sockaddr_in	sin_addr;

    if ( !ports || !string ) return(0);
    while( string && *string && (nres < number) ) {
	while ( *string && !isdigit(*string) ) string++;
	if ( !*string ) break;
	p = string;
	d = buf;
	while ( *p && !isspace(*p) ) {
	    *d++ = *p++;
	}
	*d = 0;
	if ( ( t = strchr(buf, ':') ) ) {
	    *t = 0;
	    port = atoi(t+1);
	    bzero(&sin_addr, sizeof(sin_addr));
	    str_to_sa(buf, (struct sockaddr*)&sin_addr);
	} else {
	    port = atoi(buf);
	    bzero(&sin_addr, sizeof(sin_addr));
	}
	if ( port == http_port ) {
	    nres++;
	    bzero(pptr, sizeof(*pptr));
	    pptr->port = port;
	    pptr->so = -1;	/* this is sign to use server_so */
	    pptr++;
	} else
	if ( (so = tcp_port_in_use(port)) ) {
	    nres++;
	    bzero(pptr, sizeof(*pptr));
	    pptr->port = port;
	    pptr->so = so;
	    pptr++;
	} else
	if ( port && (so = socket(AF_INET, SOCK_STREAM, 0)) >= 0 ) {
	    setsockopt(so, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
	    sin_addr.sin_family = AF_INET;
	    sin_addr.sin_port   = htons(port);
#if	!defined(LINUX) && !defined(SOLARIS)
	    sin_addr.sin_len	= sizeof(sin_addr);
#endif
	    rc = bind(so, (struct sockaddr*)&sin_addr, sizeof(sin_addr));
	    if ( rc >=0 ) {
		nres++;
		pptr->port = port;
		pptr->in_addr = sin_addr.sin_addr;
		pptr->so = so;
		pptr++;
		add_socket_to_listen_list(so, 0, NULL);
		add_to_tcp_port_in_use(port, so);
		listen(so, 128);
	    } else {
		printf("parse_myports:bind: %s\n", strerror(errno));
	    }
	    printf("port = %d\n", port);
	}
	string = p;
    }
    return(nres);
}

int
Compare_Agents(char *agent1, char *agent2)
{

    if ( !lang_mod )
	return(TRUE);
    return(lang_mod->compare_u_agents(agent1, agent2));
}

#endif
