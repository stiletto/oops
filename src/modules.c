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
#include	"modules.h"

#if     !defined(SOLARIS)
#if	!defined(PEXT_SYM)
#define		PEXT_SYM	""
#endif
#define		DLSYM(a, b)	dlsym(a, PEXT_SYM b)
#else
#define         DLSYM(a, b)     dlsym(a, b)
#endif

struct	general_module		*global_mod_chain;
struct	log_module		*log_first	= NULL;
struct	err_module		*err_first	= NULL;
struct	auth_module		*auth_first	= NULL;
struct	output_module		*output_first	= NULL;
struct	redir_module		*redir_first	= NULL;
struct	listener_module		*listener_first	= NULL;
struct	headers_module		*headers_first	= NULL;
struct	pre_body_module		*pre_body_first	= NULL;
struct	db_api_module		*db_api_first	= NULL;
struct	output_module		*lang_mod	= NULL;

static	void	insert_module(struct general_module*, struct general_module**);

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
    res = (struct general_module*)db_api_first;
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
l_mod_call_list_t       *gr_mods = group->redir_mods;
mod_call_t	        *mod_list = NULL;
int                     instance;

    if ( gr_mods ) mod_list = gr_mods->list;
     
    if ( flag ) *flag = 0;
    while( mod_list && (rc == MOD_CODE_OK) ) {
	module = NULL;
	module = redir_module_by_name(mod_list->mod_name);
        instance = mod_list->mod_instance;
	if ( module && module->redir ) {
	    rc = module->redir(so, group, rq, flag, instance);
	}
	if ( flag && TEST(*flag, MOD_AFLAG_BRK) )
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
l_mod_call_list_t	*gr_mods = rq->redir_mods;
mod_call_t      	*mod_list = NULL;
int                     instance;

    if ( gr_mods ) mod_list = gr_mods->list;
     
    if ( !so ) return(rc);
    if ( flag ) *flag = 0;
    *so = -1;
    while( mod_list && (rc == MOD_CODE_OK) && (*so == -1) ) {
	module = redir_module_by_name(mod_list->mod_name);
        instance = mod_list->mod_instance;
	if ( module && module->redir_connect ) {
	    rc = module->redir_connect(so, rq, flag, instance);
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


void
run_modules(void)
{
struct	general_module	*mod = global_mod_chain;

    while (mod) {
	if (mod->mod_run) (mod->mod_run)();
	mod = mod->next_global;
    }
}

void
tick_modules(void)
{
struct	general_module	*mod = global_mod_chain;

    while (mod) {
	if (mod->mod_tick) (mod->mod_tick)();
	mod = mod->next_global;
    }
}

#if	defined(MODULES)
int
load_modules(void)
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
struct	db_api_module	*db_api_module;

char			*nptr;

    snprintf(modules_path, sizeof(modules_path)-1, "./modules");
    rc = stat(modules_path, &statb);
    if ( !rc && TEST(statb.st_mode, S_IFDIR) )
	goto load_mods;
    else
	snprintf(modules_path, sizeof(modules_path)-1, "%s", OOPS_LIBDIR);

load_mods:
    printf("Loading modules from %s\n", modules_path);
#if	!defined(_WIN32)
    snprintf(glob_mask, sizeof(glob_mask)-1, "%s/*.so", modules_path);
#else
    snprintf(glob_mask, sizeof(glob_mask)-1, "%s/*.dll", modules_path);
#endif	/* !_WIN32 */
    global_mod_chain = NULL;
    bzero(&globbuf, sizeof(globbuf));
    if ( glob(glob_mask, 0, NULL, &globbuf) ) {
	printf("Can't glob on %s\n", modules_path);
	return(1);
    }
    for( gc = globbuf.gl_pathc, paths = globbuf.gl_pathv; gc; gc--, paths++) {
	module_path = *paths;
	printf("Loading module %s\n", module_path);
	modh = dlopen(module_path, RTLD_NOW);
	if ( modh ) {
	    mod_type = (char*)DLSYM(modh, "module_type");
	    if ( !mod_type ) {
		printf("*** loading error: %s: %d: can't find symbolic name `module_type': %s\n", module_path, ERRNO, dlerror());
		continue;
	    }
	    mod_info = (char*)DLSYM(modh, "module_info");
/*	    if ( mod_info ) printf("Module: %s ", mod_info);*/
	    switch(*mod_type) {
	      case MODULE_LOG:
		/* allocate module structure */
		log_module = (struct log_module*)xmalloc(sizeof(*log_module), "load_modules(): for log_module");
		if ( !log_module ) {
		    dlclose(modh);
		}
		bzero(log_module, sizeof(*log_module));
		log_module->general.handle = modh;
		log_module->general.load   = (mod_load_t*)DLSYM(modh, "mod_load");
		log_module->general.unload = (mod_load_t*)DLSYM(modh, "mod_unload");
		log_module->general.config = (mod_load_t*)DLSYM(modh, "mod_config");
		log_module->general.config_beg = (mod_load_t*)DLSYM(modh, "mod_config_beg");
		log_module->general.config_end = (mod_load_t*)DLSYM(modh, "mod_config_end");
		log_module->mod_log = (mod_load_t*)DLSYM(modh, "mod_log");
		MOD_RUN(log_module) = (mod_load_t*)DLSYM(modh, "mod_run");
		MOD_TICK(log_module) = (mod_load_t*)DLSYM(modh, "mod_tick");
		nptr = (char*)DLSYM(modh, "module_name");
		*MOD_NAME(log_module) = 0;
		if ( nptr )
		    strncpy(MOD_NAME(log_module), nptr, MODNAMELEN-1);

		if ( log_module->general.load )
			(*log_module->general.load)();
		log_module->general.type = MODULE_LOG;
		log_module->mod_reopen = (mod_load_t*)DLSYM(modh, "mod_reopen");
		insert_module((struct general_module*)log_module,
			      (struct general_module**)&log_first);

		if ( mod_info ) {
		    strncpy(MOD_INFO(log_module), mod_info, MODINFOLEN-1);
		    printf("Module: %s ", mod_info);
		} else
		    MOD_INFO(log_module)[0] = 0;
		printf("(Logger)\n");
		break;
	      case MODULE_ERR:
		/* allocate module structure */
		err_module = (struct err_module*)xmalloc(sizeof(*err_module), "load_modules(): for err_module");
		if ( !err_module ) {
		    dlclose(modh);
		}
		bzero(err_module, sizeof(*err_module));
		MOD_HANDLE(err_module) = modh;
		MOD_LOAD(err_module)   = (mod_load_t*)DLSYM(modh, "mod_load");
		MOD_UNLOAD(err_module) = (mod_load_t*)DLSYM(modh, "mod_unload");
		MOD_CONFIG(err_module) = (mod_load_t*)DLSYM(modh, "mod_config");
		MOD_CONFIG_BEG(err_module) = (mod_load_t*)DLSYM(modh, "mod_config_beg");
		MOD_CONFIG_END(err_module) = (mod_load_t*)DLSYM(modh, "mod_config_end");
		MOD_RUN(err_module) = (mod_load_t*)DLSYM(modh, "mod_run");
		MOD_TICK(err_module) = (mod_load_t*)DLSYM(modh, "mod_tick");
		*MOD_NAME(err_module) = 0;
		nptr = (char*)DLSYM(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(err_module), nptr, MODNAMELEN-1);

		err_module->err	   = (mod_load_t*)DLSYM(modh, "err");
		err_module->general.type = MODULE_ERR;
		insert_module((struct general_module*)err_module,
			      (struct general_module**)&err_first);

		if ( mod_info ) {
		    strncpy(MOD_INFO(err_module), mod_info, MODINFOLEN-1);
		    printf("Module: %s ", mod_info);
		} else
		    MOD_INFO(err_module)[0] = 0;
		printf("(Error handling)\n");
		break;
	      case MODULE_AUTH:
		/* allocate module structure */
		auth_module = (struct auth_module*)xmalloc(sizeof(*auth_module), "load_modules(): for auth_module");
		if ( !auth_module ) {
		    dlclose(modh);
		}
		bzero(auth_module, sizeof(*auth_module));
		MOD_HANDLE(auth_module) = modh;
		MOD_LOAD(auth_module)   = (mod_load_t*)DLSYM(modh, "mod_load");
		MOD_UNLOAD(auth_module) = (mod_load_t*)DLSYM(modh, "mod_unload");
		MOD_CONFIG(auth_module) = (mod_load_t*)DLSYM(modh, "mod_config");
		MOD_CONFIG_BEG(auth_module) = (mod_load_t*)DLSYM(modh, "mod_config_beg");
		MOD_CONFIG_END(auth_module) = (mod_load_t*)DLSYM(modh, "mod_config_end");
		MOD_RUN(auth_module) = (mod_load_t*)DLSYM(modh, "mod_run");
		MOD_TICK(auth_module) = (mod_load_t*)DLSYM(modh, "mod_tick");
		*MOD_NAME(auth_module) = 0;
		nptr = (char*)DLSYM(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(auth_module), nptr, MODNAMELEN-1);

		auth_module->auth = (mod_load_t*)DLSYM(modh, "auth");
		auth_module->general.type = MODULE_AUTH;
		insert_module((struct general_module*)auth_module,
			      (struct general_module**)&auth_first);

		if ( mod_info ) {
		    strncpy(MOD_INFO(auth_module), mod_info, MODINFOLEN-1);
		    printf("Module: %s ", mod_info);
		} else
		    MOD_INFO(auth_module)[0] = 0;
		printf("(Auth module)\n");
		break;
	      case MODULE_REDIR:
		/* allocate module structure */
		redir_module = (struct redir_module*)xmalloc(sizeof(*redir_module), "load_modules(): for redir_module");
		if ( !redir_module ) {
		    dlclose(modh);
		}
		bzero(redir_module, sizeof(*redir_module));
		MOD_HANDLE(redir_module) = modh;
		MOD_LOAD(redir_module)   = (mod_load_t*)DLSYM(modh, "mod_load");
		MOD_UNLOAD(redir_module) = (mod_load_t*)DLSYM(modh, "mod_unload");
		MOD_CONFIG(redir_module) = (mod_load_t*)DLSYM(modh, "mod_config");
		MOD_CONFIG_BEG(redir_module) = (mod_load_t*)DLSYM(modh, "mod_config_beg");
		MOD_CONFIG_END(redir_module) = (mod_load_t*)DLSYM(modh, "mod_config_end");
		MOD_RUN(redir_module) = (mod_load_t*)DLSYM(modh, "mod_run");
		MOD_TICK(redir_module) = (mod_load_t*)DLSYM(modh, "mod_tick");
		*MOD_NAME(redir_module) = 0;
		nptr = (char*)DLSYM(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(redir_module), nptr, MODNAMELEN-1);

		redir_module->redir = (mod_load_t*)DLSYM(modh, "redir");
		redir_module->redir_connect = (mod_load_t*)DLSYM(modh, "redir_connect");
		redir_module->redir_rewrite_header = (mod_load_t*)DLSYM(modh, "redir_rewrite_header");
		redir_module->general.type = MODULE_REDIR;
		insert_module((struct general_module*)redir_module,
			      (struct general_module**)&redir_first);

		if ( mod_info ) {
		    strncpy(MOD_INFO(redir_module), mod_info, MODINFOLEN-1);
		    printf("Module: %s ", mod_info);
		} else
		    MOD_INFO(redir_module)[0] = 0;
		printf("(Redirect module)\n");
		break;
	      case MODULE_OUTPUT:
		/* allocate module structure */
		output_module = (struct output_module*)xmalloc(sizeof(*output_module), "load_modules(): for output_module");
		if ( !output_module ) {
		    dlclose(modh);
		}
		bzero(output_module, sizeof(*output_module));
		MOD_HANDLE(output_module) = modh;
		MOD_LOAD(output_module)   = (mod_load_t*)DLSYM(modh, "mod_load");
		MOD_UNLOAD(output_module) = (mod_load_t*)DLSYM(modh, "mod_unload");
		MOD_CONFIG(output_module) = (mod_load_t*)DLSYM(modh, "mod_config");
		MOD_CONFIG_BEG(output_module) = (mod_load_t*)DLSYM(modh, "mod_config_beg");
		MOD_CONFIG_END(output_module) = (mod_load_t*)DLSYM(modh, "mod_config_end");
		MOD_RUN(output_module) = (mod_load_t*)DLSYM(modh, "mod_run");
		MOD_TICK(output_module) = (mod_load_t*)DLSYM(modh, "mod_tick");
		*MOD_NAME(output_module) = 0;
		nptr = (char*)DLSYM(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(output_module), nptr, MODNAMELEN-1);

		output_module->output = (mod_load_t*)DLSYM(modh, "output");
		output_module->compare_u_agents = /* for lang only */
		    (mod_load_t*)DLSYM(modh, "compare_u_agents");

		output_module->general.type = MODULE_OUTPUT;
		insert_module((struct general_module*)output_module,
			      (struct general_module**)&output_first);

		if ( mod_info ) {
		    strncpy(MOD_INFO(output_module), mod_info, MODINFOLEN-1);
		    printf("Module: %s ", mod_info);
		} else
		    MOD_INFO(output_module)[0] = 0;
		printf("(Output module)\n");
		break;
	      case MODULE_LISTENER:
		/* allocate module structure */
		listener_module = (struct listener_module*)xmalloc(sizeof(*listener_module), "load_modules(): for listener_module");
		if ( !listener_module ) {
		    dlclose(modh);
		}
		bzero(listener_module, sizeof(*listener_module));
		MOD_HANDLE(listener_module) = modh;
		MOD_LOAD(listener_module)   = (mod_load_t*)DLSYM(modh, "mod_load");
		MOD_UNLOAD(listener_module) = (mod_load_t*)DLSYM(modh, "mod_unload");
		MOD_CONFIG(listener_module) = (mod_load_t*)DLSYM(modh, "mod_config");
		MOD_CONFIG_BEG(listener_module) = (mod_load_t*)DLSYM(modh, "mod_config_beg");
		MOD_CONFIG_END(listener_module) = (mod_load_t*)DLSYM(modh, "mod_config_end");
		MOD_RUN(listener_module) = (mod_load_t*)DLSYM(modh, "mod_run");
		MOD_TICK(listener_module) = (mod_load_t*)DLSYM(modh, "mod_tick");
		*MOD_NAME(listener_module) = 0;
		nptr = (char*)DLSYM(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(listener_module), nptr, MODNAMELEN-1);

		listener_module->process_call = (mod_void_ptr_t*)DLSYM(modh, "process_call");
		listener_module->general.type = MODULE_LISTENER;
		insert_module((struct general_module*)listener_module,
			      (struct general_module**)&listener_first);

		if ( mod_info ) {
		    strncpy(MOD_INFO(listener_module), mod_info, MODINFOLEN-1);
		    printf("Module: %s ", mod_info);
		} else
		    MOD_INFO(listener_module)[0] = 0;
		printf("(Listener module)\n");
		break;
	      case MODULE_HEADERS:
		/* allocate module structure */
		headers_module = (struct headers_module*)xmalloc(sizeof(*headers_module), "load_modules(): for header_module");
		if ( !headers_module ) {
		    dlclose(modh);
		}
		bzero(headers_module, sizeof(*headers_module));
		MOD_HANDLE(headers_module) = modh;
		MOD_LOAD(headers_module)   = (mod_load_t*)DLSYM(modh, "mod_load");
		MOD_UNLOAD(headers_module) = (mod_load_t*)DLSYM(modh, "mod_unload");
		MOD_CONFIG(headers_module) = (mod_load_t*)DLSYM(modh, "mod_config");
		MOD_CONFIG_BEG(headers_module) = (mod_load_t*)DLSYM(modh, "mod_config_beg");
		MOD_CONFIG_END(headers_module) = (mod_load_t*)DLSYM(modh, "mod_config_end");
		MOD_RUN(headers_module) = (mod_load_t*)DLSYM(modh, "mod_run");
		MOD_TICK(headers_module) = (mod_load_t*)DLSYM(modh, "mod_tick");
		*MOD_NAME(headers_module) = 0;
		nptr = (char*)DLSYM(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(headers_module), nptr, MODNAMELEN-1);

		headers_module->match_headers = (mod_load_t*)DLSYM(modh, "match_headers");
		headers_module->general.type = MODULE_HEADERS;
		insert_module((struct general_module*)headers_module,
			      (struct general_module**)&headers_first);

		if ( mod_info ) {
		    strncpy(MOD_INFO(headers_module), mod_info, MODINFOLEN-1);
		    printf("Module: %s ", mod_info);
		} else
		    MOD_INFO(headers_module)[0] = 0;
		printf("(Headers match module)\n");
		break;
	      case MODULE_PRE_BODY:
		/* allocate module structure */
		pre_body_module = (struct pre_body_module*)xmalloc(sizeof(*pre_body_module), "load_modules(): for pre_body_module");
		if ( !pre_body_module ) {
		    dlclose(modh);
		}
		bzero(pre_body_module, sizeof(*pre_body_module));
		MOD_HANDLE(pre_body_module) = modh;
		MOD_LOAD(pre_body_module)   = (mod_load_t*)DLSYM(modh, "mod_load");
		MOD_UNLOAD(pre_body_module) = (mod_load_t*)DLSYM(modh, "mod_unload");
		MOD_CONFIG(pre_body_module) = (mod_load_t*)DLSYM(modh, "mod_config");
		MOD_CONFIG_BEG(pre_body_module) = (mod_load_t*)DLSYM(modh, "mod_config_beg");
		MOD_CONFIG_END(pre_body_module) = (mod_load_t*)DLSYM(modh, "mod_config_end");
		MOD_RUN(pre_body_module) = (mod_load_t*)DLSYM(modh, "mod_run");
		MOD_TICK(pre_body_module) = (mod_load_t*)DLSYM(modh, "mod_tick");
		*MOD_NAME(pre_body_module) = 0;
		nptr = (char*)DLSYM(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(pre_body_module), nptr, MODNAMELEN-1);

		pre_body_module->pre_body = (mod_load_t*)DLSYM(modh, "pre_body");
		pre_body_module->general.type = MODULE_PRE_BODY;
		insert_module((struct general_module*)pre_body_module,
			      (struct general_module**)&pre_body_first);

		if ( mod_info ) {
		    strncpy(MOD_INFO(pre_body_module), mod_info, MODINFOLEN-1);
		    printf("Module: %s ", mod_info);
		} else
		    MOD_INFO(pre_body_module)[0] = 0;

		printf("(Pre-body)\n");
		break;
	      case MODULE_DB_API:
		/* allocate module structure */
		db_api_module = (struct db_api_module*)xmalloc(sizeof(*db_api_module), "load_modules(): for db_api_module");
		if ( !db_api_module ) {
		    dlclose(modh);
		}
		bzero(db_api_module, sizeof(*db_api_module));
		MOD_HANDLE(db_api_module) = modh;
		MOD_LOAD(db_api_module)   = (mod_load_t*)DLSYM(modh, "mod_load");
		MOD_UNLOAD(db_api_module) = (mod_load_t*)DLSYM(modh, "mod_unload");
		MOD_CONFIG(db_api_module) = (mod_load_t*)DLSYM(modh, "mod_config");
		MOD_CONFIG_BEG(db_api_module) = (mod_load_t*)DLSYM(modh, "mod_config_beg");
		MOD_CONFIG_END(db_api_module) = (mod_load_t*)DLSYM(modh, "mod_config_end");
		MOD_RUN(db_api_module) = (mod_load_t*)DLSYM(modh, "mod_run");
		MOD_TICK(db_api_module) = (mod_load_t*)DLSYM(modh, "mod_tick");
		*MOD_NAME(db_api_module) = 0;
		nptr = (char*)DLSYM(modh, "module_name");
		if ( nptr )
		    strncpy(MOD_NAME(db_api_module), nptr, MODNAMELEN-1);

		db_api_module->general.type = MODULE_DB_API;
		db_api_module->db_api_open = (mod_load_t*)DLSYM(modh, "db_api_open");
		db_api_module->db_api_close = (mod_load_t*)DLSYM(modh, "db_api_close");
		db_api_module->db_api_get = (mod_load_t*)DLSYM(modh, "db_api_get");
		db_api_module->db_api_del = (mod_load_t*)DLSYM(modh, "db_api_del");
		db_api_module->db_api_put = (mod_load_t*)DLSYM(modh, "db_api_put");
		db_api_module->db_api_cursor_open = (db_api_cursor_f_t*)DLSYM(modh, "db_api_cursor_open");
		db_api_module->db_api_cursor_get = (mod_load_t*)DLSYM(modh, "db_api_cursor_get");
		db_api_module->db_api_cursor_del = (mod_load_t*)DLSYM(modh, "db_api_cursor_del");
		db_api_module->db_api_cursor_close = (mod_load_t*)DLSYM(modh, "db_api_cursor_close");
		db_api_module->db_api_cursor_freeze = (mod_load_t*)DLSYM(modh, "db_api_cursor_freeze");
		db_api_module->db_api_cursor_unfreeze = (mod_load_t*)DLSYM(modh, "db_api_cursor_unfreeze");
		db_api_module->db_api_sync =(mod_load_t*)DLSYM(modh, "db_api_sync");
		db_api_module->db_api_attach =(mod_load_t*)DLSYM(modh, "db_api_attach");
		db_api_module->db_api_detach =(mod_load_t*)DLSYM(modh, "db_api_detach");
		db_api_module->db_api_precommit =(mod_load_t*)DLSYM(modh, "db_api_precommit");
		insert_module((struct general_module*)db_api_module,
			      (struct general_module**)&db_api_first);

		if ( mod_info ) {
		    strncpy(MOD_INFO(db_api_module), mod_info, MODINFOLEN-1);
		    printf("Module: %s ", mod_info);
		} else
		    MOD_INFO(db_api_module)[0] = 0;

		printf("(DB API)\n");
		break;
	      default:
		printf(" (Unknown module type. Unload it)\n");
		dlclose(modh);
	    }
	} else {
	    printf("*** loading error: %s: %d: %s\n", module_path, ERRNO, dlerror());
	}
    }
    globfree(&globbuf);
    /* we will need lang */
    lang_mod = (struct output_module*)module_by_name("lang");
    return(0);
}
#else
int
load_modules(void)
{
    insert_module(&log_dummy.general, (struct general_module **)&log_first);
    insert_module(&custom_log.general, (struct general_module **)&log_first);

    insert_module(&oopsctl_mod.general, (struct general_module **)&listener_first);
    insert_module(&wccp2_mod.general, (struct general_module **)&listener_first);

    insert_module(&accel.general, (struct general_module **)&redir_first);
    insert_module(&fastredir.general, (struct general_module **)&redir_first);
    insert_module(&redir_mod.general, (struct general_module **)&redir_first);
    insert_module(&transparent.general, (struct general_module **)&redir_first);

    insert_module(&lang.general, (struct general_module **)&output_first);

    insert_module(&err_mod.general, (struct general_module **)&err_first);

    insert_module(&passwd_file.general, (struct general_module **)&auth_first);
    insert_module(&pam.general, (struct general_module **)&auth_first);
    insert_module(&passwd_mysql.general, (struct general_module **)&auth_first);
    insert_module(&passwd_pgsql.general, (struct general_module **)&auth_first);

    insert_module(&vary_header.general, (struct general_module **)&headers_first);

    insert_module(&berkeley_db_api.general, (struct general_module **)&db_api_first);
    insert_module(&gigabase_db_api.general, (struct general_module **)&db_api_first);
}

#endif

static void
insert_module(struct general_module *mod, struct general_module **list) {
struct	general_module *first = *list;

    if (!mod || !list )
	return;
    printf("Insert module '%s'\n", mod->name);
    if ( mod->load ) (mod->load)(); 
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
	p = string;
	while ( *p && IS_SPACE(*p) ) p++;
	if ( !*p ) return(nres);
	d = buf;
	while ( *p && !IS_SPACE(*p) ) {
	    *d++ = *p++;
	}
	*d = 0;
	string = p;
	if ( (t = (char*)strchr(buf, ':')) != 0 ) {
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
	    continue;
	} else
	if ( (so = tcp_port_in_use(port, &sin_addr.sin_addr)) !=0 ) {
	    nres++;
	    bzero(pptr, sizeof(*pptr));
	    pptr->port = port;
	    pptr->so = so;
	    pptr++;
	    continue;
	} else
#if	defined(FREEBSD)
	/*
	 * sockets in freebsd have 'owner' (at least in 4.0)
	 * and any furrher binds will fail regardless of SO_REUSEADDR 
	 * if we will bind from different user (of course if there is
	 * socket in WAIT_TIME and such in system pcb list)
	 * we can ignore this for reserved ports as we use different
	 * method for binding reserved ports.
	 */
	if ( oops_user && (port >= IPPORT_RESERVED) )
	    set_euser(oops_user);
#endif
	if ( port && (so = socket(AF_INET, SOCK_STREAM, 0)) >= 0 ) {
	    setsockopt(so, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
	    sin_addr.sin_family = AF_INET;
	    sin_addr.sin_port   = htons(port);
#if	!defined(LINUX) && !defined(SOLARIS) && !defined(OSF) && !defined(_WIN32)
	    sin_addr.sin_len	= sizeof(sin_addr);
#endif
	    rc = bind(so, (struct sockaddr*)&sin_addr, sizeof(sin_addr));
	    if ( rc >=0 ) {
		nres++;
		pptr->port = port;
		pptr->in_addr = sin_addr.sin_addr;
		pptr->so = so;
		add_socket_to_listen_list(so, port, &pptr->in_addr, 0, NULL);
		listen(so, 128);
		pptr++;
	    } else {
		verb_printf("parse_myports(): bind: %s\n", strerror(errno));
		my_xlog(OOPS_LOG_SEVERE, "parse_myports(): bind: %m\n");
	    }
	    printf("port = %d\n", port);
	}
#if	defined(FREEBSD)
	if ( oops_user && (port >= IPPORT_RESERVED) )
	    set_euser(NULL);
#endif
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

int
check_log_mods(int elapsed, struct request *rq, struct mem_obj *obj)
{
struct	log_module	*mod = log_first;

    while( mod ) {
	if ( mod->mod_log ) (mod->mod_log)(elapsed, rq, obj);
	mod = (struct log_module*)((struct general_module*)mod)->next;
    }
    return(0);
}

int
mod_reopen_logs(void)
{
struct	log_module	*mod = log_first;

    while( mod ) {
	if ( mod->mod_reopen ) (mod->mod_reopen)();
	mod = (struct log_module*)((struct general_module*)mod)->next;
    }
    return(0);
}
int
db_mod_open(void)
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    while ( mod ) {
	if ( mod->db_api_open ) (mod->db_api_open)(&aflag);
	if ( aflag == MOD_AFLAG_BRK )	/* some DB successfully initialized */
	    return(TRUE);
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(FALSE);
}

int
db_mod_close(void)
{
struct	db_api_module	*mod = db_api_first;

    while ( mod ) {
	if ( mod->db_api_close ) (mod->db_api_close)();
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(0);
}

int
db_mod_get(db_api_arg_t *arg, db_api_arg_t *res)
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    if ( !arg || !res ) return(DB_API_RES_CODE_ERR);
    res->flags = DB_API_RES_CODE_ERR;
    while ( mod ) {
	if ( mod->db_api_get ) (mod->db_api_get)(arg, res, &aflag);
	if ( aflag == MOD_AFLAG_BRK )	/* some DB successfully get'ed */
	    break;
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(res->flags);
}

int
db_mod_put(db_api_arg_t *key, db_api_arg_t *data, struct mem_obj *obj)
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    if ( !key || !data ) return(DB_API_RES_CODE_ERR);
    data->flags = DB_API_RES_CODE_ERR;
    while ( mod ) {
	if ( mod->db_api_put ) (mod->db_api_put)(key, data, obj, &aflag);
	if ( aflag == MOD_AFLAG_BRK )	/* some DB successfully put'ed */
	    break;
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(data->flags);
}

int
db_mod_del(db_api_arg_t *key)
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    if ( !key ) return(DB_API_RES_CODE_ERR);
    while ( mod ) {
	if ( mod->db_api_del ) (mod->db_api_del)(key, &aflag);
	if ( aflag == MOD_AFLAG_BRK )	/* some DB successfully del'ed */
	    return(key->flags);
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(DB_API_RES_CODE_NOTFOUND);
}

void*
db_mod_cursor_open(int type)
{
struct	db_api_module	*mod = db_api_first;
void			*res;
int			aflag = 0;

    while ( mod ) {
	if ( mod->db_api_cursor_open ) res = (mod->db_api_cursor_open)(type, &aflag);
	if ( aflag == MOD_AFLAG_BRK )	/* some DB successfully del'ed */
	    return(res);
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(NULL);
}

int
db_mod_cursor_close(void* cursor)
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    while ( mod ) {
	if ( mod->db_api_cursor_close ) (mod->db_api_cursor_close)(cursor, &aflag);
	if ( aflag == MOD_AFLAG_BRK )	/* some DB successfully del'ed */
	    return(0);
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(DB_API_RES_CODE_ERR);
}

int
db_mod_cursor_get(void* cursor, db_api_arg_t* key, db_api_arg_t* res)
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    while ( mod ) {
	if ( mod->db_api_cursor_get ) (mod->db_api_cursor_get)(cursor, key, res, &aflag);
	if ( aflag == MOD_AFLAG_BRK )	/* some DB successfully del'ed */
	    return(res->flags);
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(DB_API_RES_CODE_ERR);
}


int
db_mod_cursor_del(void* cursor)
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    while ( mod ) {
	if ( mod->db_api_cursor_del ) (mod->db_api_cursor_del)(cursor, &aflag);
	if ( aflag == MOD_AFLAG_BRK )	/* some DB successfully del'ed */
	    return(0);
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(DB_API_RES_CODE_ERR);
}

int
db_mod_cursor_freeze(void* cursor)
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    while ( mod ) {
	if ( mod->db_api_cursor_freeze ) (mod->db_api_cursor_freeze)(cursor, &aflag);
	if ( aflag == MOD_AFLAG_BRK )	/* some DB successfully del'ed */
	    return(0);
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(DB_API_RES_CODE_ERR);
}

int
db_mod_cursor_unfreeze(void* cursor)
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    while ( mod ) {
	if ( mod->db_api_cursor_unfreeze ) (mod->db_api_cursor_unfreeze)(cursor, &aflag);
	if ( aflag == MOD_AFLAG_BRK )	/* some DB successfully del'ed */
	    return(0);
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(DB_API_RES_CODE_ERR);
}


int
db_mod_sync()
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    while ( mod ) {
	if ( mod->db_api_sync ) (mod->db_api_sync)(&aflag);
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(0);
}

int
db_mod_attach()
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    while ( mod ) {
	if ( mod->db_api_attach ) (mod->db_api_attach)(&aflag);
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(0);
}

int
db_mod_detach()
{
struct	db_api_module	*mod = db_api_first;
int			aflag = 0;

    while ( mod ) {
	if ( mod->db_api_detach ) (mod->db_api_detach)(&aflag);
	mod = (struct db_api_module*)((struct general_module*)mod)->next;
    }
    return(0);
}
