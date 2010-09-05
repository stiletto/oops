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

struct	log_module	*log_first = NULL;
struct	err_module	*err_first = NULL;
struct	auth_module	*auth_first = NULL;
struct	output_module	*output_first = NULL;
struct	redir_module	*redir_first = NULL;

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
struct	string_list	*mod_list = group->auth_mods;

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
struct	string_list	*mod_list = group->redir_mods;

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
load_modules()
{
void			*modh;
char			*mod_type, *mod_info, **paths, *module_path;
glob_t			globbuf;
int			gc;
struct	log_module	*log_module;
struct	err_module	*err_module;
struct	auth_module	*auth_module;
struct	redir_module	*redir_module;
struct	output_module	*output_module;
char			*nptr;

    bzero(&globbuf, sizeof(globbuf));
    if ( glob("./modules/*.so", 0, NULL, &globbuf) ) {
	printf("can't glob on ./modules\n");
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
		if ( log_module->general.load )
			(*log_module->general.load)();
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

		err_module->err	   = (mod_load_t*)dlsym(modh, "err");
		if ( MOD_LOAD(err_module) )
			(*MOD_LOAD(err_module))();
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

		auth_module->auth = (mod_load_t*)dlsym(modh, "auth");
		if ( MOD_LOAD(auth_module) )
			(*MOD_LOAD(auth_module))();
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

		redir_module->redir = (mod_load_t*)dlsym(modh, "redir");
		if ( MOD_LOAD(redir_module) )
			(*MOD_LOAD(redir_module))();
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
		if ( MOD_LOAD(output_module) )
			(*MOD_LOAD(output_module))();
		insert_module((struct general_module*)output_module,
			      (struct general_module**)&output_first);
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
    return(0);
}

void
insert_module(struct general_module *mod, struct general_module **list) {
struct	general_module *first = *list;

    if (!mod || !list )
	return;
    if (!first) {
	*list = mod;
	return;
    }
    while (first->next) {
	first = first->next;
    }
    first->next = mod;
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


#endif
