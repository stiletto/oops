#define	MOD_CODE_OK	0
#define	MOD_CODE_ERR	1

#define	MOD_AFLAG_OK	1	/* can continue with next module		*/
#define	MOD_AFLAG_BRK	2	/* do not continue with next module		*/
#define	MOD_AFLAG_OUT	4	/* module did some output			*/
#define	MOD_AFLAG_CKACC	8	/* check access after rewrite url modiles	*/

#define	MODULE_LOG	1
#define	MODULE_ERR	2
#define	MODULE_AUTH	3
#define	MODULE_OUTPUT	4
#define	MODULE_REDIR	5
#define	MODULE_LISTENER	6
#define	MODULE_HEADERS	7
#define	MODULE_PRE_BODY	8
#define	MODULE_DB_API	9


#define	MODNAMELEN	16
#define	MODINFOLEN	80

#define	MOD_NEXT(m)		(m->general.next)
#define	MOD_HANDLE(m)		(m->general.handle)
#define	MOD_NAME(m)		(m->general.name)
#define	MOD_INFO(m)		(m->general.info)
#define	MOD_LOAD(m)		(m->general.load)
#define	MOD_UNLOAD(m)		(m->general.unload)
#define	MOD_CONFIG(m)		(m->general.config)
#define	MOD_RUN(m)		(m->general.mod_run)
#define	MOD_TICK(m)		(m->general.mod_tick)
#define	MOD_CONFIG_BEG(m)	(m->general.config_beg)
#define	MOD_CONFIG_END(m)	(m->general.config_end)

typedef	int (mod_load_t)();
typedef void* (mod_void_ptr_t)(void*);
typedef void* (db_api_cursor_f_t)();

extern	struct	general_module		*global_mod_chain;

struct	general_module {
	struct general_module	*next;
	void			*handle;
	char			name[MODNAMELEN];
	int			(*load)(void);
	int			(*unload)();
	int			(*config_beg)(int);
	int			(*config_end)(int);
	int			(*config)(char*, int);
	struct general_module	*next_global;
	int			type;
	char		info[MODINFOLEN];
	int			(*mod_run)();
	int			(*mod_tick)();
};

struct	log_module {
	struct	general_module	general;
	int	(*mod_log)(int, struct request *, struct mem_obj *);
	int	(*mod_reopen)();
};

struct	err_module {
	struct	general_module	general;
	int	(*err)(int, char*, char*, int, struct request*, int*);
};

struct	auth_module {
	struct	general_module	general;
	int	(*auth)(int, struct group*, struct request*, int*);
};

struct	redir_module {
	struct	general_module	general;
	int	(*redir)(int, struct group*, struct request*, int*, int);
	int	(*redir_connect)(int*, struct request*, int*, int);
	int	(*redir_rewrite_header)(char **, struct request*, int*, int);
};

struct	output_module {
	struct	general_module	general;
	int	(*output)(int, struct output_object*, struct request*, int*);
	int	(*compare_u_agents)(char *, char *);
};

struct	listener_module {
	struct	general_module	general;
	void*	(*process_call)(void*);
};

struct	headers_module {
	struct	general_module	general;
	int	(*match_headers)(struct mem_obj *, struct request *, int*);
};

struct	pre_body_module {
	struct	general_module	general;
	int	(*pre_body)(int, struct mem_obj *, struct request *, int*);
};

struct	db_api_module {
	struct	general_module	general;
	int	(*db_api_open)(int*);
	int	(*db_api_close)(void);
	int	(*db_api_get)(db_api_arg_t*, db_api_arg_t*, int*);
	int	(*db_api_put)(db_api_arg_t*, db_api_arg_t*, struct mem_obj*, int*);
	int	(*db_api_del)(db_api_arg_t*, int*);
	void*   (*db_api_cursor_open)(int, int*);
	int     (*db_api_cursor_get)(void*, db_api_arg_t*, db_api_arg_t*, int*);
	int     (*db_api_cursor_del)(void*, int*);
	int     (*db_api_cursor_close)(void*, int*);
	int	(*db_api_sync)();
	int     (*db_api_attach)(int*);
	int     (*db_api_detach)(int*);
	int	(*db_api_precommit)(int*);
	int     (*db_api_cursor_freeze)(void*, int*);
	int     (*db_api_cursor_unfreeze)(void*, int*);
};

struct	general_module	*module_by_name(char*);
struct	auth_module	*auth_module_by_name(char*);
int	Compare_Agents(char *, char *);

extern	struct	log_module	log_dummy;
extern	struct	log_module	custom_log;

extern	struct	listener_module	oopsctl_mod;
extern	struct	listener_module	wccp2_mod;

extern	struct	redir_module	accel;
extern	struct	redir_module	fastredir;
extern	struct	redir_module	redir_mod;
extern	struct	redir_module	transparent;

extern	struct	output_module	lang;

extern	struct	err_module	err_mod;

extern	struct	auth_module	passwd_file;
extern	struct	auth_module	pam;
extern	struct	auth_module	passwd_mysql;
extern	struct	auth_module	passwd_pgsql;

extern	struct	headers_module	vary_header;

extern	struct	db_api_module	berkeley_db_api;
extern  struct	db_api_module	gigabase_db_api;

extern	struct	redir_module	*redir_first;

inline	static	int	do_redir_rewrite_header(char **hdr, struct request *rq, int *flag);
inline	static	struct	redir_module *redir_module_by_name(char *name);

inline
static int
do_redir_rewrite_header(char **hdr, struct request *rq, int *flag)
{
int			rc = MOD_CODE_OK;
struct	redir_module	*module;
l_mod_call_list_t	*gr_mods;
mod_call_t      	*mod_list = NULL;
int                     instance;

    if ( !rq ) return(rc);
    if ( flag ) *flag = 0;
    gr_mods = rq->redir_mods;
    if ( gr_mods ) mod_list = gr_mods->list;

    while( mod_list && (rc == MOD_CODE_OK) ) {
	module = redir_module_by_name(mod_list->mod_name);
        instance = mod_list->mod_instance;
	if ( module && module->redir_rewrite_header ) {
	    rc = module->redir_rewrite_header(hdr, rq, flag, instance);
	}
	if ( flag && TEST(*flag, (MOD_AFLAG_BRK|MOD_AFLAG_OUT)) )
	    return(MOD_CODE_ERR);
	mod_list = mod_list->next;
    }
    return(rc);
}

inline
static struct	redir_module *
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
