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

#define	MODNAMELEN	16
#define	MODINFOLEN	80

#define	MOD_NEXT(m)		(m->general.next)
#define	MOD_HANDLE(m)		(m->general.handle)
#define	MOD_NAME(m)		(m->general.name)
#define	MOD_INFO(m)		(m->general.info)
#define	MOD_LOAD(m)		(m->general.load)
#define	MOD_UNLOAD(m)		(m->general.unload)
#define	MOD_CONFIG(m)		(m->general.config)
#define	MOD_CONFIG_BEG(m)	(m->general.config_beg)
#define	MOD_CONFIG_END(m)	(m->general.config_end)

typedef	int (mod_load_t)();

struct	general_module		*global_mod_chain;

struct	general_module {
	struct general_module	*next;
	void			*handle;
	char			name[MODNAMELEN];
	int			(*load)();
	int			(*unload)();
	int			(*config_beg)();
	int			(*config_end)();
	int			(*config)(char*);
	struct general_module	*next_global;
	int			type;
	char			info[MODINFOLEN];
};

struct	log_module {
	struct	general_module	general;
};

struct	err_module {
	struct	general_module	general;
	int	(*err)(int, char*,char*,int, struct request*, int*);
};

struct	auth_module {
	struct	general_module	general;
	int	(*auth)(int, struct group*, struct request*, int*);
};

struct	redir_module {
	struct	general_module	general;
	int	(*redir)(int, struct group*, struct request*, int*);
	int	(*redir_connect)(int*, struct request*, int*);
	int	(*redir_rewrite_header)(char **, struct request*, int*);
};

struct	output_module {
	struct	general_module	general;
	int	(*output)(int, struct output_object*, struct request*, int*);
	int	(*compare_u_agents)(char *, char *);
};

struct	listener_module {
	struct	general_module	general;
	int	(*process_call)(int);
};

struct	headers_module {
	struct	general_module	general;
	int	(*match_headers)(struct mem_obj *, struct request *, int*);
};

struct	pre_body_module {
	struct	general_module	general;
	int	(*pre_body)(int, struct mem_obj *, struct request *, int*);
};

struct	general_module	*module_by_name(char*);
struct	auth_module	*auth_module_by_name(char*);
