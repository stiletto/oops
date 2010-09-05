#define	MOD_CODE_OK	0
#define	MOD_CODE_ERR	1

#define	MOD_AFLAG_OK	1	/* can continue with next module	*/
#define	MOD_AFLAG_BRK	2	/* do not continue with next module	*/
#define	MOD_AFLAG_OUT	4	/* module did some output		*/

#define	MODULE_LOG	1
#define	MODULE_ERR	2
#define	MODULE_AUTH	3
#define	MODULE_OUTPUT	4

#define	MODNAMELEN	16

#define	MOD_NEXT(m)		(m->general.next)
#define	MOD_HANDLE(m)		(m->general.handle)
#define	MOD_NAME(m)		(m->general.name)
#define	MOD_LOAD(m)		(m->general.load)
#define	MOD_UNLOAD(m)		(m->general.unload)
#define	MOD_CONFIG(m)		(m->general.config)
#define	MOD_CONFIG_BEG(m)	(m->general.config_beg)
#define	MOD_CONFIG_END(m)	(m->general.config_end)

typedef	int (mod_load_t)();

struct	general_module {
	struct general_module	*next;
	void			*handle;
	char			name[MODNAMELEN];
	int			(*load)();
	int			(*unload)();
	int			(*config_beg)();
	int			(*config_end)();
	int			(*config)(char*);
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
struct	output_module {
	struct	general_module	general;
	int	(*output)(int, struct output_object*, struct request*, int*);
};

struct	general_module	*module_by_name(char*);
struct	auth_module	*auth_module_by_name(char*);
