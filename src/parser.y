%token	LOGFILE ACCESSLOG STATISTICS PIDFILE NAMESERVER HTTP_PORT ICP_PORT
%token	ICONS_HOST ICONS_PORT ICONS_PATH EXPIRE_VALUE EXPIRE_INTERVAL
%token	STOP_CACHE MAXRESIDENT CONNECT_FROM
%token	MEM_MAX LO_MARK HI_MARK DISK_LOW_FREE_T DISK_HI_FREE_T
%token	PARENT_T PEER_T SIBLING_T LOCAL_DOMAIN_T LOCAL_NETWORKS_T
%token	GROUP NETWORK NETWORKS HTTP ICP
%token	NUMBER NUMBER_K NUMBER_M STRING
%token	ALLOW DENY BADPORTS_T MISS_T AUTH_MODS_T REDIR_MODS_T
%token	DSTDOMAIN
%token	STORAGE SIZE PATH DBNAME DBHOME
%token	PEER_PARENT_T PEER_SIBLING_T BANDWIDTH_T
%token	L_EOS ICP_TIMEOUT MODULE

%type	<NETPTR>	network_list network
%type	<STRPTR>	group_name string module_name
%type	<STRING_LIST>	mod_op mod_ops string_list string_list_e
%type	<GROUPOPS>	group_op group_ops
%type	<GROUPOPS>	http icp badports bandwidth miss auth_mods redir_mods
%type	<STORAGEST>	st_op st_ops
%type	<INT>		num
%type	<ACL>		allow_acl deny_acl allow_acls deny_acls
%type	<DOMAIN>	domain domainlist

%union	{
	int				INT;
	char				*STRPTR;
	struct	cidr_net		*NETPTR;
	struct	group_ops_struct	*GROUPOPS;
	struct	acl			*ACL;
	struct	domain_list		*DOMAIN;
	struct	storage_st		*STORAGEST;
	struct	string_list		*STRING_LIST;
	}

%{
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

#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/file.h>
#include	<sys/time.h>

#include	<netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"
#ifdef	MODULES
#include	"modules.h"
#endif

int	atline;
int	parser_errors;

static	char	*storage_path = NULL, *storage_db = NULL;
static	int	storage_size = 0;
static	int	ns_curr;

static	struct	peer_c	*peerc_ptr;
static	struct	range	badports[MAXBADPORTS];
static	struct	range	*badp_p = NULL;
FILE	*yyin;

struct	peer_c {
	char	type;
	struct	acls	*acls;
} peer_c;

%}

%%

config		: /* empty */
		| statements statement
		;

statements	: statement
		| statements statement

statement	: logfile
		| accesslog
		| statistics
		| pidfile
		| nameserver
		| connect_from
		| http_port
		| icp_port
		| icp_timeout
		| icons_host
		| icons_path
		| icons_port
		| expire_value
		| expire_interval
		| disk_low_free
		| disk_hi_free
		| parent
		| local_domain
		| local_networks
		| stop_cache
		| maxresident
		| mem_max
		| lo_mark
		| hi_mark
		| group
		| peer
		| storage
		| dbhome
		| dbname
		| module
		| error L_EOS {
			yyerrok;
		  }
		| L_EOS

logfile		: LOGFILE STRING L_EOS {
			printf("LOGFILE:\t<<%s>>\n", yylval.STRPTR);
			strncpy(logfile, yylval.STRPTR, sizeof(logfile)-1);
			free(yylval.STRPTR);
		}
		| LOGFILE string '{' num num '}' L_EOS {
			printf("LOGFILE:\t<<%s>> num: %d, size: %d\n",
			$2, $4, $5);
			strncpy(logfile, $2, sizeof(logfile)-1);
			log_num = $4;
			log_size = $5;
			free($2);
		}

accesslog	: ACCESSLOG STRING L_EOS {
			printf("ACCESSLOG:\t<<%s>>\n", yylval.STRPTR);
			strncpy(accesslog, yylval.STRPTR, sizeof(accesslog)-1);
			accesslog_num = accesslog_size = 0;
			free(yylval.STRPTR);
		}
		| ACCESSLOG string '{' num num '}' L_EOS {
			printf("ACCESSLOG:\t<<%s>> num: %d, size: %d\n",
			$2, $4, $5);
			strncpy(accesslog, $2, sizeof(accesslog)-1);
			accesslog_num = $4;
			accesslog_size = $5;
			free($2);
		}

statistics	: STATISTICS STRING L_EOS {
			printf("STATISTICS:\t<<%s>>\n", yylval.STRPTR);
			strncpy(statisticslog, yylval.STRPTR, sizeof(statisticslog)-1);
			free(yylval.STRPTR);
		}

pidfile		: PIDFILE STRING L_EOS {
			printf("PIDFILE:\t<<%s>>\n", yylval.STRPTR);
			strncpy(pidfile, yylval.STRPTR, sizeof(pidfile)-1);
			free(yylval.STRPTR);
		}

nameserver	: NAMESERVER STRING L_EOS {
			printf("NAMESERVER:\t<<%s>>\n", yylval.STRPTR);
			if ( ns_curr < MAXNS ) {
			    ns_sa[ns_curr].sin_addr.s_addr = inet_addr(yylval.STRPTR);
			    ns_sa[ns_curr].sin_port = htons(53);
			    ns_curr++;
			} else {
			    printf("You can configure maximum %d nameservers\n", MAXNS);
			}
			free(yylval.STRPTR);
		}

connect_from	: CONNECT_FROM STRING L_EOS {
			printf("CONNECT_FROM:\t<<%s>>\n", yylval.STRPTR);
			strncpy(connect_from, yylval.STRPTR, sizeof(connect_from)-1);
			free(yylval.STRPTR);
		}

stop_cache	: STOP_CACHE STRING L_EOS {
			printf("STOP_CACHE:\t<<%s>>\n", yylval.STRPTR);
			add_to_stop_cache(yylval.STRPTR);
		}
maxresident	: MAXRESIDENT NUMBER L_EOS {
			printf("MAXRESIDENT:\t %d\n", yylval.INT);
			maxresident = yylval.INT;
		}

http_port	: HTTP_PORT NUMBER L_EOS {
			printf("HTTP_PORT\t<<%d>>\n", yylval.INT);
			http_port = yylval.INT;
		}
icp_port	: ICP_PORT NUMBER L_EOS {
			printf("ICP_PORT\t<<%d>>\n", yylval.INT);
			icp_port = yylval.INT;
		}

icp_timeout	: ICP_TIMEOUT NUMBER L_EOS {
			printf("ICP_TIMEOUT\t<<%d>>\n", yylval.INT);
			icp_timeout = 1000*yylval.INT;
		}

icons_host	: ICONS_HOST STRING L_EOS {
			printf("ICONS_HOST:\t<<%s>>\n", yylval.STRPTR);
			strncpy(icons_host, yylval.STRPTR, sizeof(icons_host)-1);
			free(yylval.STRPTR);
		}

icons_port	: ICONS_PORT NUMBER L_EOS {
			printf("ICONS_PORT:\t<<%d>>\n", yylval.INT);
			sprintf(icons_port, "%d", yylval.INT);
		}

icons_path	: ICONS_PATH STRING L_EOS {
			printf("ICONS_PATH:\t<<%s>>\n", yylval.STRPTR);
			strncpy(icons_path, yylval.STRPTR, sizeof(icons_path)-1);
			free(yylval.STRPTR);
		}

expire_value	: EXPIRE_VALUE NUMBER L_EOS {
			printf("EXPIRE_VALUE:\t<<%d days>>\n", yylval.INT);
			default_expire_value=yylval.INT * 24 * 3600;
		}

expire_interval	: EXPIRE_INTERVAL NUMBER L_EOS {
			printf("EXPIRE_INTERVAL:<<%d hours>>\n", yylval.INT);
			default_expire_interval=yylval.INT * 3600;
		}

disk_low_free	: DISK_LOW_FREE_T NUMBER L_EOS {
			printf("DISK_LOW_FREE:\t<<%d %%>>\n", yylval.INT);
			disk_low_free=yylval.INT ;
		}

disk_hi_free	: DISK_HI_FREE_T NUMBER L_EOS {
			printf("DISK_HI_FREE:\t<<%d %%>>\n", yylval.INT);
			disk_hi_free=yylval.INT ;
		}

parent		: PARENT_T string num L_EOS{
			printf("PARENT: %s:%d\n", $2, $3);
			strncpy(parent_host, $2, sizeof(parent_host));
			parent_port = $3;
			free($2);
		}

local_domain	: LOCAL_DOMAIN_T domainlist L_EOS {
		    struct domain_list *d;
			printf ("LOCAL_DOMAIN\n");
			if ( !local_domains) local_domains = $2;
			else {
			    d = $2;
			    while( d ) {
				if ( !d->next ) {
				    d->next = local_domains;
				    local_domains = $2;
				    break;
				}
				d = d->next;
			    }
			}
		}

local_networks	: LOCAL_NETWORKS_T network_list L_EOS {
		    struct cidr_net *n;
			printf ("LOCAL_NETWORKS\n");
			if ( !local_networks) local_networks = $2;
			else {
			    n = local_networks;
			    while( n ) {
				if ( !n->next ) {
				    n->next = $2;
				    break;
				}
				n = n->next;
			    }
			}
		}

dbhome		: DBHOME STRING L_EOS {
			printf("DBHOME:\t<<%s>>\n", yylval.STRPTR);
			strncpy(dbhome, yylval.STRPTR, sizeof(dbhome)-1);
			free(yylval.STRPTR);
		}

dbname		: DBNAME STRING L_EOS {
			printf("DBNAME:\t<<%s>>\n", yylval.STRPTR);
			strncpy(dbname, yylval.STRPTR, sizeof(dbname)-1);
			free(yylval.STRPTR);
		}

mem_max		: MEM_MAX num L_EOS {
			printf("MEM_MAX:\t<<%d>>\n", $2);
			mem_max_val = $2 ;
		}

lo_mark		: LO_MARK num L_EOS {
			printf("LO_MARK:\t<<%d>>\n", $2);
			lo_mark_val = $2 ;
		}

hi_mark		: HI_MARK num L_EOS {
			printf("HI_MARK:\t<<%d>>\n", $2);
			hi_mark_val = $2 ;
		}

num		: NUMBER { $$ = yylval.INT;}

string		: STRING { $$ = yylval.STRPTR; }

module		: MODULE module_name '{' mod_ops '}' L_EOS {
			struct string_list	*list = $4, *next;
#ifdef	MODULES
			struct general_module	*mod = module_by_name($2);
			if ( mod ) {
			    printf("Config %s\n", $2);
			    if ( mod->config_beg ) (*mod->config_beg)();
			    while( list ) {
				printf("send '%s' to %s\n", list->string, $2);
				if (mod->config) (*mod->config)(list->string);
				list = list->next;
			    }
			    if ( mod->config_end ) (*mod->config_end)();
			    printf("Done with %s\n", $2);
			} else {
			    printf("Module %s not found\n", $2);
			}
#else
			printf("Modules was not configured\n");
#endif
			free_string_list($4);
			free($2);
		}
		| MODULE module_name '{' '}' L_EOS {
#ifdef	MODULES
			struct general_module	*mod = module_by_name($2);
			if ( mod && mod->config_beg ) (*mod->config_beg)();
			if ( mod && mod->config_end ) (*mod->config_end)();
#endif
			free($2);
		}
mod_ops		: mod_op {
			$$ = $1;
			printf("mod_op: %s\n", $$->string);
		}
		| mod_ops mod_op {
		    struct string_list *last = $1;
			while ( last->next ) last = last->next;
			last->next = $2;
			$$ = $1;
			printf("mod_op: %s\n", $2->string);
		}

mod_op		: string {
			struct string_list *new = xmalloc(sizeof(*new), "mod_ops");
			char		   *new_str;
			if ( !new ) {
				yyerror();
			}
			bzero(new, sizeof(*new));
			new_str = xmalloc(strlen($1)+1,"mod_op");
			if ( !new_str ) {
				yyerror();
			}
			strcpy(new_str, $1);
			free($1);
			new->string = new_str;
			$$=new;
		}

module_name	: STRING {
			$$ = yylval.STRPTR;
		}


storage		: STORAGE '{' st_ops '}' L_EOS {
		    struct storage_st *new;
		    printf("Storage: %s (size %d bytes)\n", storage_path, storage_size);
		    new = xmalloc(sizeof(*new), "new storage");
		    if ( !new ) {
			yyerror();
		    }
		    bzero(new, sizeof(*new));
		    new->path = storage_path;
		    new->size = storage_size;
		    if ( !storages ) {
			storages = new;
		    } else {
			struct storage_st *tmp = storages;
			while(tmp->next) {
			    tmp=tmp->next;
			}
			tmp->next = new;
		    }
		    storage_path = NULL;
		    storage_size = 0;
		}

peerconfig	: PEER_PARENT_T ';' {
			if ( !peerc_ptr )
				peerc_ptr = &peer_c;
			peerc_ptr->type = PEER_PARENT;
		  }
		| PEER_SIBLING_T ';' {
			if ( !peerc_ptr )
				peerc_ptr = &peer_c;
			peerc_ptr->type = PEER_SIBLING;
		  }
		| allow_acl {
			if ( !peerc_ptr )
				peerc_ptr = &peer_c;
			if ( !peerc_ptr->acls ) {
			    peerc_ptr->acls = malloc(sizeof(struct acls));
			    if ( peerc_ptr->acls ) {
				bzero(peerc_ptr->acls, sizeof(struct acls));
			    } else {
				yyerror();
			    }
			}
			$1->next = peerc_ptr->acls->allow;
			peerc_ptr->acls->allow = $1;
		  }
		| deny_acl {
			if ( !peerc_ptr )
				peerc_ptr = &peer_c;
			if ( !peerc_ptr->acls ) {
			    peerc_ptr->acls = malloc(sizeof(struct acls));
			    if ( peerc_ptr->acls ) {
				bzero(peerc_ptr->acls, sizeof(struct acls));
			    } else {
				yyerror();
			    }
			}
			$1->next = peerc_ptr->acls->deny;
			peerc_ptr->acls->deny = $1;
		  }

peerops		: peerconfig {}
		| peerops peerconfig {}

peer		: PEER_T string num num '{' peerops '}' L_EOS {
			struct	peer *peer,*p;
			peer = malloc(sizeof(struct peer));
			if ( !peer ) {
				yyerror();
			}
			bzero(peer, sizeof(*peer));
			peer->name      = $2;
			peer->http_port = $3;
			peer->icp_port  = $4;
			if ( peerc_ptr ) {
			    peer->type = peerc_ptr->type;
			    peer->acls = peerc_ptr->acls;
			}
			/* insert peer in the list */
			if ( !peers ) {
			    peers = peer;
			} else {
			    p = peers;
			    while ( p->next ) p=p->next;
			    p->next = peer;
			}
			bzero(&peer_c, sizeof(peer_c));
			peerc_ptr = NULL;
		}

st_ops		: st_op {}
		| st_op st_ops {}

st_op		: SIZE num ';' { storage_size = $2; }
		| PATH STRING ';' { storage_path = yylval.STRPTR; }

group		: GROUP group_name '{' group_ops '}' L_EOS {
			struct	group_ops_struct *ops, *next_ops;
			struct	group	*new_grp;

			new_grp = xmalloc(sizeof(*new_grp),"new group");
			if ( !new_grp ) {
				yyerror();
			}
			bzero(new_grp, sizeof(*new_grp));
			pthread_mutex_init(&new_grp->group_mutex, NULL);
			new_grp->name = $2;
			printf("Group '%s'\n", $2);
			ops = $4;
			while ( ops ) {
				next_ops = ops->next;
				switch(ops->op) {
				case OP_NETWORKS:
					new_grp->nets = ops->val;
					break;
				case OP_HTTP:
					new_grp->http = ops->val;
					break;
				case OP_ICP:
					new_grp->icp = ops->val;
					break;
				case OP_BADPORTS:
					new_grp->badports = ops->val;
					break;
				case OP_BANDWIDTH:
					new_grp->bandwidth = (int)ops->val;
					break;
				case OP_MISS:
					new_grp->miss_deny = (int)ops->val;
					break;
				case OP_AUTH_MODS:
					new_grp->auth_mods = ops->val;
					break;
				case OP_REDIR_MODS:
					new_grp->redir_mods = ops->val;
					break;
				default:
					printf("Unknown OP\n");
					break;
				}
				free(ops);
				ops = next_ops;
			}
			new_grp->next = groups;
			groups = new_grp;
		}
group_name	: STRING {
			$$ = yylval.STRPTR;
		}

group_ops	: group_op { $$ = $1;}
		| group_op group_ops { $1->next = $2; $$=$1;}

group_op	: NETWORKS network_list ';' {
			struct	group_ops_struct	*new;
			new = xmalloc(sizeof(*new), "new group_op");
			if ( !new ) yyerror();
			new->op  = OP_NETWORKS;
			new->val = $2;
			new->next= NULL;
			$$ = new;
		}
		| bandwidth	{ $$ = $1; }
		| badports	{ $$ = $1; }
		| http		{ $$ = $1; }
		| icp		{ $$ = $1; }
		| miss		{ $$ = $1; }
		| auth_mods	{ $$ = $1; }
		| redir_mods	{ $$ = $1; }

miss		: MISS_T DENY ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_MISS;
			    printf("MISS DENY\n");
			    new_op->val= (void*)TRUE;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
		| MISS_T ALLOW ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_MISS;
			    printf("MISS ALLOWED\n");
			    new_op->val= (void*)FALSE;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}

auth_mods	: AUTH_MODS_T string_list ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_AUTH_MODS;
			    printf("AUTH_MODS\n");
			    new_op->val= $2;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
redir_mods	: REDIR_MODS_T string_list ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_REDIR_MODS;
			    printf("REDIR_MODS\n");
			    new_op->val= $2;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
bandwidth	: BANDWIDTH_T num ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "new bandwidth");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_BANDWIDTH;
			    printf("Bandwidth %dbytes/sec\n", $2);
			    new_op->val= (void*)$2;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
range		: NUMBER {
			if ( !badp_p ) badp_p = &badports[0];
			badp_p->from = yylval.INT;
			badp_p->length = 1;
			if ( badp_p < &badports[MAXBADPORTS] ) badp_p++;
			    else {
			    printf("You can use max %d badports ranges\n", MAXBADPORTS);
				badp_p--;
			    }
			}
		| '[' num ':' num ']'  {
			if ( !badp_p ) badp_p = &badports[0];
			badp_p->from = $2;
			badp_p->length = $4-$2+1;
			if ( badp_p < &badports[MAXBADPORTS] ) badp_p++;
			    else {
			    printf("You can use max %d badports ranges\n", MAXBADPORTS);
				badp_p--;
			    }
			}

ranges		: range {}
		| range ',' ranges {}

badports	: BADPORTS_T ranges ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "new badports");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    struct range *val;
			    val = xmalloc(sizeof(*val)*MAXBADPORTS, "badports");
			    badp_p = NULL;
			    if ( !val ) {
				yyerror();
				$$=NULL;
			    } else {
				memcpy((void*)val, (void*)&badports, sizeof(badports));
				bzero((void*)&badports, sizeof(badports));
				new_op->op = OP_BADPORTS;
				new_op->val= val;
				new_op->next=NULL;
				$$ = new_op;
			    }
			}
		}

icp		: ICP '{' deny_acls allow_acls '}' {
			struct	acls			*new_acls;
			struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "new http");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "new_acl");
				if ( !new_acls ) {
					printf("No mem at http acl\n");
					yyerror();
					free(new_op);
					$$ = NULL;
				} else {
					new_acls->deny  = $3;
					new_acls->allow = $4;
					new_op->op  = OP_ICP;
					new_op->val = new_acls;
					new_op->next= NULL;
					$$ = new_op;
				}
			}
		}
		| ICP '{' allow_acls deny_acls '}' {
			struct	acls			*new_acls;
			struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "new gr op1");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "new_acl");
				if ( !new_acls ) {
					printf("No mem at http acl\n");
					yyerror();
					free(new_op);
					$$ = NULL;
				} else {
					new_acls->allow = $3;
					new_acls->deny  = $4;
					new_op->op  = OP_ICP;
					new_op->val = new_acls;
					new_op->next= NULL;
					$$ = new_op;
				}
			}
		}
		| ICP '{' allow_acls '}' {
			struct	acls		*new_acls;
			struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "new gr op2");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "new acl2");
				if ( !new_acls ) {
					printf("No mem at icp acl\n");
					yyerror();
					free(new_op);
					$$ = NULL;
				} else {
					new_acls->allow = $3;
					new_acls->deny  = NULL;
					new_op->op  = OP_ICP;
					new_op->val = new_acls;
					new_op->next= NULL;
					$$ = new_op;
				}
			}
		}
		| ICP '{' deny_acls '}' {
			struct	acls		*new_acls;
			struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "new gr op2");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "new acl");
				if ( !new_acls ) {
					printf("No mem at icp acl\n");
					yyerror();
					free(new_op);
					$$ = NULL;
				} else {
					new_acls->deny  = $3;
					new_acls->allow = NULL;
					new_op->op  = OP_ICP;
					new_op->val = new_acls;
					new_op->next= NULL;
					$$ = new_op;
				}
			}
		}

http		: HTTP '{' deny_acls allow_acls '}' {
			struct	acls			*new_acls;
			struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "new http");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "new_acl");
				if ( !new_acls ) {
					printf("No mem at http acl\n");
					yyerror();
					free(new_op);
					$$ = NULL;
				} else {
					new_acls->deny  = $3;
					new_acls->allow = $4;
					new_op->op  = OP_HTTP;
					new_op->val = new_acls;
					new_op->next= NULL;
					$$ = new_op;
				}
			}
		}
		| HTTP '{' allow_acls deny_acls '}'  {
			struct	acls			*new_acls;
			struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "new gr op1");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "new_acl");
				if ( !new_acls ) {
					printf("No mem at http acl\n");
					yyerror();
					free(new_op);
					$$ = NULL;
				} else {
					new_acls->allow = $3;
					new_acls->deny  = $4;
					new_op->op  = OP_HTTP;
					new_op->val = new_acls;
					new_op->next= NULL;
					$$ = new_op;
				}
			}
		}
		| HTTP '{' allow_acls '}' {
			struct	acls		*new_acls;
			struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "new gr op2");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "new acl2");
				if ( !new_acls ) {
					printf("No mem at http acl\n");
					yyerror();
					free(new_op);
					$$ = NULL;
				} else {
					new_acls->allow = $3;
					new_acls->deny  = NULL;
					new_op->op  = OP_HTTP;
					new_op->val = new_acls;
					new_op->next= NULL;
					$$ = new_op;
				}
			}
		}
		| HTTP '{' deny_acls '}' {
			struct	acls		*new_acls;
			struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "new gr op2");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "new acl");
				if ( !new_acls ) {
					printf("No mem at http acl\n");
					yyerror();
					free(new_op);
					$$ = NULL;
				} else {
					new_acls->deny  = $3;
					new_acls->allow = NULL;
					new_op->op  = OP_HTTP;
					new_op->val = new_acls;
					new_op->next= NULL;
					$$ = new_op;
				}
			}
		}
deny_acls	: deny_acl 			{ $$ = $1; }
		| deny_acl deny_acls 		{ $2->next = $1 ; $$ = $2; }

deny_acl	: DENY DSTDOMAIN domainlist ';' { 
			struct acl *new = xmalloc(sizeof(*new), "new acl");
			if ( !new ) {
				printf("No mem for acl\n");
				yyerror();
				$$ = NULL;
			} else {
				$$ = new;
				$$->list = $3 ;
				$$->next = NULL;
				$$->type = ACL_DOMAINDST ;
			}
		}

allow_acls	: allow_acl 			{ $$ = $1; }
		| allow_acl allow_acls 		{ $2->next = $1 ; $$ = $2; }

allow_acl	: ALLOW  DSTDOMAIN domainlist ';' { 
			struct acl *new = xmalloc(sizeof(*new), "new acl");
			if ( !new ) {
				printf("No mem for acl\n");
				yyerror();
				$$ = NULL;
			} else {
				$$ = new;
				$$->list = $3;
				$$->next = NULL;
				$$->type = ACL_DOMAINDST ;
			}
		}

string_list	: string_list_e { $$ = $1; }
		| string_list_e string_list {
			struct string_list *d;
			$1->next = $2; $$ = $1; 
			d = $1;
			while(d) {
				printf("string_list:<%s>\n", d->string);
				d = d->next;
			}
		}
string_list_e	: string {
		struct string_list	*new;
			new = xmalloc(sizeof(*new),"");
			if ( !new ) yyerror();
			new->string = malloc(strlen($1)+1);
			if ( !new->string ) yyerror();
			strcpy(new->string, $1);
			new->next = NULL;
			$$ = new;
			free($1);
		}
domainlist	: domain { $$ = $1; }
		| domain domainlist {
			struct domain_list *d;
			$1->next = $2; $$ = $1; 
			d = $1;
			while(d) {
				printf("<%s>\n", d->domain);
				d = d->next;
			}
		};

domain		: STRING {
			struct	domain_list *new;
			new = xmalloc(sizeof(*new), "new acl");
			if ( !new ) yyerror();
			new->domain = malloc(strlen(yylval.STRPTR)+1);
			if ( !new->domain ) yyerror();
			strcpy(new->domain, yylval.STRPTR);
			if ( !strcmp(yylval.STRPTR, "*") )
				new->length = -1;
			    else
				new->length = strlen(yylval.STRPTR);
			free(yylval.STRPTR);
			new->next = NULL;
			$$ = new;
			}


network_list	: network
		| network network_list {
			$1->next = $2; $$ = $1;
		}

network		: NETWORK {
			char	*n, *l, *dot, *dot_holder, *t;
			int	net = 0, masklen = 0, i = 24;
			struct	cidr_net *new;
			n = yylval.STRPTR;
			l = strchr(n, '/');
			if ( !l ) {
				yyerror();
			}
			*l = 0;
			masklen = atoi(l+1);
			t = n;
			while( ( dot=(char*)strtok_r(t, ".", &dot_holder) ) && (i >=0) ) {
				t = NULL;
				net |= (atol(dot) << i);
				i -= 8;
			}
			new =  xmalloc(sizeof(struct cidr_net), "new acl");
			new->network = net;
			new->masklen = masklen;
			new->next = NULL;
			if ( !masklen )
				new->mask = 0;
			    else {
				if ( (masklen<0) || (masklen>32) ) {
					printf("Invalid masklen %d\n", masklen);
					yyerror();
					return(-1);
				}
				new->mask = (int)0x80000000 >> ( masklen - 1 );
			    }
			printf("NetWork: <<%8.8x/%d & %08x>>\n",  new->network,
							new->masklen,
							new->mask);
			free(yylval.STRPTR);
			$$ = new;
		}

%%

int
readconfig(char *name)
{
FILE		*cf;
int		code;

    cf = fopen(name, "r");
    if ( !cf ) {
	perror("readconfig");
	exit(1);
    }
    yyin = cf;
    atline = 1;
    ns_curr = 0;
    bzero(&peer_c, sizeof(peer_c));
    peerc_ptr = NULL;
    bzero((void*)&badports, sizeof(badports));
    code = yyparse();
    ns_configured = ns_curr;
    fclose(cf);
    printf("Parser returned %d, %d errors found\n", code, parser_errors);
    if ( parser_errors ) code = parser_errors;
    return(code);
}