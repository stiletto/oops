%token	LOGFILE ACCESSLOG STATISTICS PIDFILE NAMESERVER HTTP_PORT ICP_PORT
%token	ICONS_HOST ICONS_PORT ICONS_PATH EXPIRE_VALUE FTP_EXPIRE_VALUE_T EXPIRE_INTERVAL
%token	STOP_CACHE MAXRESIDENT MINRESIDENT CONNECT_FROM
%token	MEM_MAX LO_MARK HI_MARK DISK_LOW_FREE_T DISK_HI_FREE_T
%token	PARENT_T PEER_T SIBLING_T LOCAL_DOMAIN_T LOCAL_NETWORKS_T
%token	GROUP NETWORK NETWORKS HTTP ICP
%token	NUMBER NUMBER_K NUMBER_M STRING
%token	ALLOW DENY BADPORTS_T MISS_T AUTH_MODS_T REDIR_MODS_T
%token	DSTDOMAIN DB_CACHE_MEM
%token	STORAGE SIZE PATH DBNAME DBHOME
%token	PEER_PARENT_T PEER_SIBLING_T BANDWIDTH_T DENYTIME_T
%token	L_EOS ICP_TIMEOUT MODULE INCLUDE_T
%token	ALWAYS_CHECK_FRESHNESS_T FORCE_HTTP11_T FORCE_COMPLETION_T
%token	LAST_MODIFIED_FACTOR_T MAX_EXPIRE_VALUE_T
%token	INSERT_X_FORWARDED_FOR_T INSERT_VIA_T ACL_T REFRESH_PATTERN_T
%token	ACL_ALLOW_T ACL_DENY_T SRCDOMAINS_T BIND_T STOP_CACHE_ACL_T
%token	NETWORKS_ACL_T STORAGE_OFFSET_T AUTO_T USERID_T CHROOT_T
%token	BIND_ACL_T MAXREQRATE_T BLACKLIST_T START_RED_T REFUSE_AT_T
%token	DONT_CACHE_WITHOUT_LAST_MODIFIED_T MY_AUTH_T PARENT_AUTH_T
%token	PEER_ACCESS_T PER_SESS_BW_T PER_IP_BW_T PER_IP_CONN_T CONN_FROM_T
%token	ALWAYS_CHECK_FRESHNESS_ACL_T PEER_DOWN_TIMEOUT_T
%token	EXPIRE_TIME_T SWAP_ADVANCE_T FETCH_WITH_CLIENT_SPEED_T
%token  FTP_PASSW_T NEGATIVE_CACHE_T

%type	<NETPTR>	network_list network
%type	<STRPTR>	group_name string module_name
%type	<STRING_LIST>	mod_op mod_ops string_list string_list_e
%type	<GROUPOPS>	group_op group_ops
%type	<GROUPOPS>	http icp badports bandwidth miss auth_mods redir_mods
%type	<GROUPOPS>	denytime per_sess_bw per_ip_bw per_ip_conn conn_from
%type	<STORAGEST>	st_op st_ops
%type	<INT>		num
%type	<OFFSET>	offset
%type	<ACL>		allow_acl deny_acl allow_acls deny_acls
%type	<DOMAIN>	domain domainlist

%{

#include	"oops.h"
#include	"modules.h"

extern	FILE	*yyin;

int	atline;
char	*conf_file_name;
int	parser_errors;

static	char	*storage_path = NULL;
static	off_t	storage_size = 0;
static	off_t	storage_offset = 0;
static	int	ns_curr;

static	struct	peer_c	*peerc_ptr = NULL;
static	struct	range	badports[MAXBADPORTS];
static	struct	range	*badp_p = NULL;
struct	peer_c {
	char			type;
	struct	acls		*acls;
	char			*my_auth;
	acl_chk_list_hdr_t	*peer_access;
	int			down_timeout;
} peer_c = {PEER_SIBLING,NULL,NULL,NULL, 60};

static	void			add_to_stop_cache(char *);
static	struct	domain_list	*load_domlist_from_file(char *);
static	struct	domain_list	*load_domlist_from_list(struct string_list *);
static	int			string_to_days(struct denytime *, struct string_list *);

%}

%union	{
	int				INT;
	char				*STRPTR;
	char				CHAR;
	struct	cidr_net		*NETPTR;
	struct	group_ops_struct	*GROUPOPS;
	struct	acl			*ACL;
	struct	domain_list		*DOMAIN;
	struct	storage_st		*STORAGEST;
	struct	string_list		*STRING_LIST;
	off_t				OFFSET;
	}



%%

config		: /* empty */
		| statement
		| statements statement
		;

statements	: statement
		| statements statement
		;

statement	: logfile
		| accesslog
		| statistics
		| pidfile
		| nameserver
		| bind
		| connect_from
		| http_port
		| icp_port
		| icp_timeout
		| icons_host
		| icons_path
		| icons_port
		| expire_value
		| max_expire_value
		| ftp_expire_value
		| expire_interval
		| expiretime
		| last_modified_factor
		| always_check_freshness
		| always_check_freshness_acl
		| force_http11
		| force_completion
		| disk_low_free
		| disk_hi_free
		| parent
		| parent_auth
		| local_domain
		| local_networks
		| stop_cache
		| maxresident
		| minresident
		| mem_max
		| negative_cache
		| lo_mark
		| hi_mark
		| swap_advance
		| group
		| peer
		| storage
		| insert_x_forwarded_for
		| insert_via
		| dbhome
		| dbname
		| db_cache_mem
		| module
		| acl
		| refresh_pattern
		| acl_allow
		| acl_deny
		| stop_cache_acl
		| userid
		| anon_ftp_passw
		| chroot
		| bind_acl
		| blacklist
		| start_red
		| refuse_at
		| fetch_with_client_speed
		| dont_cache_without_last_modified
		| error L_EOS {
			yyerrok;
		  }
		| L_EOS
		;

logfile		: LOGFILE string L_EOS {
			verb_printf("LOGFILE:\t<<%s>>\n", $2);
			strncpy(logfile, $2, sizeof(logfile)-1);
			free($2);
			logfile_buffered = FALSE;
			printf("Making logfile %s unbuffered.\n", logfile);
		}
		| LOGFILE string string L_EOS {
			verb_printf("LOGFILE:\t<<%s>>\n", $2);
			strncpy(logfile, $2, sizeof(logfile)-1);
			free($2);
			if ( !strcasecmp($3, "buffered") ) {
			    logfile_buffered = TRUE;
			    printf("Making logfile %s buffered.\n", logfile);
			} else if ( !strcasecmp($3, "unbuffered") ) {
			    logfile_buffered = FALSE;
			    printf("Making logfile %s unbuffered.\n", logfile);
			} else {
			    printf("Last parameter of logfile statement can be `buffered' or `unbuffered': %s\n", $3);
			    logfile_buffered = FALSE;
			    printf("Making logfile %s unbuffered.\n", logfile);
			}
			free($3);
		}
		| LOGFILE string '{' num num '}' L_EOS {
			verb_printf("LOGFILE:\t<<%s>> num: %d, size: %d\n",
			$2, $4, $5);
			strncpy(logfile, $2, sizeof(logfile)-1);
			log_num = $4;
			log_size = $5;
			free($2);
			logfile_buffered = FALSE;
			printf("Making logfile %s unbuffered.\n", logfile);
		}
		| LOGFILE string '{' num num '}' string L_EOS {
			verb_printf("LOGFILE:\t<<%s>> num: %d, size: %d\n",
			$2, $4, $5);
			strncpy(logfile, $2, sizeof(logfile)-1);
			log_num = $4;
			log_size = $5;
			free($2);
			if ( !strcasecmp($7, "buffered") ) {
			    logfile_buffered = TRUE;
			    printf("Making logfile %s buffered.\n", logfile);
			} else if ( !strcasecmp($7, "unbuffered") ) {
			    logfile_buffered = FALSE;
			    printf("Making logfile %s unbuffered.\n", logfile);
			} else {
			    printf("Last parameter of logfile statement can be `buffered' or `unbuffered': %s\n", $7);
			    logfile_buffered = FALSE;
			    printf("Making logfile %s unbuffered.\n", logfile);
			}
			free($7);
		}
		;

userid		: USERID_T string L_EOS {
			oops_user = $2;
		}
		;
anon_ftp_passw  : FTP_PASSW_T string L_EOS {
                        ftp_passw = $2;
                }
                ;
chroot		: CHROOT_T string L_EOS {
			oops_chroot = $2;
		}
		;
blacklist	: BLACKLIST_T num L_EOS {
			blacklist_len = $2;
		}
		;
refuse_at	: REFUSE_AT_T num L_EOS {
			refuse_at = $2;
		}
		;
start_red	: START_RED_T num L_EOS {
			start_red = $2;
		}
		;
dont_cache_without_last_modified : DONT_CACHE_WITHOUT_LAST_MODIFIED_T L_EOS {
			dont_cache_without_last_modified = TRUE;
		}
		;
insert_x_forwarded_for : INSERT_X_FORWARDED_FOR_T string L_EOS {
			if ( !strcasecmp(yylval.STRPTR, "yes") )
				insert_x_forwarded_for = TRUE;
			   else
			if (!strcasecmp(yylval.STRPTR, "no") )
				insert_x_forwarded_for = FALSE;
			   else
				printf("insert_x_forwarded_for can be 'yes' or 'no'\n");
			free(yylval.STRPTR);
		}
		;
fetch_with_client_speed : FETCH_WITH_CLIENT_SPEED_T string L_EOS {
			if ( !strcasecmp(yylval.STRPTR, "yes") )
				fetch_with_client_speed = TRUE;
			   else
			if (!strcasecmp(yylval.STRPTR, "no") )
				fetch_with_client_speed = FALSE;
			   else
				printf("fetch_with_client_speed can be 'yes' or 'no'\n");
			free(yylval.STRPTR);
		}
		;
insert_via	: INSERT_VIA_T string L_EOS {
			if ( !strcasecmp(yylval.STRPTR, "yes") )
				insert_via = TRUE;
			   else
			if (!strcasecmp(yylval.STRPTR, "no") )
				insert_via = FALSE;
			   else
				printf("insert_via can be 'yes' or 'no'\n");
			free(yylval.STRPTR);
		}
		;
accesslog	: ACCESSLOG string L_EOS {
			verb_printf("ACCESSLOG:\t<<%s>>\n", $2);
			strncpy(accesslog, $2, sizeof(accesslog)-1);
			accesslog_num = accesslog_size = 0;
			free($2);
			accesslog_buffered = FALSE;
			printf("Making accesslog %s unbuffered.\n", accesslog);
		}
		| ACCESSLOG string string L_EOS {
			verb_printf("ACCESSLOG:\t<<%s>>\n",
			$2);
			strncpy(accesslog, $2, sizeof(accesslog)-1);
			free($2);
			if ( !strcasecmp($3, "buffered") ) {
			    accesslog_buffered = TRUE;
			    printf("Making accesslog %s buffered.\n", accesslog);
			} else if ( !strcasecmp($3, "unbuffered") ) {
			    accesslog_buffered = FALSE;
			    printf("Making accesslog %s unbuffered.\n", accesslog);
			} else {
			    printf("Last parameter of accesslog statement can be `buffered' or `unbuffered': %s\n", $3);
			    accesslog_buffered = FALSE;
			    printf("Making accesslog %s unbuffered.\n", accesslog);
			}
			free($3);
		}
		| ACCESSLOG string '{' num num '}' L_EOS {
			verb_printf("ACCESSLOG:\t<<%s>> num: %d, size: %d\n",
			$2, $4, $5);
			strncpy(accesslog, $2, sizeof(accesslog)-1);
			accesslog_num = $4;
			accesslog_size = $5;
			free($2);
			accesslog_buffered = FALSE;
			printf("Making accesslog %s unbuffered.\n", accesslog);
		}
		| ACCESSLOG string '{' num num '}' string L_EOS {
			verb_printf("ACCESSLOG:\t<<%s>> num: %d, size: %d\n",
			$2, $4, $5);
			strncpy(accesslog, $2, sizeof(accesslog)-1);
			accesslog_num = $4;
			accesslog_size = $5;
			free($2);
			if ( !strcasecmp($7, "buffered") ) {
			    accesslog_buffered = TRUE;
			    printf("Making accesslog %s buffered.\n", accesslog);
			} else if ( !strcasecmp($7, "unbuffered") ) {
			    accesslog_buffered = FALSE;
			    printf("Making accesslog %s unbuffered.\n", accesslog);
			} else {
			    printf("Last parameter of accesslog statement can be `buffered' or `unbuffered': %s\n", $7);
			    accesslog_buffered = FALSE;
			    printf("Making accesslog %s unbuffered.\n", accesslog);
			}
			free($7);
		}
		;
refresh_pattern	: REFRESH_PATTERN_T string num string num L_EOS {
			char	*buf;
			int	len;
			len = strlen($2) + strlen($4) + 20 ;
			buf = malloc(len);
			if ( buf ) {
			    snprintf(buf, len, "%s %d %s %d", $2, $3, $4, $5);
			    parse_refresh_pattern(&global_refresh_pattern, buf);
			    free(buf);
			}
			free($2);
			free($4);
		}
		;
bind_acl	: BIND_ACL_T STRING L_EOS {
			parse_bind_acl(yylval.STRPTR);
			free(yylval.STRPTR);
		}
		;
acl_allow	: ACL_ALLOW_T STRING L_EOS {
			parse_acl_access(&acl_allow, yylval.STRPTR);
			free(yylval.STRPTR);
		}
		;
acl_deny	: ACL_DENY_T  STRING L_EOS {
			parse_acl_access(&acl_deny, yylval.STRPTR);
			free(yylval.STRPTR);
		}
		;
stop_cache_acl	: STOP_CACHE_ACL_T  STRING L_EOS {
			parse_acl_access(&stop_cache_acl, yylval.STRPTR);
			free(yylval.STRPTR);
		}
		;
acl		: ACL_T	STRING L_EOS {
			char		  *token, *p, *tptr;
			char		  *n=NULL, *type=NULL, *data=NULL;
			struct	named_acl *new_acl;
			int		  acl_type, res;

			printf("Named ACL %s\n", yylval.STRPTR);
			new_acl = malloc(sizeof(*new_acl));
			if ( !new_acl ) goto error;
			bzero(new_acl, sizeof(*new_acl));
			/* must be 
			   name type data
			*/
			p = yylval.STRPTR;
			printf("DATA: %s\n", p);
			tptr = p;
			while( 1 ) {
			    char	op;
			    token = p+1;
			    while ( *token && IS_SPACE(*token) ) token++;
			    if ( !*token ) break;
			    p = token; while ( *p && !IS_SPACE(*p) ) p++;
			    op = *p;
			    *p = 0;
			    if ( !n ) {
				n = token;
				strncpy((char*)&new_acl->name, n, sizeof(new_acl->name)-1);
				continue;
			    }
			    if ( !type ) {
				type = token;
				acl_type = named_acl_type_by_name(type);
				if ( acl_type == -1 ) {
				    printf("Unknown acl type %s\n", type);
				    goto error;
				}
				new_acl->type = acl_type;
				continue;
			    }
			    if ( !data ) {
				data = token;
				*p = op;
				break;
			    }
			}
			if ( !data ) goto error;
			res = parse_named_acl_data(new_acl, data);
			if ( res ) {
			    printf("Unparsable acl data `%s'.\n", data);
			    goto error;
			}
			insert_named_acl_in_list(new_acl);
			goto done;
		error:
			if ( new_acl ) free_named_acl(new_acl);
		done:;
			free(yylval.STRPTR);
		}
		;
statistics	: STATISTICS STRING L_EOS {
			verb_printf("STATISTICS:\t<<%s>>\n", yylval.STRPTR);
			strncpy(statisticslog, yylval.STRPTR, sizeof(statisticslog)-1);
			free(yylval.STRPTR);
		}
		;
pidfile		: PIDFILE STRING L_EOS {
			verb_printf("PIDFILE:\t<<%s>>\n", yylval.STRPTR);
			strncpy(pidfile, yylval.STRPTR, sizeof(pidfile)-1);
			free(yylval.STRPTR);
		}
		;
nameserver	: NAMESERVER STRING L_EOS {
			verb_printf("NAMESERVER:\t<<%s>>\n", yylval.STRPTR);
			if ( ns_curr < OOPSMAXNS ) {
			    bzero(&ns_sa[ns_curr], sizeof(ns_sa[ns_curr]));
			    ns_sa[ns_curr].sin_family = AF_INET;
#if	!defined(SOLARIS) && !defined(LINUX) && !defined(OSF) && !defined(_WIN32)
			    ns_sa[ns_curr].sin_len = sizeof(ns_sa[ns_curr]);
#endif
			    ns_sa[ns_curr].sin_addr.s_addr = inet_addr(yylval.STRPTR);
			    ns_sa[ns_curr].sin_port = htons(53);
			    ns_curr++;
			} else {
			    verb_printf("You can configure maximum %d nameservers\n", OOPSMAXNS);
			}
			free(yylval.STRPTR);
		}
		;
connect_from	: CONNECT_FROM STRING L_EOS {
			char	*p;
			strncpy(connect_from, yylval.STRPTR, sizeof(connect_from)-1);
			free(yylval.STRPTR);
			p = connect_from;
			while ( *p ) { *p=tolower(*p); p++; }
			verb_printf("CONNECT_FROM:\t<<%s>>\n", connect_from);
		}
		;
stop_cache	: STOP_CACHE STRING L_EOS {
			verb_printf("STOP_CACHE:\t<<%s>>\n", yylval.STRPTR);
			add_to_stop_cache(yylval.STRPTR);
		}
		;
maxresident	: MAXRESIDENT NUMBER L_EOS {
			verb_printf("MAXRESIDENT:\t %d\n", yylval.INT);
			maxresident = yylval.INT;
		}
		;
minresident	: MINRESIDENT NUMBER L_EOS {
			verb_printf("MINRESIDENT:\t %d\n", yylval.INT);
			minresident = yylval.INT;
		}
		;
bind		: BIND_T string L_EOS {
			bind_addr = $2;
		}
		;
http_port	: HTTP_PORT NUMBER L_EOS {
			verb_printf("HTTP_PORT\t<<%d>>\n", yylval.INT);
			http_port = yylval.INT;
		}
		;
icp_port	: ICP_PORT NUMBER L_EOS {
			verb_printf("ICP_PORT\t<<%d>>\n", yylval.INT);
			icp_port = yylval.INT;
		}
		;
icp_timeout	: ICP_TIMEOUT NUMBER L_EOS {
			verb_printf("ICP_TIMEOUT\t<<%d>>\n", yylval.INT);
			icp_timeout = 1000*yylval.INT;
		}
		;
negative_cache	: NEGATIVE_CACHE_T NUMBER L_EOS {
			verb_printf("NEGATIVE_CACHE\t<<%d>>\n", yylval.INT);
			negative_cache = yylval.INT;
		}
		;
icons_host	: ICONS_HOST STRING L_EOS {
			verb_printf("ICONS_HOST:\t<<%s>>\n", yylval.STRPTR);
			strncpy(icons_host, yylval.STRPTR, sizeof(icons_host)-1);
			free(yylval.STRPTR);
		}
		;
icons_port	: ICONS_PORT NUMBER L_EOS {
			verb_printf("ICONS_PORT:\t<<%d>>\n", yylval.INT);
			sprintf(icons_port, "%d", yylval.INT);
		}
		;
icons_path	: ICONS_PATH STRING L_EOS {
			verb_printf("ICONS_PATH:\t<<%s>>\n", yylval.STRPTR);
			strncpy(icons_path, yylval.STRPTR, sizeof(icons_path)-1);
			free(yylval.STRPTR);
		}
		;
always_check_freshness : ALWAYS_CHECK_FRESHNESS_T L_EOS {
			verb_printf("ALWAYS CHECK FRESHNESS\n");
			always_check_freshness = TRUE;
		}
		;
always_check_freshness_acl : ALWAYS_CHECK_FRESHNESS_ACL_T STRING L_EOS {
			verb_printf("ALWAYS CHECK FRESHNESS ACL\n");
			parse_acl_access(&always_check_freshness_acl, yylval.STRPTR);
			free(yylval.STRPTR);
		}
		;
force_http11	: FORCE_HTTP11_T L_EOS {
			verb_printf("FORCE_HTTP11\n");
			force_http11 = TRUE;
		}
		;
force_completion : FORCE_COMPLETION_T NUMBER L_EOS {
			verb_printf("FORCE_COMPLETION: %d%%\n", yylval.INT);
			force_completion = yylval.INT;
		}
		;
last_modified_factor : LAST_MODIFIED_FACTOR_T NUMBER L_EOS {
			verb_printf("LAST_MODIFIED_FACTOR: %d\n", yylval.INT);
			last_modified_factor = yylval.INT;
		}
		;
expire_value	: EXPIRE_VALUE NUMBER L_EOS {
			verb_printf("EXPIRE_VALUE:\t<<%d days>>\n", yylval.INT);
			default_expire_value=yylval.INT * 24 * 3600;
		}
		;
expiretime	: EXPIRE_TIME_T string_list {
		    struct	denytime		*denytime;
		    int		start_m, end_m;
		    char m1[10], m2[10];

		    expiretime = xmalloc(sizeof(*expiretime), "");
		    if ( expiretime != NULL ) {
		        bzero(expiretime, sizeof(*expiretime));
		        string_to_days(expiretime, $2);
		    }
		    free_string_list($2);
		}
		;
max_expire_value : MAX_EXPIRE_VALUE_T NUMBER L_EOS {
			verb_printf("MAX_EXPIRE_VALUE:\t<<%d days>>\n", yylval.INT);
			max_expire_value=yylval.INT * 24 * 3600;
		}
		;
ftp_expire_value : FTP_EXPIRE_VALUE_T NUMBER L_EOS {
			verb_printf("FTP_EXPIRE_VALUE:\t<<%d days>>\n", yylval.INT);
			ftp_expire_value=yylval.INT * 24 * 3600;
		}
		;
expire_interval	: EXPIRE_INTERVAL NUMBER L_EOS {
			verb_printf("EXPIRE_INTERVAL:<<%d hours>>\n", yylval.INT);
			default_expire_interval=yylval.INT * 3600;
		}
		;
disk_low_free	: DISK_LOW_FREE_T NUMBER L_EOS {
			verb_printf("DISK_LOW_FREE:\t<<%d %%>>\n", yylval.INT);
			disk_low_free=yylval.INT ;
		}
		;
disk_hi_free	: DISK_HI_FREE_T NUMBER L_EOS {
			verb_printf("DISK_HI_FREE:\t<<%d %%>>\n", yylval.INT);
			disk_hi_free=yylval.INT ;
		}
		;
parent		: PARENT_T string num L_EOS{
			verb_printf("PARENT: %s:%d\n", $2, $3);
			strncpy(parent_host, $2, sizeof(parent_host));
			parent_port = $3;
			free($2);
		}
		;
parent_auth	: PARENT_AUTH_T string L_EOS{
			verb_printf("PARENT_AUTH: %s\n", $2);
			parent_auth = base64_encode($2);
			free($2);
		}
		;
local_domain	: LOCAL_DOMAIN_T domainlist L_EOS {
		    struct domain_list *d;
			verb_printf ("LOCAL_DOMAIN\n");
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
		;
local_networks	: LOCAL_NETWORKS_T network_list L_EOS {
		    struct cidr_net *n;
			verb_printf ("LOCAL_NETWORKS\n");
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
		;
dbhome		: DBHOME STRING L_EOS {
			printf("WARNING!!!! dbhome must be moved to module berkeley_db\n");
			free(yylval.STRPTR);
		}
		;
dbname		: DBNAME STRING L_EOS {
			printf("WARNING!!!! dbname must be moved to module berkeley_db\n");
			free(yylval.STRPTR);
		}
		;
db_cache_mem    : DB_CACHE_MEM num L_EOS {
			printf("WARNING!!!! db_cache_mem must be moved to module berkeley_db\n");
		}
		;
mem_max		: MEM_MAX num L_EOS {
			verb_printf("MEM_MAX:\t<<%d>>\n", $2);
			mem_max_val = $2 ;
		}
		;
lo_mark		: LO_MARK num L_EOS {
			verb_printf("LO_MARK:\t<<%d>>\n", $2);
			lo_mark_val = $2 ;
		}
		;
swap_advance	: SWAP_ADVANCE_T num L_EOS {
			verb_printf("SWAP_ADVANCE:\t<<%d>>\n", $2);
			swap_advance = $2 ;
			if ( swap_advance <= 0 ) swap_advance = 1;
		}
		;
hi_mark		: HI_MARK num L_EOS {
			verb_printf("HI_MARK:\t<<%d>>\n", $2);
			hi_mark_val = $2 ;
		}
		;
num		: NUMBER { $$ = yylval.INT;}
		;
offset		: NUMBER { $$ = yylval.OFFSET;}
		;
string		: STRING { $$ = yylval.STRPTR; }
		;
module		: MODULE module_name '{' mod_ops '}' L_EOS {
			struct string_list	*list = $4;
			struct general_module	*mod;
			char			*modname, *inst;
			int			instance = 0;

			modname = $2;
			if ( (inst = strchr($2, '/')) ) {
			    *inst = 0;
			    instance = atoi(++inst);
			}
			mod = module_by_name(modname);
			if ( mod ) {
			    verb_printf("Config %s / %d\n", modname, instance);
			    if ( mod->config_beg ) (*mod->config_beg)(instance);
			    while( list ) {
				verb_printf("send `%s' to `%s'.\n", list->string, $2);
				if (mod->config) (*mod->config)(list->string, instance);
				list = list->next;
			    }
			    if ( mod->config_end ) (*mod->config_end)(instance);
			    verb_printf("Done with %s / %d\n", modname, instance);
			} else {
			    verb_printf("Module %s not found\n", modname);
			}
			free_string_list($4);
			free($2);
		}
		| MODULE module_name '{' '}' L_EOS {
			struct general_module	*mod = module_by_name($2);
			if ( mod && mod->config_beg ) (*mod->config_beg)(0);
			if ( mod && mod->config_end ) (*mod->config_end)(0);
			free($2);
		}
		;
mod_ops		: mod_op {
			$$ = $1;
			verb_printf("mod_op: %s\n", $$->string);
		}
		| mod_ops mod_op {
		    struct string_list *last = $1;
			while ( last->next ) last = last->next;
			last->next = $2;
			$$ = $1;
			verb_printf("mod_op: %s\n", $2->string);
		}
		;
mod_op		: string {
			struct string_list *new = xmalloc(sizeof(*new), "parser: mod_ops");
			char		   *new_str;
			if ( !new ) {
				yyerror();
			}
			bzero(new, sizeof(*new));
			new_str = xmalloc(strlen($1)+1,"parser: mod_op");
			if ( !new_str ) {
				yyerror();
			}
			strcpy(new_str, $1);
			free($1);
			new->string = new_str;
			$$=new;
		}
		;
module_name	: STRING {
			$$ = yylval.STRPTR;
		}
		;

storage		: STORAGE '{' st_ops '}' L_EOS {
		    struct storage_st *new;
#if	defined(WITH_LARGE_FILES)
		    verb_printf("Storage: %s (size %lld bytes)\n", storage_path, storage_size);
#else
		    verb_printf("Storage: %s (size %d bytes)\n", storage_path, storage_size);
#endif
		    new = calloc(1, sizeof(*new));
		    if ( !new ) {
			yyerror();
		    }
		    bzero(new, sizeof(*new));
		    new->path = storage_path;
		    new->size = storage_size;
		    new->i_off = storage_offset;
		    new->fd = -1;
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
		    storage_offset = 0;
		}
		;
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
		| PEER_DOWN_TIMEOUT_T num ';' {
			if ( !peerc_ptr )
				peerc_ptr = &peer_c;
			peerc_ptr->down_timeout = $2 ;
		  }
		| MY_AUTH_T string ';' {
			if ( !peerc_ptr )
				peerc_ptr = &peer_c;
			peerc_ptr->my_auth = base64_encode($2);
			free($2);
		  }
		| PEER_ACCESS_T STRING ';' {
			if ( !peerc_ptr )
				peerc_ptr = &peer_c;
			verb_printf("PEER_ACCESS: %s\n", yylval.STRPTR);
			parse_acl_access(&peerc_ptr->peer_access, yylval.STRPTR);
			free(yylval.STRPTR);
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
		;
peerops		: peerconfig {}
		| peerops peerconfig {}
		;
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
			peer->state	= PEER_DOWN;
			if ( peerc_ptr ) {
			    peer->type = peerc_ptr->type;
			    peer->acls = peerc_ptr->acls;
			    peer->my_auth = peerc_ptr->my_auth;
			    peer->peer_access = peerc_ptr->peer_access;
			    peer->down_timeout = peerc_ptr->down_timeout;
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
			peer_c.type = PEER_SIBLING;
			peerc_ptr = NULL;
		}
		;
st_ops		: st_op {}
		| st_op st_ops {}
		;
st_op		: SIZE offset ';' { storage_size = $2; }
		| SIZE AUTO_T ';' { storage_size = -1; }
		| STORAGE_OFFSET_T offset ';' {storage_offset = $2; }
		| PATH STRING ';' { storage_path = yylval.STRPTR; }
		;
group		: GROUP group_name '{' group_ops '}' L_EOS {
			struct	group_ops_struct *ops, *next_ops;
			struct	group	*new_grp, *g;

			new_grp = xmalloc(sizeof(*new_grp),"parser: new group");
			if ( !new_grp ) {
				yyerror();
			}
			bzero(new_grp, sizeof(*new_grp));
			pthread_mutex_init(&new_grp->group_mutex, NULL);
			new_grp->name = $2;
			verb_printf("Group `%s'.\n", $2);
			ops = $4;
			while ( ops ) {
				next_ops = ops->next;
				switch(ops->op) {
				case OP_NETWORKS:
					new_grp->nets = ops->val;
					break;
				case OP_SRCDOMAINS:
					new_grp->srcdomains = ops->val;
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
				case OP_PER_SESS_BW:
					new_grp->per_sess_bw = (int)ops->val;
					break;
				case OP_PER_IP_BW:
					new_grp->per_ip_bw = (int)ops->val;
					break;
				case OP_PER_IP_CONN:
					new_grp->per_ip_conn = (int)ops->val;
					break;
				case OP_CONN_FROM:
					memcpy(&new_grp->conn_from_sa, ops->val, sizeof(new_grp->conn_from_sa));
					free(ops->val);
					break;
				case OP_MISS:
					new_grp->miss_deny = (int)ops->val;
					break;
				case OP_MAXREQRATE:
					new_grp->maxreqrate = (int)ops->val;
					break;
				case OP_AUTH_MODS:
					if ( ops->val ) {
					    new_grp->auth_mods =
						malloc(sizeof(*new_grp->auth_mods));
					    if (new_grp->auth_mods) {
						bzero(new_grp->auth_mods, sizeof(*new_grp->auth_mods));
						new_grp->auth_mods->list = ops->val;
						new_grp->auth_mods->refs = 1;
						pthread_mutex_init(&new_grp->auth_mods->lock, NULL);
					    }
					} else
					    new_grp->auth_mods = NULL;;
					break;
				case OP_REDIR_MODS:
					if ( ops->val ) {
					    new_grp->redir_mods =
						malloc(sizeof(*new_grp->redir_mods));
					    if (new_grp->redir_mods) {
						struct string_list	*l = ops->val;
						mod_call_t		*mc, *last=NULL;
						char			*sl;

						bzero(new_grp->redir_mods, sizeof(*new_grp->redir_mods));
						while ( l ) {
						    mc = calloc(1, sizeof(*mc));
						    if ( mc ) {
							if ( !last ) {
							    new_grp->redir_mods->list = mc;
							} else {
							    last->next = mc;
							}
							last = mc;
							strncpy(mc->mod_name, l->string, sizeof(mc->mod_name)-1);
							if ( (sl = strchr(mc->mod_name, '/')) ) {
							    *sl = 0;
							    mc->mod_instance = atoi(sl+1);
							}
							printf("%s:%d\n", mc->mod_name, mc->mod_instance);
						    }
						    l = l->next;
						}
						free_string_list(ops->val);
						new_grp->redir_mods->refs = 1;
						pthread_mutex_init(&new_grp->redir_mods->lock, NULL);
					    }
					} else
					    new_grp->redir_mods = NULL;;
					break;
				case OP_DENYTIME:
					((struct denytime*)(ops->val))->next = 
						new_grp->denytimes;
					new_grp->denytimes = ops->val;
					break;
				case OP_NETWORKS_ACL:
					/* list of acl
					   all must be known, all must be src_ip
					*/
					parse_networks_acl(&new_grp->networks_acl,
							  ops->val);
					free_string_list(ops->val);
					break;
				default:
					verb_printf("Unknown OP\n");
					break;
				}
				free(ops);
				ops = next_ops;
			}
			new_grp->next = 0;
			/* create acl/dstdomain cache */
			new_grp->dstdomain_cache = hash_init(128, HASH_KEY_STRING);
			if ( ! groups ) groups = new_grp;
                            else {
                                g = groups;
                                while( g->next ) g = g->next;
                                g->next = new_grp;
                        }
		}
		;
group_name	: STRING {
			$$ = yylval.STRPTR;
		}
		;
group_ops	: group_op { $$ = $1;}
		| group_op group_ops { $1->next = $2; $$=$1;}
		;
group_op	: NETWORKS network_list ';' {
			struct	group_ops_struct	*new;
			new = xmalloc(sizeof(*new), "parser: new group_op");
			if ( !new ) yyerror();
			new->op  = OP_NETWORKS;
			new->val = $2;
			new->next= NULL;
			$$ = new;
		}
		| SRCDOMAINS_T INCLUDE_T string ';' L_EOS {
		}
		| SRCDOMAINS_T domainlist ';' {
			struct	group_ops_struct	*new;
			new = xmalloc(sizeof(*new), "parser: new group_op");
			if ( !new ) yyerror();
			new->op  = OP_SRCDOMAINS;
			new->val = $2;
			new->next= NULL;
			$$ = new;
		}
		| NETWORKS_ACL_T string_list ';' {
			struct	group_ops_struct	*new;
			new = xmalloc(sizeof(*new), "parser: new group_op");
			if ( !new ) yyerror();
			new->op  = OP_NETWORKS_ACL;
			new->val = $2;
			new->next= NULL;
			$$ = new;
		}
		| MAXREQRATE_T num ';' {
			struct	group_ops_struct	*new;
			new = xmalloc(sizeof(*new), "parser: new group_op");
			if ( !new ) yyerror();
			new->op  = OP_MAXREQRATE;
			new->val = (void*)$2;
			new->next= NULL;
			$$ = new;
		}
		| bandwidth	{ $$ = $1; }
		| per_sess_bw	{ $$ = $1; }
		| per_ip_bw	{ $$ = $1; }
		| per_ip_conn	{ $$ = $1; }
		| conn_from	{ $$ = $1; }
		| badports	{ $$ = $1; }
		| http		{ $$ = $1; }
		| icp		{ $$ = $1; }
		| miss		{ $$ = $1; }
		| denytime	{ $$ = $1; }
		| auth_mods	{ $$ = $1; }
		| redir_mods	{ $$ = $1; }
		;
denytime	: DENYTIME_T string_list {
		    struct	group_ops_struct	*new_op;
		    struct	denytime		*denytime;
		    int		start_m, end_m;
			new_op = xmalloc(sizeof(*new_op), "parser: denytime 1");
			denytime = xmalloc(sizeof(*denytime), "parser: denytime 2");
			if ( !new_op || !denytime ) {
				yyerror();
				$$ = NULL;
			} else {
			    char m1[10], m2[10];
			    new_op->op = OP_DENYTIME;
			    bzero(denytime, sizeof(*denytime));
			    string_to_days(denytime, $2);
			    new_op->val= (void*)denytime;
			    new_op->next=NULL;
			    $$ = new_op;
			}
			free_string_list($2);
		}
		;
miss		: MISS_T DENY ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "parser: miss 1");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_MISS;
			    verb_printf("MISS DENY\n");
			    new_op->val= (void*)TRUE;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
		| MISS_T ALLOW ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "parser: miss 2");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_MISS;
			    verb_printf("MISS ALLOWED\n");
			    new_op->val= (void*)FALSE;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
		;
auth_mods	: AUTH_MODS_T string_list ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "parser: auth_mods");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_AUTH_MODS;
			    verb_printf("AUTH_MODS\n");
			    new_op->val= $2;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
		;
redir_mods	: REDIR_MODS_T string_list ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "parser: redir_mods");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_REDIR_MODS;
			    verb_printf("REDIR_MODS\n");
			    new_op->val= $2;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
		;
bandwidth	: BANDWIDTH_T num ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "parser: bandwidth");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_BANDWIDTH;
			    verb_printf("Bandwidth %dbytes/sec\n", $2);
			    new_op->val= (void*)$2;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
		;
per_sess_bw	: PER_SESS_BW_T num ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "parser: bandwidth");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_PER_SESS_BW;
			    verb_printf("Per session Bandwidth %dbytes/sec\n", $2);
			    new_op->val= (void*)$2;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
		;
per_ip_bw	: PER_IP_BW_T num ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "parser: bandwidth/ip");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_PER_IP_BW;
			    verb_printf("Per IP Bandwidth %dbytes/sec\n", $2);
			    new_op->val= (void*)$2;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
		;
per_ip_conn	: PER_IP_CONN_T num ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "parser: connect/ip");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    new_op->op = OP_PER_IP_CONN;
			    verb_printf("Per IP Connections limit: %d\n", $2);
			    new_op->val= (void*)$2;
			    new_op->next=NULL;
			    $$ = new_op;
			}
		}
		;
conn_from	: CONN_FROM_T string ';' {
		    struct	group_ops_struct	*new_op;

		    new_op = xmalloc(sizeof(*new_op), "parser: group connect_from");
		    if ( !new_op ) {
			yyerror();
			$$ = NULL;
		    } else {
			char			c_from[64], *p;
			struct sockaddr_in	*c_from_sa_p;
			c_from_sa_p = xmalloc(sizeof(*c_from_sa_p), "parser: group c_from_sa_p ");

			bzero(c_from_sa_p, sizeof(*c_from_sa_p));
			strncpy(c_from, $2, sizeof(c_from)-1);
			p = c_from;
			while ( *p ) {*p=tolower(*p);p++;}
			verb_printf("Group conn_from: %s\n", c_from);

			if ( str_to_sa(c_from, (struct sockaddr*)c_from_sa_p) ) {
			    verb_printf("WARNING: Can't resolve group connect_from %s, function disabled.\n", c_from);
			    bzero(c_from_sa_p, sizeof(*c_from_sa_p));
			} else
			    verb_printf("Group connect_from %s enabled.\n", c_from);
			new_op->op = OP_CONN_FROM;
			new_op->val = (void*)c_from_sa_p;
			new_op->next = NULL;
			$$ = new_op;
		    }
		}
		;
range		: '[' num ':' num ']'  {
			if ( !badp_p ) badp_p = &badports[0];
			badp_p->from = $2;
			badp_p->length = $4-$2+1;
			if ( badp_p < &badports[MAXBADPORTS] ) badp_p++;
			    else {
			    verb_printf("You can use max %d badports ranges\n", MAXBADPORTS);
				badp_p--;
			    }
			}
		| NUMBER {
			if ( !badp_p ) badp_p = &badports[0];
			badp_p->from = yylval.INT;
			badp_p->length = 1;
			if ( badp_p < &badports[MAXBADPORTS] ) badp_p++;
			    else {
			    verb_printf("You can use max %d badports ranges\n", MAXBADPORTS);
				badp_p--;
			    }
			}
		| '[' string ']' {
			int	from, to;
			/* this must be [port:port] */
			if ( !badp_p ) badp_p = &badports[0];
			    if ( sscanf($2, "%d:%d", &from, &to) == 2 ) {
				badp_p->from = from;
				badp_p->length = to - from + 1;
				if ( badp_p < &badports[MAXBADPORTS] ) badp_p++;
				    else {
				    verb_printf("You can use max %d badports ranges\n", MAXBADPORTS);
					badp_p--;
				    }
			    } else {
				printf("Unrecognized format: %s\n", $2);
			    }
			    free($2);
			}
		;
ranges		: range {}
		| range ',' ranges {}
		;
badports	: BADPORTS_T ranges ';' {
		    struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "parser: badports 1");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
			    struct range *val;
			    val = xmalloc(sizeof(*val)*MAXBADPORTS, "parser: badports 2");
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
		;
icp		: ICP '{' deny_acls allow_acls '}' {
			struct	acls			*new_acls;
			struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "parser: icp");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "parser: icp new_acl 1");
				if ( !new_acls ) {
					verb_printf("No mem at http acl\n");
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

			new_op = xmalloc(sizeof(*new_op), "parser: icp new gr op1");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "parser: icp new_acl 2");
				if ( !new_acls ) {
					verb_printf("No mem at http acl\n");
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

			new_op = xmalloc(sizeof(*new_op), "parser: icp new gr op2");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "parser: icp new acl 3");
				if ( !new_acls ) {
					verb_printf("No mem at icp acl\n");
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

			new_op = xmalloc(sizeof(*new_op), "parser: icp new gr op2");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "parser: icp new acl 4");
				if ( !new_acls ) {
					verb_printf("No mem at icp acl\n");
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
		;
http		: HTTP '{' deny_acls allow_acls '}' {
			struct	acls			*new_acls;
			struct	group_ops_struct	*new_op;

			new_op = xmalloc(sizeof(*new_op), "parser: new http");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "parser: http new_acl 1");
				if ( !new_acls ) {
					verb_printf("No mem at http acl\n");
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

			new_op = xmalloc(sizeof(*new_op), "parser: http new gr op1");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "parser: http new_acl 2");
				if ( !new_acls ) {
					verb_printf("No mem at http acl\n");
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

			new_op = xmalloc(sizeof(*new_op), "parser: http new gr op2");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "parser: http new acl 3");
				if ( !new_acls ) {
					verb_printf("No mem at http acl\n");
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

			new_op = xmalloc(sizeof(*new_op), "parser: http new gr op2");
			if ( !new_op ) {
				yyerror();
				$$ = NULL;
			} else {
				new_acls = xmalloc(sizeof(*new_acls), "parser: http new acl 4");
				if ( !new_acls ) {
					verb_printf("No mem at http acl\n");
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
		;
deny_acls	: deny_acl 			{ $$ = $1; }
		| deny_acl deny_acls 		{ $2->next = $1 ; $$ = $2; }
		;
deny_acl	: DENY DSTDOMAIN string_list ';' { 
			struct acl *new = xmalloc(sizeof(*new), "parser: deny_acl new acl 2");
			if ( !new ) {
				verb_printf("No mem for acl\n");
				yyerror();
				$$ = NULL;
			} else {
				$$ = new;
				if ( $3
				     && $3->string
				     && !strncasecmp($3->string,"include:",8) )
				   $$->list =
					load_domlist_from_file($3->string + 8);
				else
				   $$->list = load_domlist_from_list($3);
				$$->next = NULL;
				$$->type = ACL_DOMAINDST ;
			}
			free_string_list($3);
		}
		;
allow_acls	: allow_acl 			{ $$ = $1; }
		| allow_acl allow_acls 		{ $1->next = $2 ; $$ = $1; }
		;
allow_acl	: ALLOW  DSTDOMAIN string_list ';' {
			struct acl *new = xmalloc(sizeof(*new), "parser: allow_acl new acl 2");
			if ( !new ) {
				verb_printf("No mem for acl\n");
				yyerror();
				$$ = NULL;
			} else {
				$$ = new;
				if ( $3
				     && $3->string
				     && !strncasecmp($3->string,"include:",8) )
				   $$->list =
					load_domlist_from_file($3->string + 8);
				else
				   $$->list = load_domlist_from_list($3);
				$$->next = NULL;
				$$->type = ACL_DOMAINDST ;
			}
			free_string_list($3);
		}
		;
string_list	: string_list_e { $$ = $1; }
		| string_list_e string_list {
			struct string_list *d;
			$1->next = $2; $$ = $1; 
			d = $1;
			while(d) {
				verb_printf("string_list:<%s>\n", d->string);
				d = d->next;
			}
		}
		| string_list_e ',' string_list {
			struct string_list *d;
			$1->next = $3; $$ = $1; 
			d = $1;
			while(d) {
				verb_printf("string_list:<%s>\n", d->string);
				d = d->next;
			}
		}
		;
string_list_e	: string {
		struct string_list	*new;
			new = xmalloc(sizeof(*new),"parser: string_list_e");
			if ( !new ) yyerror();
			new->string = malloc(strlen($1)+1);
			if ( !new->string ) yyerror();
			strcpy(new->string, $1);
			new->next = NULL;
			$$ = new;
			free($1);
		}
		;
domainlist	: domain {
			struct domain_list *d=$1;
			verb_printf("<%s>\n", d->domain);
			$$ = $1;
		}
		| domain domainlist {
			struct domain_list *d;
			$1->next = $2; $$ = $1;
			d = $1;
			while(d) {
				verb_printf("<%s>\n", d->domain);
				d = d->next;
			}
		}
		;
domain		: STRING {
			struct	domain_list *new;
			char		    *s, *d;

			new = xmalloc(sizeof(*new), "parser: domain new acl 1");
			if ( !new ) {
			    verb_printf("malloc failed\n");
			    yyerror();
			}
			new->domain = malloc(strlen(yylval.STRPTR)+1);
			if ( !new->domain ) yyerror();
			s = yylval.STRPTR;
			d = new->domain;
			while( *s ) {*d = tolower(*s);s++;d++;}; *d=0;
			if ( !strcmp(yylval.STRPTR, "*") )
				new->length = -1;
			    else
				new->length = strlen(yylval.STRPTR);
			free(yylval.STRPTR);
			new->next = NULL;
			$$ = new;
			}

		;
network_list	: network
		| network network_list {
			$1->next = $2; $$ = $1;
		}
		;
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
			new =  xmalloc(sizeof(struct cidr_net), "parser: network new acl 1");
			new->network = net;
			new->masklen = masklen;
			new->next = NULL;
			if ( !masklen )
				new->mask = 0;
			    else {
				if ( (masklen<0) || (masklen>32) ) {
					verb_printf("Invalid masklen %d\n", masklen);
					yyerror();
					return(-1);
				}
				new->mask = (int)0x80000000 >> ( masklen - 1 );
			    }
			verb_printf("NetWork: <<%8.8x/%d & %08x>>\n",  new->network,
							new->masklen,
							new->mask);
			free(yylval.STRPTR);
			$$ = new;
		}
		;

%%


static void
add_to_stop_cache(char *string)
{
struct  string_list     *new;

    new = xmalloc(sizeof(*new), "add_to_stop_cache(): 1");
    if ( new ) {
	new->string = string;
	new->next = stop_cache;
	stop_cache = new;
    }
}

struct domain_list*
load_domlist_from_file(char* file)
{
FILE			*f;
struct	domain_list	*first=NULL, *new, *last=NULL;
char			buf[128], *p;

    f = fopen(file,"r");
    if ( !f ) {
	verb_printf("Failed to open file %s: %m\n", file);
	return(NULL);
    }
    /* read file - domain per line */
    while ( fgets(buf, sizeof(buf), f) ) {
	p = buf;
	if ( (p = memchr(buf, '\n', sizeof(buf))) ) *p = 0;
	/* skip leading spaces */
	p = buf;
	while ( *p && IS_SPACE(*p) ) p++;
	if ( !*p ) /* empty line */
	    continue;
	if ( *p == '#' ) /* comment */
	    continue;
	/* ok here is domain */
	new = malloc(sizeof(*new));
	if ( !new ) {
	    if ( first ) free_dom_list(first);
	    fclose(f);
	    return(NULL);
	}
	bzero(new, sizeof(*new));
	new->domain = malloc(strlen(p)+1);
	if ( !new->domain ) {
	    if ( first ) free_dom_list(first);
	    fclose(f);
	    return(NULL);
	}
	strcpy(new->domain, p);
	if ( !strcmp(p, "*") )
		new->length = -1;
	    else
		new->length = strlen(p);
	if ( !first ) first = new;
	if ( last ) last->next = new;
	last = new;
    }
    fclose(f);
    return(first);
}

struct domain_list*
load_domlist_from_list(struct string_list *list)
{
struct	domain_list	*first=NULL, *new, *last=NULL;
char			buf[128], *p;

    while ( list && list->string ) {
	new = malloc(sizeof(*new));
	if ( !new ) {
	    if ( first ) free_dom_list(first);
	    return(NULL);
	}
	bzero(new, sizeof(*new));
	new->domain = strdup(list->string);
	if ( !new->domain ) {
	    if ( first ) free_dom_list(first);
	    return(NULL);
	}
	if ( !strcmp(new->domain, "*") )
		new->length = -1;
	    else
		new->length = strlen(new->domain);
	if ( !first ) first = new;
	if ( last ) last->next = new;
	last = new;
	list = list->next;
    }
    return(first);
}

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
    conf_file_name = strdup(name);
    ns_curr = 0;
    bzero(&peer_c, sizeof(peer_c));
    peer_c.type  = PEER_SIBLING;
    peer_c.down_timeout = 60;
    peerc_ptr = NULL;
    bzero((void*)&badports, sizeof(badports));
    code = yyparse();
    ns_configured = ns_curr;
    fclose(cf);
    printf("Parser returned %d, %d errors found\n", code, parser_errors);
    if ( parser_errors ) code = parser_errors;
    return(code);
}

static int
string_to_days(struct denytime *dt, struct string_list *list)
{
unsigned char	res = 0;
char		*t, *tokptr, *tb;
int		start_m=0, end_m=0;

    if ( (dt == NULL) || (list == NULL) ) return(0);

    while ( list ) {
	tb = list->string;
	if ( list->next ) /* this must be dayspec */
	while( (t = (char*)strtok_r(tb, ",", &tokptr)) != 0 ) {
	    char          fday[4],tday[4];
	    unsigned char d1, d2, i;

	    tb = NULL;
	    if ( sscanf(t,"%3s:%3s", (char*)&fday,(char*)&tday) == 2 ) {
		verb_printf("string_to_days(): Day interval from: '%s' to '%s'\n", fday,tday);
		d1 = daybit(fday);
		d2 = daybit(tday);
		if ( TEST(d1, 0x80) || TEST(d2, 0x80) ) {
		    verb_printf("string_to_days(): Wrong daytime\n");
		    return(0);
		}
		i = d1;
		d2 <<= 1; if ( d2 > 64 ) d2 = 1;
		if ( d2 == d1 ) {
                    res |= daybit("all");
		} else {
		    while(i != d2) {
		        res |= i;
		        i <<= 1;
		        if ( i > 64 ) i = 1;
		    }
                }
	    } else {
		verb_printf("string_to_days(): Day: '%s'\n", t);
		res |= daybit(t);
	    }  
	} else /* this must be timespec */ {
	    if ( list->string && (sscanf(list->string, "%d:%d", &start_m, &end_m) != 2) ) {
		verb_printf("Wrong timespec: %s\n", list->string);
		return(0);
	    }
	    verb_printf("string_to_days(): %0.4d-%0.4d\n", start_m, end_m);
	    dt->start_minute = 60*(start_m/100) + start_m%100;
	    dt->end_minute = 60*(end_m/100) + end_m%100;
	}
	list = list->next;
    }
    dt->days = res;
    return(0);
}
