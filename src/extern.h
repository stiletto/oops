/*
Copyright (C) 1999, 2000 Igor Khasilev, igor@paco.net
Copyright (C) 2000 Andrey Igoshin, ai@vsu.ru

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


#if	!defined(_EXTERN_H_INCLUDED_)
#define _EXTERN_H_INCLUDED_

#if		!defined(OOPS_MAIN)
extern time_t		start_time;
extern struct		mem_obj	*youngest_obj, *oldest_obj;
extern pthread_rwlock_t	config_lock;
extern pthread_rwlock_t	db_lock;
extern char		logfile[MAXPATHLEN], pidfile[MAXPATHLEN],
			base[MAXPATHLEN];
extern char		accesslog[MAXPATHLEN];
extern char    		statisticslog[MAXPATHLEN];
extern char     disk_state_string[MAXPATHLEN];
extern int		db_in_use, broken_db;
extern int		reserved_fd[RESERVED_FD];
extern int		accesslog_num, accesslog_size;
extern int		log_num, log_size;
extern unsigned int	maxresident;
extern unsigned int	minresident;
extern int		icp_so;
extern int		server_so;
extern int		peer_down_interval;
extern char		icons_path[MAXPATHLEN];
extern char		icons_port[64];
extern char		icons_host[MAXPATHLEN];
extern char		mem_max[MAXPATHLEN];
extern char		lo_mark[MAXPATHLEN];
extern char		hi_mark[MAXPATHLEN];
extern u_short		internal_http_port;
extern char		connect_from[64];
extern char		parent_host[64];
extern int		parent_port;
extern char		*parent_auth;
extern int		always_check_freshness;
extern int		force_http11;
extern unsigned int		force_completion;
extern refresh_pattern_t	*global_refresh_pattern;
extern int			max_rate_per_socket;
extern int			one_second_proxy_requests;
extern struct	domain_list 	*local_domains;
extern struct	cidr_net	*local_networks;
extern struct	cidr_net	**local_networks_sorted;
extern int			local_networks_sorted_counter;
extern struct	sockaddr_in	connect_from_sa, *connect_from_sa_p;
extern struct	sockaddr_in	ns_sa[OOPSMAXNS];
extern int			ns_configured;
extern u_short 	http_port;
extern u_short		icp_port;
extern char		*bind_addr;
extern struct		string_list	*stop_cache;
extern struct		storage_st	*storages, *next_alloc_storage;
extern int		default_expire_value;
extern int		max_expire_value;
extern int		ftp_expire_value;
extern int		default_expire_interval;
extern struct denytime  *expiretime;
extern int		last_modified_factor;
extern int		disk_low_free, disk_hi_free;
extern int		kill_request, reconfig_request;
extern volatile	time_t	global_sec_timer;
extern unsigned negative_cache;
extern int		dns_ttl;
extern int		icp_timeout;
extern int		accesslog_buffered;
extern int		logfile_buffered;
extern int		verbose_startup;
extern int		verbosity_level;
extern int		check_config_only;
extern int		skip_check;
extern pthread_mutex_t	malloc_mutex;
extern pthread_mutex_t	clients_lock;
extern pthread_mutex_t	icp_resolver_lock;
extern pthread_mutex_t	dns_cache_lock;
extern pthread_mutex_t	st_check_in_progr_lock;
extern pthread_mutex_t	mktime_lock;
extern pthread_mutex_t	flush_mem_cache_lock;

extern int			use_workers;
extern int			current_workers;
extern int			max_workers;
extern int			total_alloc;
extern int			clients_number;
extern int			total_objects;
extern char			*version;
extern pid_t			my_pid;
extern int			st_check_in_progr;
extern struct	oops_stat	oops_stat;
extern struct	peer		*peers;
extern struct	group		*groups;
extern struct	cidr_net	**sorted_networks_ptr;
extern struct	listen_so_list	*listen_so_list;
extern int			sorted_networks_cnt;
extern int		mem_max_val, lo_mark_val, hi_mark_val, swap_advance;
extern u_short		internal_http_port;
extern struct	obj_hash_entry	hash_table[HASH_SIZE];
extern struct	rq_hash_entry	rq_hash[RQ_HASH_SIZE];
extern struct	ip_hash_head	ip_hash[IP_HASH_SIZE];
extern struct	dns_hash_head	dns_hash[DNS_HASH_SIZE];
extern hash_t		*icp_requests_hash;
extern list_t		blacklist;
extern char		domain_name[MAXHOSTNAMELEN+1];
extern char		host_name[MAXHOSTNAMELEN+1];
extern char		*oops_user;
extern char     *ftp_passw;
extern char		*oops_chroot;
extern uid_t    oops_uid;
extern int             insert_via;
extern int             insert_x_forwarded_for;
extern named_acl_t	*named_acls;
extern struct charset	*charsets;
extern acl_chk_list_hdr_t	*acl_allow;
extern acl_chk_list_hdr_t	*acl_deny;
extern acl_chk_list_hdr_t	*stop_cache_acl;
extern bind_acl_t		*bind_acl_list;
extern acl_chk_list_hdr_t	*always_check_freshness_acl;
extern int	blacklist_len;
extern unsigned int	start_red;
extern unsigned int	refuse_at;
extern filebuff_t   logbuff;
extern filebuff_t   accesslogbuff;
extern int          dont_cache_without_last_modified;
extern int          storages_ready;
extern int          fetch_with_client_speed;
extern int          dst_ip_acl_present;
#endif		/* !defined(OOPS_MAIN) */

extern	struct	cidr_net **sort_n(struct cidr_net*, int*);
extern	int		readt(int, char*, int, int);


extern	void            do_exit(int);
extern	void		run(void);
#if	defined(SOLARIS) || defined(_AIX) || defined(_WIN32)
extern	int		daemon(int, int);
#endif
extern	void		*garbage_collector(void*);
extern	void		*garbage_drop(void*);
extern	void		*rotate_logs(void*);
extern	void		rotate_logbuff(void);
extern	void		rotate_accesslogbuff(void);
extern	void		*clean_disk(void*);
extern	void		*statistics(void*);
extern	void		*eraser(void*);
extern	void		*deadlock(void*);
extern	void		*run_client(void*);
extern	void		worker(void*);
extern	void		say_bad_request(int, char*, char*, int, struct request *);
extern	int		parse_url(char*, char*, struct url *, int);
extern	int		sendstr(int, char*);
extern	int		wait_for_read(int, int);
extern	void		xfree(void *);
extern	void		verb_printf(char *form, ...);
extern	void		log_access(int elapsed, struct request *rq, struct mem_obj *obj);
extern	int		http_date(char *date, time_t*);
extern	int		mk1123time(time_t, char*, int);
extern	int		str_to_sa(char*, struct sockaddr*);
extern	struct mem_obj	*locate_in_mem(struct url*, int, int*, struct request *);
extern	void		leave_obj(struct mem_obj*);
extern	void		destroy_obj(struct mem_obj*);
extern	int		move_obj_to_storage(struct mem_obj *obj, struct storage_st **st, struct disk_ref **);
extern	char		*htmlize(char*);
extern	char		*dehtmlize(char*);
extern	char		*html_escaping(char*);
extern	int		check_server_headers(struct server_answ *a, struct mem_obj *obj, struct buff *b, struct request *);
extern	void		free_chain(struct buff *);
extern	void		free_avlist(struct av *);
extern	void		free_url(struct url*);
extern	void		free_net_list(struct cidr_net*);
extern	void		ftp_fill_mem_obj(int, struct request *, char *, struct mem_obj*);
extern	void		fill_mem_obj(int, struct request *, char *, struct mem_obj*, int sso, int type, struct sockaddr_in *psa);
extern	int		writen(int, char*, int);
extern	int		writet(int, char*, int, int);
extern	int		writet_cv_cs(int, char*, int, int, char *, int);
extern	int		tm_cmp(struct tm *, struct tm *);
extern	void		send_error(int, int, char*);
extern	time_t		current_obj_age(struct mem_obj *);
extern	time_t		obj_freshness_lifetime(struct mem_obj *);
extern	int		send_av_pair(int, char*, char*);
extern	void		increase_hash_size(struct obj_hash_entry*, int);
extern	void		decrease_hash_size(struct obj_hash_entry*, int);
extern	struct	group*	rq_to_group(struct request*);
extern	int		deny_http_access(int, struct request *, struct group *);
extern	void		update_sess_transfer_rate(struct request *rq, int size);
extern	int		sess_traffic_load(struct request *rq);
#if	defined(__cplusplus)
extern "C" {
#endif

#if	!defined(NO_NEED_XMALLOC)
extern	void		*xmalloc(size_t, char*);
#endif /* NO_NEED_XMALLOC */

extern	void 		my_xlog(int lvl, char *form, ...);
#if	defined(__cplusplus)
}
#endif
extern	void		free_storages(struct storage_st*);
extern	void		prepare_storages(void);
extern	void		do_format_storages(void);
extern	int		locate_url_on_disk(struct url *, struct disk_ref**);
extern	int		load_obj_from_disk(struct mem_obj *, struct disk_ref *);
extern	struct storage_st *locate_storage_by_id(uint32_t);
extern	int		erase_from_disk(char *, struct disk_ref*);
extern  void            icp_processor(void*);
extern	void		my_sleep(int);
extern	void		my_msleep(int);
extern	int		calculate_resident_size(struct mem_obj *);
extern	int		calculate_container_datalen(struct buff *);
extern	int		release_blks(uint32_t n, struct storage_st *storage, struct disk_ref*);
extern	int		flush_super(struct storage_st *);
extern	int		flush_map(struct storage_st *);
extern	void		flush_mem_cache(void);
extern	int		set_socket_options(int);
extern	void		send_ssl(int, struct request*);
extern	int		bind_server_so(int, struct request*);
extern	int		is_local_dom(char*);
extern	int		is_local_net(struct sockaddr_in*);
extern	void		send_not_cached(int, struct request*, char*);
extern	int		send_icp_requests(struct request *, struct icp_queue_elem*, hash_entry_t **he);
extern	void		send_from_mem(int so, struct request *rq, char *headers, struct mem_obj *obj, int flags);
extern	void		icp_request_destroy(struct icp_queue_elem*);
extern	int		is_domain_allowed(char*, struct acls *);
extern	struct string_list *add_to_string_list(struct string_list **, char *);
extern	void		free_string_list(struct string_list*);
extern	struct search_list *add_to_search_list(struct search_list **, char *, int);
extern	void		free_search_list(struct search_list*);
extern	void		free_dns_hash_entry(struct dns_cache*);
extern	struct	av	*lookup_av_by_attr(struct av*, char*);
extern	char		*lookup_mime_type(char*);
extern	struct	peer	*peer_by_http_addr(struct sockaddr_in*);
extern	void		base_64_init(void);
extern	char		*base64_encode(char*);
extern	char		*base64_decode(char*);
extern	int		load_modules(void);
extern	struct	charset	*lookup_charset_by_name(struct charset *, char*);
extern	struct	charset	*lookup_charset_by_Agent(struct charset *, char*);
extern	struct	charset	*add_new_charset(struct charset **, char *);
extern	int		free_charsets(struct charset*);
extern	int		miss_deny(struct group*);
extern	int		put_av_pair(struct av **, char *, char*);
extern	struct	av	*lookup_av_by_attr(struct av*, char*);
extern	int		poll_descriptors(int, struct pollarg*, int);
#if	defined(FREEBSD)
extern	int		poll_descriptors_S(int, struct pollarg*, int);
#endif /* FREEBSD */
extern	int		add_socket_to_listen_list(int, u_short, struct in_addr*, int, void* (*f)(void*));
extern	char		daybit(char*);
extern	int		denytime_check(struct denytime*);
extern	int             send_data_from_buff_no_wait(int, int, struct buff **, int *, unsigned int *, int*, int, struct mem_obj*, char*, struct request *);
extern	void		update_transfer_rate(struct request*, int size);
extern	int		traffic_load(struct request *rq);
extern	char		*format_av_pair(char*, char*);
extern	int		tcp_port_in_use(u_short, struct in_addr *);
extern	void		init_domain_name(void);
extern	char		*fetch_internal_rq_header(struct mem_obj*,char*);
extern	l_string_list_t *lock_l_string_list(struct l_string_list*);
extern	l_string_list_t *alloc_l_string_list(void);
extern  l_mod_call_list_t *lock_l_mod_call_list(l_mod_call_list_t*);
extern	void		leave_string_list(struct l_string_list*);
extern	int		parse_named_acl_data(named_acl_t*, char*);
extern	void		free_named_acl(named_acl_t *);
extern	char		named_acl_type_by_name(char*);
extern	void		free_named_acls(named_acl_t *);
extern	int		acl_index_by_name(char*);
extern	void		set_refresh_pattern(struct request *, refresh_pattern_t*);
extern	void		free_refresh_patterns(refresh_pattern_t*);
extern	void		free_acl_access(acl_chk_list_hdr_t*);
extern	void		parse_acl_access(acl_chk_list_hdr_t**, char*);
extern	void		parse_bind_acl(char*);
extern	int		check_acl_access(acl_chk_list_hdr_t*, struct request*);
extern	void		unlink_obj(struct mem_obj*);
extern	void		set_user(void);
extern	void		set_euser(char*);
extern	int		obj_rate(struct mem_obj*);
extern	void		leave_l_string_list(struct l_string_list *l_list);
extern	int		rq_match_named_acl_by_index(struct request *, int);
extern	void		rotate_log_file(void);
extern	void		rotate_accesslog_file(void);
extern	void		memcpy_to_lower(char *, char *, size_t);
extern	void		process_output_object(int, struct output_object *, struct request *);
extern	void		free_output_obj(struct output_object *);
extern	int		insert_header(char *, char *, struct mem_obj *);
extern	int             peer_connect(int, struct sockaddr_in*, struct request *);
extern	int		peer_connect_silent(int client_so, struct sockaddr_in *peer_sa, struct request *rq);
extern	int		check_acl_access(acl_chk_list_hdr_t *, struct request *);
extern	int		obj_check_acl_access(acl_chk_list_hdr_t *, struct mem_obj*, struct request *);
extern	void		free_dom_list(struct domain_list *);
extern	void		free_denytimes(struct denytime *);
extern	void		print_networks(struct cidr_net **, int, int);
extern	int		parse_raw_url(char *, struct url *);
extern	void		parse_refresh_pattern(refresh_pattern_t **, char *);
extern	void		insert_named_acl_in_list(named_acl_t *acl);
extern	void		parse_networks_acl(acl_chk_list_hdr_t **, string_list_t *);
extern	void		CTIME_R(time_t *, char *, size_t);
extern	char		*STRERROR_R(int, char *, size_t);
extern	int		url_match_named_acl_by_index(char*, int);
extern	int		init_filebuff(filebuff_t*);
extern	int		reopen_filebuff(filebuff_t*, char*, int);
extern	void		close_filebuff(filebuff_t *);
extern	void		flushout_fb(filebuff_t *);
extern	void		free_groups(struct group *);
extern	int		use_peer(struct request *, struct peer*);
extern	internal_doc_t	*find_internal(char* name, internal_doc_t *ia);
extern	int		destination_is_local(char* host);
extern	void		leave_l_mod_call_list(l_mod_call_list_t *l_list);
extern	int		word_vector(char *string, char *delim, char** res, int size);
extern	void		free_word_vector(char** vector, int size);
extern	int		parent_connect(int, char *, int, struct request *);
extern	int		parent_connect_silent(int, char *, int, struct request *);
extern	void		tick_modules(void);
extern	void		unlock_obj(struct mem_obj *);
extern	void		lock_obj(struct mem_obj *);
extern	int		is_negative_code(int);
extern	int		is_negative_status(int code);

#if	defined(WITH_LARGE_FILES) && !defined(HAVE_ATOLL) && !defined(HAVE_STRTOLL)
extern	long long	atoll(const char *);
#endif

#if     !defined(HAVE_BZERO)
extern	void		bzero(void *, size_t);
#endif	/* !HAVE_BZERO */
#if     !defined(HAVE_STRERROR_R)
extern	int		strerror_r(int, char *, size_t);
#endif	/* !HAVE_STRERROR_R */

extern	dataq_t	eraser_queue;
extern  workq_t icp_workq;
extern  workq_t wq;

extern	void	run_modules(void);
extern	int	check_output_mods(int so, struct output_object *obj, struct request *rq, int *mod_flags);
extern	int	check_redirect(int so, struct request *rq, struct group *group, int *flag);
extern	int	check_auth(int so, struct request *rq, struct group *group, int *flag);
extern	int	check_headers_match(struct mem_obj*, struct request *, int*);
extern	int	check_log_mods(int, struct request *, struct mem_obj*);
extern	int	mod_reopen_logs(void);
extern	int	pre_body(int, struct mem_obj *, struct request *, int *);
extern	int	check_redir_connect(int *, struct request *, int *);
extern	int	check_redir_control_request(int so, struct request *rq, struct group *group, int *flag);
extern	int	parse_myports(char *, myport_t *, int);
extern	int	db_mod_attach(void);
extern	int	db_mod_detach(void);
extern	int	db_mod_open(void);
extern	int	db_mod_close(void);
extern	int	db_mod_sync(void);
extern	int	db_mod_precommit(void);
extern	int	db_mod_get(db_api_arg_t*, db_api_arg_t*);
extern	int	db_mod_put(db_api_arg_t*, db_api_arg_t*, struct mem_obj*);
extern	int	db_mod_del(db_api_arg_t*);
extern	void*	db_mod_cursor_open(int);
extern	int	db_mod_cursor_get(void*, db_api_arg_t*, db_api_arg_t*);
extern	int	db_mod_cursor_del(void*);
extern	int	db_mod_cursor_close(void*);
extern	int	db_mod_cursor_freeze(void*);
extern	int	db_mod_cursor_unfreeze(void*);

#endif	/* !_EXTERN_H_INCLUDED_ */
