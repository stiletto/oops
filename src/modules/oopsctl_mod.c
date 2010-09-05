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

#define	MODULE_NAME	"oopsctl"
#define	MODULE_INFO	"Oops controlling module"

#if	defined(MODULES)
char		module_type   = MODULE_LISTENER ;
char		module_name[] = MODULE_NAME ;
char		module_info[] = MODULE_INFO;
int		mod_load(void);
int		mod_unload(void);
int		mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run(void);
void*		process_call(void *arg);
#define		MODULE_STATIC
#else
static	char	module_type   = MODULE_LISTENER ;
static	char	module_name[] = MODULE_NAME ;
static	char	module_info[] = MODULE_INFO ;
static  int     mod_load();
static  int     mod_unload();
static  int     mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run();
static	void*	process_call(void *arg);
#define		MODULE_STATIC	static
#endif

struct	listener_module	oopsctl_mod = {
	{
	NULL, NULL,
	MODULE_NAME,
	mod_load,
	mod_unload,
	mod_config_beg,
	mod_config_end,
	mod_config,
	NULL,
	MODULE_LISTENER,
	MODULE_INFO,
	mod_run
	},
	process_call
};

static	pthread_rwlock_t	oopsctl_config_lock;

static	char		socket_path[MAXPATHLEN];
static	int		html_refresh;

int	oopsctl_so	= -1;

#define	WRLOCK_OOPSCTL_CONFIG	pthread_rwlock_wrlock(&oopsctl_config_lock)
#define	RDLOCK_OOPSCTL_CONFIG	pthread_rwlock_rdlock(&oopsctl_config_lock)
#define	UNLOCK_OOPSCTL_CONFIG	pthread_rwlock_unlock(&oopsctl_config_lock)

static	void	open_oopsctl_so(void);

typedef struct	rq_l_ {
	char			*conn;
	char			*url;
	char			*info;
	char			*tag;
	int			age;
	struct  rq_l_		*next;
} rq_list_t;

#define	RQ_OP_AGE_GT	1
#define	RQ_OP_AGE_LT	2
#define	RQ_OP_DST	3
#define	RQ_OP_SRC	4
#define	RQ_OP_GRP	5
typedef	struct	rq_op_ {
	char	op;
	union	{
		int		   INT;
		char		   *CHAR;
		struct sockaddr_in ADR;
	} data;
	struct  rq_op_ *next;
} rq_op_t;

MODULE_STATIC
int
mod_load(void)
{
    printf("Oopsctl started\n");
    pthread_rwlock_init(&oopsctl_config_lock, NULL);
    socket_path[0] = 0;
    html_refresh = 0;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_unload(void)
{
    WRLOCK_OOPSCTL_CONFIG ;
    printf("oopsctl_report stopped\n");
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_beg(int i)
{
    WRLOCK_OOPSCTL_CONFIG ;
    oopsctl_so = -1;		/* was closed in core */
    socket_path[0] = 0;
    html_refresh = 0;
    UNLOCK_OOPSCTL_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_run(void)
{
    WRLOCK_OOPSCTL_CONFIG ;
    if ( oops_user ) set_euser(oops_user);
    if ( socket_path[0] ) {
	open_oopsctl_so();
    }
    if ( oops_user ) set_euser(NULL);
    UNLOCK_OOPSCTL_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_end(int i)
{
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config(char *config, int i)
{
char	*p = config;

    WRLOCK_OOPSCTL_CONFIG ;

    while( *p && IS_SPACE(*p) ) p++;
    if ( !strncasecmp(p, "socket_path", 11) ) {
	p += 11;
	while (*p && IS_SPACE(*p) ) p++;
	strncpy(socket_path, p, sizeof(socket_path) -1 );
    }
    if ( !strncasecmp(p, "html_refresh", 12) ) {
	p += 12;
	while (*p && IS_SPACE(*p) ) p++;
	html_refresh = atoi(p);
    }
    UNLOCK_OOPSCTL_CONFIG ;
    return(MOD_CODE_OK);
}

static int
read_command(int so, char *buff, int len)
{
char *ptr = buff, c;

    if ( !buff || (len <= 0) ) return(0);
    *buff = 0;
    while( read(so, &c, 1) == 1 ) {
	/* skip any leading space chars */
	if ( (ptr==buff) && IS_SPACE(c) ) continue;
	if ( c == '\n' || c == '\r' ) {
	    return(1);
	}
	*ptr = c; ptr++; *ptr = 0;
        if ( ptr - buff >= len -1 )
            return(1);
    }
    return(0);
}

static int
print_help(int so)
{
char	**p, *help_message[] = {"reconfigure - re-read config file (like kill -HUP).\n",
			   "shutdown    - gracefuly shutdown (like kill -TERM).\n",
			   "stat        - display statistics.\n",
			   "htmlstat    - display statistics in html.\n",
			   "verbosity=LVL - set new verbosity level (LVL as in -x option).\n",
			   NULL};

    p = help_message;
    while(*p) {
	write(so, *p, strlen(*p));
	p++;
    }
    return(0);
}

static int
print_stat(int so)
{
char			buf[1024], *type, *info;
int			uptime = global_sec_timer - start_time;
struct	storage_st	*storage;
struct	general_module	*mod;
struct	peer		*peer;
double			last_min_req_rate, last_min_hit_rate,last_min_icp_rate;
double			tot_req_rate, tot_hit_rate;
double			peer_hits_percent;
double			max_req_rate, max_icp_rate, max_hit_rate;
double			free_pages_p;
double			drop_rate;
char			ctime_buf[30] = "";
struct  oops_stat       temp_stat;

    LOCK_STATISTICS(oops_stat);
    memcpy(&temp_stat, &oops_stat, sizeof(oops_stat));
    UNLOCK_STATISTICS(oops_stat);
    if ( temp_stat.requests_http1 ) {
	last_min_req_rate = temp_stat.requests_http1/6e1;
	last_min_hit_rate = (temp_stat.hits1*1e2)/temp_stat.requests_http1;
    } else {
	last_min_req_rate = last_min_hit_rate = 0;
    }
    last_min_icp_rate = temp_stat.requests_icp1/6e1;
    if ( uptime ) {
	tot_req_rate = (temp_stat.requests_http*1e0)/uptime;
	if ( temp_stat.requests_http )
		tot_hit_rate = (temp_stat.hits*1e2)/temp_stat.requests_http;
	    else
		tot_hit_rate = 0;
    } else {
	tot_req_rate = tot_hit_rate = 0;
	uptime = 1;
    }
    max_req_rate = temp_stat.requests_http0_max/6e1;
    max_icp_rate = temp_stat.requests_icp0_max/6e1;
    max_hit_rate = temp_stat.hits0_max/6e1;
    drop_rate    = temp_stat.drops0/6e1;
    write(so, "## --  General info   --\n", 25);
    snprintf(buf, sizeof(buf)-1, "Version      : %s\n", version);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "Uptime       : %dsec, (%dday(s), %dhour(s), %dmin(s))\n",
			uptime, uptime/(24*3600), (uptime%(24*3600))/3600,
			(uptime%3600)/60);
    write(so, buf, strlen(buf));
    CTIME_R((time_t*)&global_sec_timer, ctime_buf, sizeof(ctime_buf)-1);
    snprintf(buf, sizeof(buf)-1, "Last update  : %s", ctime_buf);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "Clients      : %d (max: %d)\n", (int)clients_number, (int)temp_stat.clients_max);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "HTTP requests: %d\n", (int)temp_stat.requests_http);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "ICP  requests: %d\n", (int)temp_stat.requests_icp);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "Total hits   : %d\n", (int)temp_stat.hits);
    write(so, buf, strlen(buf));
    if ( max_workers ) {
	snprintf(buf, sizeof(buf)-1, "Thread pool  : %d ready to serve (out of %d max)\n", wq.counter, wq.parallelism);
	write(so, buf, strlen(buf));
    }
    snprintf(buf, sizeof(buf)-1, "Curr.req.rate: %.2f req/sec (max: %.2f)\n",
	last_min_req_rate, max_req_rate);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "Tot.req.rate : %.2f req/sec\n", tot_req_rate);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "Curr.hit.rate: %.2f %%\n", last_min_hit_rate);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "Tot.hit.rate : %.2f %%\n", tot_hit_rate);
    write(so, buf, strlen(buf));
    if ( (temp_stat.drops0>0) || (temp_stat.drops>0) ) {
	snprintf(buf, sizeof(buf)-1, "Cur.drop.rate: %.2f %%\n", drop_rate);
	write(so, buf, strlen(buf));
	snprintf(buf, sizeof(buf)-1, "Tot. drops   : %d\n", temp_stat.drops);
	write(so, buf, strlen(buf));
    }
    snprintf(buf, sizeof(buf)-1, "Curr.icp.rate: %.2f req/sec (max: %.2f)\n",
	last_min_icp_rate, max_icp_rate);
    write(so, buf, strlen(buf));
#if	HAVE_GETRUSAGE
    {
    unsigned long utime, stime, utime0, stime0, total;
    unsigned long delta, deltatime, deltau, deltas;

    deltatime= (temp_stat.timestamp - temp_stat.timestamp0)*1000;
    if ( (signed) deltatime <= 0 ) deltatime = 60000;
    utime = temp_stat.rusage.ru_utime.tv_sec*1000 +
            temp_stat.rusage.ru_utime.tv_usec/1000;
    stime = temp_stat.rusage.ru_stime.tv_sec*1000 +
            temp_stat.rusage.ru_stime.tv_usec/1000;
    utime0 = temp_stat.rusage0.ru_utime.tv_sec*1000 +
            temp_stat.rusage0.ru_utime.tv_usec/1000;
    stime0 = temp_stat.rusage0.ru_stime.tv_sec*1000 +
            temp_stat.rusage0.ru_stime.tv_usec/1000;
    delta = (utime+stime) - (utime0+stime0);
    deltau = utime - utime0;
    deltas = stime - stime0;
    write(so, "## --       CPU       --\n", 25);
    snprintf(buf, sizeof(buf)-1, "Total usage  : %dms\n", (int)(utime+stime));
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "Delta usage  : %dms\n", (int)delta);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "Delta time   : %dms\n", (int)deltatime);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "Curr. CPU    : %.2f %% (%.2fs+%.2fu)\n",
	    (1e2*delta)/deltatime,
	    (1e2*deltas)/deltatime,
	    (1e2*deltau)/deltatime);
    write(so, buf, strlen(buf));
    total=utime+stime;
    uptime = 1000*uptime;
    snprintf(buf, sizeof(buf)-1, "Aver. CPU    : %.2f %% (%.2fs+%.2fu)\n",
	    (1e2*total)/uptime,
	    (1e2*stime)/uptime,
	    (1e2*utime)/uptime);
    write(so, buf, strlen(buf));
    }
#endif
    /* storages */
    write(so, "## --    storages     --\n", 25);
    RDLOCK_CONFIG;
    storage = storages;
    snprintf(buf, sizeof(buf)-1, "Disks msg    : %s\n", disk_state_string);
    write(so, buf, strlen(buf));
    while(storage) {
	snprintf(buf, sizeof(buf)-1, "Storage      : %s\n", storage->path);
	write(so, buf, strlen(buf));
	if ( storage->size != -1 )
	    snprintf(buf, sizeof(buf)-1, "Size         : %.2f MB\n",
					(1e0*storage->size)/(1024*1024));
	else
	    snprintf(buf, sizeof(buf)-1, "Size         : %.2f MB\n",
					(storage->super.blks_total*4e0)/1024);
	write(so, buf, strlen(buf));
	if ( storage->super.blks_free == 0 || storage->super.blks_total == 0 )
		free_pages_p = 0;
	    else
		free_pages_p = (1e2*storage->super.blks_free)/storage->super.blks_total;
	snprintf(buf, sizeof(buf)-1, "Free blks    : %d blks (%.2fMb) %.2f %%\n",
		storage->super.blks_free,
		(1e0*storage->super.blks_free*STORAGE_PAGE_SIZE)/(1024*1024),
		free_pages_p);
	write(so, buf, strlen(buf));
	snprintf(buf, sizeof(buf)-1, "State        : %s\n", (storage->flags&ST_READY)?
					"READY":"NOT_READY");
	write(so, buf, strlen(buf));
	snprintf(buf, sizeof(buf)-1, "Fileno       : %d\n", storage->fd);
	write(so, buf, strlen(buf));
	storage = storage->next;
    }
    UNLOCK_CONFIG;
    write(so, "## -- end of storages --\n", 25);
    /* modules */
    write(so, "## --     modules     --\n", 25);
    mod = global_mod_chain;
    while(mod) {
	switch (mod->type) {
	case(MODULE_LOG):
	    type = "Log recording";
	    break;
	case(MODULE_ERR):
	    type = "Error reporting";
	    break;
	case(MODULE_AUTH):
	    type = "Authentication";
	    break;
	case(MODULE_REDIR):
	    type = "URL redirector";
	    break;
	case(MODULE_OUTPUT):
	    type = "Output handling";
	    break;
	case(MODULE_LISTENER):
	    type = "Independent port listener";
	    break;
	case(MODULE_HEADERS):
	    type = "Document headers check";
	    break;
	case(MODULE_PRE_BODY):
	    type = "Document body begins";
	    break;
	case(MODULE_DB_API):
	    type = "DB Interface";
	    break;
	default:
	    type = "Unknown";
	    break;
	}
	info = mod->info ? mod->info : "";
	snprintf(buf, sizeof(buf)-1, "%-13s %s (%s)\n", mod->name, info, type);
	write(so, buf, strlen(buf));
	mod = mod->next_global;
    }
    write(so,   "## -- end of modules  --\n", 25);
    snprintf(buf, sizeof(buf)-1, "## --    icp peers    --\n");
    write(so, buf, strlen(buf));
    RDLOCK_CONFIG ;
    peer = peers;
    while ( peer ) {
        snprintf(buf, sizeof(buf)-1, "Name         : %s %d %d\n", peer->name, peer->http_port, peer->icp_port);
	write(so, buf, strlen(buf));
	switch( peer->type ) {
	case PEER_PARENT:
		type = "PARENT";
		break;
	case PEER_SIBLING:
		type = "SIBLING";
		break;
	default:
		type = "UNKNOWN";
		break;
	}
        snprintf(buf, sizeof(buf)-1, "Type         : %s\n", type);
	write(so, buf, strlen(buf));
        snprintf(buf, sizeof(buf)-1, "Req. sent    : %d\n", peer->rq_sent);
	write(so, buf, strlen(buf));
        snprintf(buf, sizeof(buf)-1, "Answ. recvd  : %d\n", peer->an_recvd);
	write(so, buf, strlen(buf));
	if ( peer->an_recvd == 0 || peer->hits_recvd == 0 )
	    peer_hits_percent = 0;
	    else
		peer_hits_percent = (peer->hits_recvd*1e2)/peer->an_recvd;
        snprintf(buf, sizeof(buf)-1, "Hits recvd   : %d (%.2f %%)\n", peer->hits_recvd,
			peer_hits_percent);
	write(so, buf, strlen(buf));
        snprintf(buf, sizeof(buf)-1, "Reqs recvd   : %d\n", peer->rq_recvd);
	write(so, buf, strlen(buf));
	if ( peer->hits_sent == 0 || peer->rq_recvd == 0 )
	    peer_hits_percent = 0;
	    else
		peer_hits_percent = (peer->hits_sent*1e2)/peer->rq_recvd;
        snprintf(buf, sizeof(buf)-1, "Hits sent    : %d (%.2f %%)\n", peer->hits_sent,
			peer_hits_percent);
	write(so, buf, strlen(buf));
        snprintf(buf, sizeof(buf)-1, "Status       : %s\n",
        	TEST(peer->state, PEER_DOWN)?"DOWN":"UP");
	write(so, buf, strlen(buf));

	peer = peer->next;
    }
    UNLOCK_CONFIG ;
    snprintf(buf, sizeof(buf)-1, "## -- end of icp peers--\n");
    write(so, buf, strlen(buf));
    return(0);
}

static int
print_htmlstat(int so)
{
char			buf[1024], *type, *info;
int			uptime = global_sec_timer - start_time;
struct	storage_st	*storage;
struct	general_module	*mod;
struct	peer		*peer;
double			last_min_req_rate, last_min_hit_rate, last_min_icp_rate;
double			tot_req_rate, tot_hit_rate;
double			max_req_rate, max_icp_rate, max_hit_rate;
double			peer_hits_percent;
double			free_pages_p;
double			drop_rate;
char			ctime_buf[30];
struct  oops_stat       temp_stat;

    LOCK_STATISTICS(oops_stat);
    memcpy(&temp_stat, &oops_stat, sizeof(oops_stat));
    UNLOCK_STATISTICS(oops_stat);

    if ( temp_stat.requests_http1 ) {
	last_min_req_rate = temp_stat.requests_http1/6e1;
	last_min_hit_rate = (temp_stat.hits1*1e2)/temp_stat.requests_http1;
    } else {
	last_min_req_rate = last_min_hit_rate = 0;
    }
    last_min_icp_rate = temp_stat.requests_icp1/6e1;
    if ( uptime ) {
	tot_req_rate = (temp_stat.requests_http*1e0)/uptime;
	if ( temp_stat.requests_http )
		tot_hit_rate = (temp_stat.hits*1e2)/temp_stat.requests_http;
	    else
		tot_hit_rate = 0;
    } else {
	tot_req_rate = tot_hit_rate = 0;
	uptime = 1;
    }
    max_req_rate = temp_stat.requests_http0_max/6e1;
    max_icp_rate = temp_stat.requests_icp0_max/6e1;
    max_hit_rate = temp_stat.hits0_max/6e1;
    drop_rate = temp_stat.drops0/6e1;
    snprintf(buf, sizeof(buf)-1, "<html><title>Oops stat</title>\n");
    write(so, buf, strlen(buf));
    if ( html_refresh ) {
	snprintf(buf, sizeof(buf)-1, "<META HTTP-EQUIV=\"Refresh\" CONTENT=\"%d\">\n", html_refresh);
	write(so, buf, strlen(buf));
    }
    snprintf(buf, sizeof(buf)-1, "<body bgcolor=white><table><tr bgcolor=blue><td><font color=yellow>General Info<td>&nbsp</font>\n");
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td valign=top>Version<td>%s\n", version);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>Uptime<td>%dsec, (%dday(s), %dhour(s), %dmin(s))\n",
			uptime, uptime/(24*3600), (uptime%(24*3600))/3600,
			(uptime%3600)/60);
    write(so, buf, strlen(buf));
    CTIME_R((time_t*)&global_sec_timer, ctime_buf, sizeof(ctime_buf)-1);
    snprintf(buf, sizeof(buf)-1, "<tr><td>Last update<td>%s", ctime_buf);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>Clients<td>%d (max: %d)\n", (int)clients_number, (int)temp_stat.clients_max);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>HTTP requests<td>%d\n", (int)temp_stat.requests_http);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>ICP  requests<td>%d\n", (int)temp_stat.requests_icp);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>Total hits<td>%d\n", (int)temp_stat.hits);
    write(so, buf, strlen(buf));
    if ( max_workers ) {
	snprintf(buf, sizeof(buf)-1, "<tr><td>Thread pool<td>%d ready to serve (out of %d max)\n", wq.counter, wq.parallelism);
	write(so, buf, strlen(buf));
    }
    snprintf(buf, sizeof(buf)-1, "<tr><td>Curr.req.rate<td>%.2f req/sec (max: %.2f)\n",
	last_min_req_rate, max_req_rate);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>Tot.req.rate<td>%.2f req/sec\n",
	tot_req_rate);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>Curr.hit.rate<td>%.2f %%\n",
	last_min_hit_rate);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>Tot.hit.rate<td>%.2f %%\n", tot_hit_rate);
    write(so, buf, strlen(buf));
    if ( (temp_stat.drops0>0) || (temp_stat.drops>0) ) {
	snprintf(buf, sizeof(buf)-1, "<tr><td>Cur.drop.rate<td>%.2f %%\n", drop_rate);
	write(so, buf, strlen(buf));
	snprintf(buf, sizeof(buf)-1, "<tr><td>Tot. drops<td>%d\n", temp_stat.drops);
	write(so, buf, strlen(buf));
    }
    snprintf(buf, sizeof(buf)-1, "<tr><td>Curr.icp.rate<td>%.2f req/sec (max: %.2f)\n",
	last_min_icp_rate, max_icp_rate);
    write(so, buf, strlen(buf));
#if	HAVE_GETRUSAGE
    {
    unsigned long utime, stime, utime0, stime0, total;
    unsigned long delta, deltatime, deltau, deltas;

    deltatime= (temp_stat.timestamp - temp_stat.timestamp0)*1000;
    if ( (signed) deltatime <= 0 ) deltatime = 60000;
    utime = temp_stat.rusage.ru_utime.tv_sec*1000 +
            temp_stat.rusage.ru_utime.tv_usec/1000;
    stime = temp_stat.rusage.ru_stime.tv_sec*1000 +
            temp_stat.rusage.ru_stime.tv_usec/1000;
    utime0 = temp_stat.rusage0.ru_utime.tv_sec*1000 +
            temp_stat.rusage0.ru_utime.tv_usec/1000;
    stime0 = temp_stat.rusage0.ru_stime.tv_sec*1000 +
            temp_stat.rusage0.ru_stime.tv_usec/1000;
    delta = (utime+stime) - (utime0+stime0);
    deltau = utime - utime0;
    deltas = stime - stime0;
    snprintf(buf, sizeof(buf)-1, "<tr><td>Total usage<td>%dms\n", (int)(utime+stime));
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>Delta usage<td>%dms\n", (int)delta);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>Delta time<td>%dms\n", (int)deltatime);
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>Curr. CPU<td>%.2f %% (%.2fs+%.2fu)\n",
	    (1e2*delta)/deltatime,
	    (1e2*deltas)/deltatime,
	    (1e2*deltau)/deltatime);
    write(so, buf, strlen(buf));
    total=utime+stime;
    uptime = 1000*uptime;
    snprintf(buf, sizeof(buf)-1, "<tr><td>Aver. CPU<td>%.2f %% (%.2fs+%.2fu)\n",
	    (1e2*total)/uptime,
	    (1e2*stime)/uptime,
	    (1e2*utime)/uptime);
    write(so, buf, strlen(buf));
    }
#endif
    /* storages */
    snprintf(buf, sizeof(buf)-1, "<tr bgcolor=blue><td><font color=yellow>Storages</font><td>&nbsp\n");
    write(so, buf, strlen(buf));
    snprintf(buf, sizeof(buf)-1, "<tr><td>Disks msg<td>%s\n", disk_state_string);
    write(so, buf, strlen(buf));
    RDLOCK_CONFIG;
    storage = storages;
    while(storage) {
	snprintf(buf, sizeof(buf)-1, "<tr><td><b>Storage<td><b>%s\n", storage->path);
	write(so, buf, strlen(buf));
	if ( storage->size != -1 )
	    snprintf(buf, sizeof(buf)-1, "<tr><td>Size<td>%.2f MB\n",
					(1e0*storage->size/(1024*1024)));
	else
	    snprintf(buf, sizeof(buf)-1, "<tr><td>Size<td>%d blks (%.2f MB)\n", storage->super.blks_total,
					(storage->super.blks_total*4e0)/1024);
	write(so, buf, strlen(buf));
	if ( storage->super.blks_free == 0 || storage->super.blks_total == 0 )
	    free_pages_p = 0;
	    else
		free_pages_p = (1e2*storage->super.blks_free)/storage->super.blks_total;
	snprintf(buf, sizeof(buf)-1, "<tr><td>Free blks<td>%d blks (%.2fMb) %.2f %%\n", storage->super.blks_free,
					((1e0*storage->super.blks_free)*STORAGE_PAGE_SIZE)/(1024*1024),
					free_pages_p);
	write(so, buf, strlen(buf));
	snprintf(buf, sizeof(buf)-1, "<tr><td>State<td>%s\n", (storage->flags&ST_READY)?
					"READY":"<font color=red>NOT_READY</font>");
	write(so, buf, strlen(buf));
	snprintf(buf, sizeof(buf)-1, "<tr><td>Fileno<td>%d\n", storage->fd);
	write(so, buf, strlen(buf));
	storage = storage->next;
    }
    UNLOCK_CONFIG;
    /* modules */
    snprintf(buf, sizeof(buf)-1, "<tr bgcolor=blue><td><font color=yellow>Module</font><td><font color=yellow>Type</font>\n");
    write(so, buf, strlen(buf));
    mod = global_mod_chain;
    while(mod) {
	switch (mod->type) {
	case(MODULE_LOG):
	    type = "Log recording";
	    break;
	case(MODULE_ERR):
	    type = "Error reporting";
	    break;
	case(MODULE_AUTH):
	    type = "Auhtentication";
	    break;
	case(MODULE_REDIR):
	    type = "URL redirector";
	    break;
	case(MODULE_OUTPUT):
	    type = "Output handling";
	    break;
	case(MODULE_LISTENER):
	    type = "Independent port listener";
	    break;
	case(MODULE_HEADERS):
	    type = "Document headers check";
	    break;
	case(MODULE_PRE_BODY):
	    type = "Document body begins";
	    break;
	case(MODULE_DB_API):
	    type = "DB Interface";
	    break;
	default:
	    type = "Unknown";
	    break;
	}
	info = mod->info ? mod->info : "";
	snprintf(buf, sizeof(buf)-1, "<tr><td>%-13s<td>%s (%s)\n", mod->name, info, type);
	write(so, buf, strlen(buf));
	mod = mod->next_global;
    }
    snprintf(buf, sizeof(buf)-1, "<tr bgcolor=blue><td><font color=yellow>icp peers</font><td><font color=yellow>&nbsp</font>");
    write(so, buf, strlen(buf));
    RDLOCK_CONFIG ;
    peer = peers;
    while ( peer ) {
        snprintf(buf, sizeof(buf)-1, "<tr><td><b>Name<td><b>%s %d %d\n", peer->name, peer->http_port, peer->icp_port);
	write(so, buf, strlen(buf));
	switch( peer->type ) {
	case PEER_PARENT:
		type = "PARENT";
		break;
	case PEER_SIBLING:
		type = "SIBLING";
		break;
	default:
		type = "UNKNOWN";
		break;
	}
        snprintf(buf, sizeof(buf)-1, "<tr><td>Type<td>%s\n", type);
	write(so, buf, strlen(buf));
        snprintf(buf, sizeof(buf)-1, "<tr><td>Req. sent<td>%d\n", peer->rq_sent);
	write(so, buf, strlen(buf));
        snprintf(buf, sizeof(buf)-1, "<tr><td>Answ. recvd<td>%d\n", peer->an_recvd);
	write(so, buf, strlen(buf));
	if ( peer->an_recvd == 0 || peer->hits_recvd == 0 )
	    peer_hits_percent = 0;
	    else
		peer_hits_percent = (peer->hits_recvd*1e2)/peer->an_recvd;
        snprintf(buf, sizeof(buf)-1, "<tr><td>Hits recvd<td>%d (%.2f %%)\n", peer->hits_recvd,
			peer_hits_percent);
	write(so, buf, strlen(buf));
        snprintf(buf, sizeof(buf)-1, "<tr><td>Reqs recvd<td>%d\n", peer->rq_recvd);
	write(so, buf, strlen(buf));
	if ( peer->hits_sent == 0 || peer->rq_recvd == 0 )
	    peer_hits_percent = 0;
	    else
		peer_hits_percent = (peer->hits_sent*1e2)/peer->rq_recvd;
        snprintf(buf, sizeof(buf)-1, "<tr><td>Hits sent<td>%d (%.2f %%)\n", peer->hits_sent,
			peer_hits_percent);
	write(so, buf, strlen(buf));
        snprintf(buf, sizeof(buf)-1, "<tr><td>Status<td>%s\n",
        	TEST(peer->state, PEER_DOWN)?"DOWN":"UP");
	write(so, buf, strlen(buf));

	peer = peer->next;
    }
    UNLOCK_CONFIG ;
    snprintf(buf, sizeof(buf)-1, "</table></body></html>\n");
    write(so, buf, strlen(buf));
    return(0);
}

static int
set_verbosity(int so, char *command)
{
int	new_verbosity_level = verbosity_level;
char	vbuf[80], *v = vbuf;

    command += 10;
    while ( *command ) {
	switch( *command ) {
		case 'a':
			new_verbosity_level = -1;
			break;
		case 'A':
			new_verbosity_level = OOPS_LOG_SEVERE | OOPS_LOG_PRINT;
			break;
		case 'b':
			new_verbosity_level |= OOPS_LOG_CACHE;
			break;
		case 'B':
			new_verbosity_level &= ~OOPS_LOG_CACHE;
			break;
		case 'c':
			new_verbosity_level |= OOPS_LOG_NOTICE;
			break;
		case 'C':
			new_verbosity_level &= ~ OOPS_LOG_NOTICE;
			break;
		case 'd':
			new_verbosity_level |= OOPS_LOG_DBG;
			break;
		case 'D':
			new_verbosity_level &= ~ OOPS_LOG_DBG;
			break;

		case 'f':
			new_verbosity_level |= OOPS_LOG_FTP;
			break;
		case 'F':
			new_verbosity_level &= ~ OOPS_LOG_FTP;
			break;

			case 'h':
			new_verbosity_level |= OOPS_LOG_HTTP;
			break;
		case 'H':
			new_verbosity_level &= ~ OOPS_LOG_HTTP;
			break;

		case 'i':
			new_verbosity_level |= OOPS_LOG_INFORM;
			break;
		case 'I':
			new_verbosity_level &= ~ OOPS_LOG_INFORM;
			break;

		case 'n':
			new_verbosity_level |= OOPS_LOG_DNS;
			break;
		case 'N':
			new_verbosity_level &= ~ OOPS_LOG_DNS;
			break;

		case 's':
			new_verbosity_level |= OOPS_LOG_STOR;
			break;
		case 'S':
			new_verbosity_level &= ~ OOPS_LOG_STOR;
			break;
	}
	command++;
    }
    verbosity_level = new_verbosity_level;
    write(so, "OK, now verbosity is: ", 22);
    if ( v - vbuf < sizeof vbuf ) {
	if ( verbosity_level & OOPS_LOG_NOTICE ) {*v = 'c'; v++ ; *v = 0;}
    }
    if ( v - vbuf < sizeof vbuf ) {
	if ( verbosity_level & OOPS_LOG_DBG ) {*v = 'd'; v++ ; *v = 0;}
    }
    if ( v - vbuf < sizeof vbuf ) {
	if ( verbosity_level & OOPS_LOG_FTP ) {*v = 'f'; v++ ; *v = 0;}
    }
    if ( v - vbuf < sizeof vbuf ) {
	if ( verbosity_level & OOPS_LOG_HTTP ) {*v = 'h'; v++ ; *v = 0;}
    }
    if ( v - vbuf < sizeof vbuf ) {
	if ( verbosity_level & OOPS_LOG_CACHE ) {*v = 'b'; v++ ; *v = 0;}
    }
    if ( v - vbuf < sizeof vbuf ) {
	if ( verbosity_level & OOPS_LOG_INFORM ) {*v = 'i'; v++ ; *v = 0;}
    }
    if ( v - vbuf < sizeof vbuf ) {
	if ( verbosity_level & OOPS_LOG_DNS ) {*v = 'n'; v++ ; *v = 0;}
    }
    if ( v - vbuf < sizeof vbuf ) {
	if ( verbosity_level & OOPS_LOG_STOR ) {*v = 's'; v++ ; *v = 0;}
    }
    if ( v - vbuf < sizeof vbuf ) {
	if ( verbosity_level & OOPS_LOG_SEVERE ) {*v = 'E'; v++ ; *v = 0;}
    }
    write(so, vbuf, strlen(vbuf));
    write(so, "\n", 1);
    return(0);
}

static int
rq_match_ops(struct request *rq, rq_op_t *ops)
{
    if ( !rq ) return(FALSE);
    while(ops) {
	switch ( ops->op) {
	case RQ_OP_AGE_LT:
		if ( (global_sec_timer - rq->request_time) >= ops->data.INT )
			return(FALSE);
		break;
	case RQ_OP_AGE_GT:
		if ( (global_sec_timer - rq->request_time) <= ops->data.INT )
			return(FALSE);
		break;
	case RQ_OP_SRC:
		/* compare with client addr */
		if ( memcmp(&ops->data.ADR.sin_addr,
			     &rq->client_sa.sin_addr,
			     sizeof(ops->data.ADR.sin_addr)) )
			return(FALSE);
		break;
	case RQ_OP_DST:
		/* compare with request host */
		if (    ( rq->url.host == NULL )
		     || ( ops->data.CHAR == NULL) )
			return(FALSE);
		if ( strcasecmp(rq->url.host, ops->data.CHAR) ) return(FALSE);
		break;
	}
	ops = ops->next;
    }
    return(TRUE);
}

static int
process_requests(int so, char *command)
{
int		i;
struct  request *rq;
rq_list_t	*rq_list = NULL, *last_rq = NULL, *new;
char		buf[512];
rq_op_t		*ops = NULL, *last_op = NULL, *new_op;
char		*t, *tok, *lasts;

    /* parse command */
    t = command+9 /*strlen("requests=") */;
    while ( (tok = strtok_r(t, " ", &lasts)) ) {
	t = NULL;
	if ( !strncasecmp(tok, "age>", 4) ) {
	    new_op = calloc(sizeof(*new_op),1);
	    new_op->op       = RQ_OP_AGE_GT;
	    new_op->data.INT = atoi(tok+4);
	    if ( last_op ) {
		last_op->next = new_op;
		last_op = new_op;
	    } else {
		last_op = ops = new_op;
	    }
	}
	if ( !strncasecmp(tok, "age<", 4) ) {
	    new_op = calloc(sizeof(*new_op),1);
	    new_op->op       = RQ_OP_AGE_LT;
	    new_op->data.INT = atoi(tok+4);
	    if ( last_op ) {
		last_op->next = new_op;
		last_op = new_op;
	    } else {
		last_op = ops = new_op;
	    }
	}
	if ( !strncasecmp(tok, "dst=", 4) ) {
	    new_op = calloc(sizeof(*new_op),1);
	    new_op->op       = RQ_OP_DST;
	    new_op->data.CHAR = strdup(tok+4);
	    if ( last_op ) {
		last_op->next = new_op;
		last_op = new_op;
	    } else {
		last_op = ops = new_op;
	    }
	}
	if ( !strncasecmp(tok, "src=", 4) ) {
	    new_op = calloc(sizeof(*new_op),1);
	    new_op->op       = RQ_OP_SRC;
	    if ( str_to_sa(tok+4, (struct sockaddr *)&new_op->data.ADR) ) {
		my_xlog(OOPS_LOG_SEVERE, "Failed to resolve %s\n", tok+4);
	    }
	    if ( last_op ) {
		last_op->next = new_op;
		last_op = new_op;
	    } else {
		last_op = ops = new_op;
	    }
	}
    }
    /* collect all current requests in list */
    for(i=0;i<RQ_HASH_SIZE;i++) {
	pthread_mutex_lock(&rq_hash[i].lock);
	rq = rq_hash[i].link;
	while ( rq ) {
	    char	*cliaddr = NULL;
	    char	*myaddr = NULL;
	    int		rq_time;

	    if ( rq_match_ops(rq, ops) == FALSE ) {
		rq = rq->next;
		continue;
	    }
	    new = calloc(sizeof(*new),1);
	    if ( !new ) goto done;
	    if ( !last_rq ) {
		last_rq = rq_list = new;
	    } else {
		last_rq->next = new;
		last_rq = new;
	    }
	    cliaddr = my_inet_ntoa(&rq->client_sa);
	    myaddr = my_inet_ntoa(&rq->my_sa);
	    if ( cliaddr && myaddr ) {
		snprintf(buf, sizeof(buf)-1, " %s:%d->%s:%d\n",
			cliaddr, ntohs((rq->client_sa).sin_port),
			myaddr, ntohs((rq->my_sa).sin_port));
	    }
	    new->conn = strdup(buf);
	    IF_FREE(cliaddr);
	    IF_FREE(myaddr);
	    if ( rq->tag ) {
		snprintf(buf, sizeof(buf)-1, " Tag: %s\n", rq->tag);
		new->tag = strdup(buf);
	    }
	    buf[0] = 0;
	    if ( rq->method ) {
		strncat(buf, rq->method, sizeof(buf) - strlen(buf) - 2);
		strncat(buf, " ", sizeof(buf) - strlen(buf) - 2);
	    }
	    if ( rq->url.proto ) {
		strncat(buf, rq->url.proto, sizeof(buf) - strlen(buf) - 2);
		strncat(buf, "://", sizeof(buf) - strlen(buf) - 2);
	    }
	    if ( rq->url.host ) {
		strncat(buf, rq->url.host, sizeof(buf) - strlen(buf) - 2);
	    }
	    if ( rq->url.path ) {
		strncat(buf, rq->url.path, sizeof(buf) - strlen(buf) - 2);
	    }
	    new->url = strdup(buf);
	    rq_time = new->age = global_sec_timer - rq->request_time;
	    if ( rq_time < 0 ) rq_time = 0;
	    snprintf(buf, sizeof(buf)-1, " Doc size: %d,\n received: %d Bytes (%.2f B/s)\n sent:     %d Bytes (%.2f B/s)\n",
		rq->doc_size, rq->doc_received,
				rq_time?(1e0*rq->doc_received/rq_time):0,
			      rq->doc_sent,
			        rq_time?(1e0*rq->doc_sent/rq_time):0);
	    new->info = strdup(buf);
	    rq = rq->next;
	}
	pthread_mutex_unlock(&rq_hash[i].lock);
    }
done:
    last_rq = rq_list;
    while (last_rq) {
	new = last_rq->next;
	if ( last_rq->url ) write(so, last_rq->url, strlen(last_rq->url));
	write(so, "\n", 1);
	if ( last_rq->conn ) write(so, last_rq->conn, strlen(last_rq->conn));
	if ( last_rq->tag ) write(so, last_rq->tag, strlen(last_rq->tag));
	if ( last_rq->info ) write(so, last_rq->info, strlen(last_rq->info));
	snprintf(buf, sizeof(buf)-1, " Rq. age: %d\n", last_rq->age>0?last_rq->age:0);
	write(so, buf, strlen(buf));
	write(so, "---\n",4);
	last_rq = new;
    }
    while(ops) {
	new_op = ops->next;
	switch ( ops->op ) {
	case RQ_OP_DST:
	case RQ_OP_GRP:
		free(ops->data.CHAR);
		break;
	default:
		break;
	}
	free(ops);
	ops = new_op;
    }
    while ( rq_list ) {
	new = rq_list->next;
	IF_FREE(rq_list->url);
	IF_FREE(rq_list->tag);
	IF_FREE(rq_list->conn);
	IF_FREE(rq_list->info);
	free(rq_list);
	rq_list = new;
    }
    return(0);
}

static int
process_command(int so, char *command)
{
    if ( !strcasecmp(command, "reconfigure") ) {
	kill(my_pid, SIGHUP);
    }
    if ( !strcasecmp(command, "graceful") ) {
	skip_check = 1;
	kill(my_pid, SIGHUP);
    }
    if ( !strcasecmp(command, "flush") ) {
	int saved_lo_mark = lo_mark_val;
        lo_mark_val = 0;
	flush_mem_cache();
	lo_mark_val = saved_lo_mark;
    }
    if ( !strcasecmp(command, "shutdown") || !strcasecmp(command, "stop")) {
	kill(my_pid, SIGTERM);
    }
    if ( !strcasecmp(command, "rotate") ) {
	kill(my_pid, SIGWINCH);
    }
    if ( !strcasecmp(command, "help") ) {
	print_help(so);
    }
    if ( !strcasecmp(command, "stat") ) {
	print_stat(so);
    }
    if ( !strcasecmp(command, "htmlstat") ) {
	print_htmlstat(so);
    }
    if ( !strncasecmp(command, "verbosity=", 10) ) {
	set_verbosity(so, command);
    }
    if ( !strncasecmp(command, "requests", 8) ) {
	process_requests(so, command);
    }
    if ( !strcasecmp(command, "quit") ) {
	return(0);
    }
    return(0);
}

MODULE_STATIC
void*
process_call(void *arg)
{
struct	work	*work;
int	so;
char	command[128];

    if ( !arg ) return(NULL);
    work = arg;
    so = work->so;
    free(work);
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "process_call(): Accept called on %d\n", so);
    /* done */
    while( read_command(so, command, sizeof(command)) &&
           process_command(so, command) );
    close(so);
    return(NULL);
}

static void
open_oopsctl_so(void)
{
struct	sockaddr_un	sun_addr;
int			rc;

    oopsctl_so = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( oopsctl_so == -1 ) {
	printf("oopsctl: socket: %m\n");
	return;
    }
    bzero(&sun_addr, sizeof(sun_addr));
    sun_addr.sun_family = AF_UNIX;
    strncpy(sun_addr.sun_path, socket_path, sizeof(sun_addr.sun_path)-1);
    unlink(socket_path);
    rc = bind(oopsctl_so, (struct sockaddr*)&sun_addr, sizeof(sun_addr));
    if ( rc == -1 ) {
	printf("oopsctl: bind: %m\n");
	close(oopsctl_so);
	oopsctl_so = -1;
	return;
    }
    chmod(socket_path, 0600);
    listen(oopsctl_so, 5);
    add_socket_to_listen_list(oopsctl_so, 0, 0, 0, &process_call);

    printf("oopsctl: socket: %d\n", oopsctl_so);
/*
int			so, one = -1;
struct	sockaddr_in	sin_addr;

    so = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(so, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
    bzero(&sin_addr, sizeof(sin_addr));
    sin_addr.sin_family = AF_INET;
    sin_addr.sin_port   = htons(20050);
    rc = bind(so, (struct sockaddr*)&sin_addr, sizeof(sin_addr));
    if ( rc == -1 ) {
	verb_printf("oopsctl: bind2: %m\n");
	close(so);
	so = -1;
	return;
    }
    listen(so,5);
    add_socket_to_listen_list(so, 0, &process_call);
*/
}
