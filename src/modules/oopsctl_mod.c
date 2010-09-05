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

char	module_type   = MODULE_LISTENER ;
char	module_name[] = "oopsctl" ;
char	module_info[] = "Oops controlling module" ;

static	rwl_t		oopsctl_config_lock;

static	char		socket_path[MAXPATHLEN];
static	int		html_refresh;

int	oopsctl_so	= -1;

#define	WRLOCK_OOPSCTL_CONFIG	rwl_wrlock(&oopsctl_config_lock)
#define	RDLOCK_OOPSCTL_CONFIG	rwl_rdlock(&oopsctl_config_lock)
#define	UNLOCK_OOPSCTL_CONFIG	rwl_unlock(&oopsctl_config_lock)

static	void	open_oopsctl_so(void);

int
mod_load()
{
    printf("Oopsctl started\n");
    rwl_init(&oopsctl_config_lock);
    socket_path[0] = 0;
    html_refresh = 0;
    return(MOD_CODE_OK);
}
int
mod_unload()
{
    WRLOCK_OOPSCTL_CONFIG ;
    printf("oopsctl_report stopped\n");
    return(MOD_CODE_OK);
}

int
mod_config_beg()
{
    WRLOCK_OOPSCTL_CONFIG ;
    oopsctl_so = -1;		/* was closed in core */
    socket_path[0] = 0;
    html_refresh = 0;
    UNLOCK_OOPSCTL_CONFIG ;
    return(MOD_CODE_OK);
}

int
mod_run()
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

int
mod_config_end()
{
    return(MOD_CODE_OK);
}

int
mod_config(char *config)
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

int
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

int
print_help(int so)
{
char	**p, *help_message[] = {"reconfigure - re-read config file (like kill -HUP).\n",
			   "shutdown    - gracefuly shutdown (like kill -TERM).\n",
			   "stat        - display statistics.\n",
			   "htmlstat    - display statistics in html.\n",
			   NULL};

    p = help_message;
    while(*p) {
	write(so, *p, strlen(*p));
	p++;
    }
    return(0);
}

int
print_stat(int so)
{
char			buf[1024], *type, *info;
int			uptime = global_sec_timer - start_time;
struct	storage_st	*storage;
struct	general_module	*mod;
struct	peer		*peer;
float			last_min_req_rate, last_min_hit_rate,last_min_icp_rate;
float			tot_req_rate, tot_hit_rate;
float			peer_hits_percent;
float			max_req_rate, max_icp_rate, max_hit_rate;
float			free_pages_p;
float			drop_rate;
char			ctime_buf[30] = "";

    if ( oops_stat.requests_http1 ) {
	last_min_req_rate = oops_stat.requests_http1/6e1;
	last_min_hit_rate = (oops_stat.hits1*1e2)/oops_stat.requests_http1;
    } else {
	last_min_req_rate = last_min_hit_rate = 0;
    }
    last_min_icp_rate = oops_stat.requests_icp1/6e1;
    if ( uptime ) {
	tot_req_rate = (oops_stat.requests_http*1e0)/uptime;
	if ( oops_stat.requests_http )
		tot_hit_rate = (oops_stat.hits*1e2)/oops_stat.requests_http;
	    else
		tot_hit_rate = 0;
    } else {
	tot_req_rate = tot_hit_rate = 0;
	uptime = 1;
    }
    max_req_rate = oops_stat.requests_http0_max/6e1;
    max_icp_rate = oops_stat.requests_icp0_max/6e1;
    max_hit_rate = oops_stat.hits0_max/6e1;
    drop_rate    = oops_stat.drops0/6e1;
    write(so, "## --  General info   --\n", 25);
    sprintf(buf, "Version      : %s, DB version: %s\n", version, db_ver);
    write(so, buf, strlen(buf));
    sprintf(buf, "Uptime       : %dsec, (%dday(s), %dhour(s), %dmin(s))\n",
			uptime, uptime/(24*3600), (uptime%(24*3600))/3600,
			(uptime%3600)/60);
    write(so, buf, strlen(buf));
    CTIME_R(&global_sec_timer, ctime_buf, sizeof(ctime_buf)-1);
    sprintf(buf,  "Last update  : %s", ctime_buf);
    write(so, buf, strlen(buf));
    sprintf(buf, "Clients      : %d (max: %d)\n", (int)clients_number, (int)oops_stat.clients_max);
    write(so, buf, strlen(buf));
    sprintf(buf, "HTTP requests: %d\n", (int)oops_stat.requests_http);
    write(so, buf, strlen(buf));
    sprintf(buf, "ICP  requests: %d\n", (int)oops_stat.requests_icp);
    write(so, buf, strlen(buf));
    sprintf(buf, "Total hits   : %d\n", (int)oops_stat.hits);
    write(so, buf, strlen(buf));
    if ( current_workers ) {
	sprintf(buf, "Thread pool  : %d ready to serve (out of %d max)\n", current_workers, max_workers);
	write(so, buf, strlen(buf));
    }
    sprintf(buf, "Curr.req.rate: %.2f req/sec (max: %.2f)\n",
	last_min_req_rate, max_req_rate);
    write(so, buf, strlen(buf));
    sprintf(buf, "Tot.req.rate : %.2f req/sec\n", tot_req_rate);
    write(so, buf, strlen(buf));
    sprintf(buf, "Curr.hit.rate: %.2f %%\n", last_min_hit_rate);
    write(so, buf, strlen(buf));
    sprintf(buf, "Tot.hit.rate : %.2f %%\n", tot_hit_rate);
    write(so, buf, strlen(buf));
    if ( (oops_stat.drops0>0) || (oops_stat.drops>0) ) {
	sprintf(buf, "Cur.drop.rate: %.2f %%\n", drop_rate);
	write(so, buf, strlen(buf));
	sprintf(buf, "Tot. drops   : %d\n", oops_stat.drops);
	write(so, buf, strlen(buf));
    }
    sprintf(buf, "Curr.icp.rate: %.2f req/sec (max: %.2f)\n",
	last_min_icp_rate, max_icp_rate);
    write(so, buf, strlen(buf));
#if	HAVE_GETRUSAGE
    {
    unsigned long utime, stime, utime0, stime0, total;
    unsigned long delta, deltatime, deltau, deltas;

    deltatime= (oops_stat.timestamp - oops_stat.timestamp0)*1000;
    if ( deltatime <= 0 ) deltatime = 60000;
    utime = oops_stat.rusage.ru_utime.tv_sec*1000 +
            oops_stat.rusage.ru_utime.tv_usec/1000;
    stime = oops_stat.rusage.ru_stime.tv_sec*1000 +
            oops_stat.rusage.ru_stime.tv_usec/1000;
    utime0 = oops_stat.rusage0.ru_utime.tv_sec*1000 +
            oops_stat.rusage0.ru_utime.tv_usec/1000;
    stime0 = oops_stat.rusage0.ru_stime.tv_sec*1000 +
            oops_stat.rusage0.ru_stime.tv_usec/1000;
    delta = (utime+stime) - (utime0+stime0);
    deltau = utime - utime0;
    deltas = stime - stime0;
    write(so, "## --       CPU       --\n", 25);
    sprintf(buf, "Total usage  : %dms\n", (int)(utime+stime));
    write(so, buf, strlen(buf));
    sprintf(buf, "Delta usage  : %dms\n", (int)delta);
    write(so, buf, strlen(buf));
    sprintf(buf, "Delta time   : %dms\n", (int)deltatime);
    write(so, buf, strlen(buf));
    sprintf(buf, "Curr. CPU    : %.2f %% (%.2fs+%.2fu)\n",
	    (1e2*delta)/deltatime,
	    (1e2*deltas)/deltatime,
	    (1e2*deltau)/deltatime);
    write(so, buf, strlen(buf));
    total=utime+stime;
    uptime = 1000*uptime;
    sprintf(buf, "Aver. CPU    : %.2f %% (%.2fs+%.2fu)\n",
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
    while(storage) {
	sprintf(buf, "Storage      : %s\n", storage->path);
	write(so, buf, strlen(buf));
	if ( storage->size != -1 )
	    sprintf(buf, "Size         : %.2f MB\n",
					(1e0*storage->size)/(1024*1024));
	else
	    sprintf(buf, "Size         : %.2f MB\n",
					(storage->super.blks_total*4e0)/1024);
	write(so, buf, strlen(buf));
	if ( storage->super.blks_free == 0 || storage->super.blks_total == 0 )
		free_pages_p = 0;
	    else
		free_pages_p = (1e2*storage->super.blks_free)/storage->super.blks_total;
	sprintf(buf, "Free blks    : %d blks (%.2fMb) %.2f %%\n",
		storage->super.blks_free,
		(1e0*storage->super.blks_free*STORAGE_PAGE_SIZE)/(1024*1024),
		free_pages_p);
	write(so, buf, strlen(buf));
	sprintf(buf, "State        : %s\n", (storage->flags&ST_READY)?
					"READY":"NOT_READY");
	write(so, buf, strlen(buf));
	sprintf(buf, "Fileno       : %d\n", storage->fd);
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
	default:
	    type = "Unknown";
	    break;
	}
	info = mod->info?mod->info:"";
	sprintf(buf, "%-13s %s (%s)\n", mod->name, info, type);
	write(so, buf, strlen(buf));
	mod = mod->next_global;
    }
    write(so,   "## -- end of modules  --\n", 25);
    sprintf(buf,"## --    icp peers    --\n");
    write(so, buf, strlen(buf));
    RDLOCK_CONFIG ;
    peer = peers;
    while ( peer ) {
        sprintf(buf, "Name         : %s %d %d\n", peer->name, peer->http_port, peer->icp_port);
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
        sprintf(buf, "Type         : %s\n", type);
	write(so, buf, strlen(buf));
        sprintf(buf, "Req. sent    : %d\n", peer->rq_sent);
	write(so, buf, strlen(buf));
        sprintf(buf, "Answ. recvd  : %d\n", peer->an_recvd);
	write(so, buf, strlen(buf));
	if ( peer->an_recvd == 0 || peer->hits_recvd == 0 )
	    peer_hits_percent = 0;
	    else
		peer_hits_percent = (peer->hits_recvd*1e2)/peer->an_recvd;
        sprintf(buf, "Hits recvd   : %d (%.2f %%)\n", peer->hits_recvd,
			peer_hits_percent);
	write(so, buf, strlen(buf));
        sprintf(buf, "Reqs recvd   : %d\n", peer->rq_recvd);
	write(so, buf, strlen(buf));
	if ( peer->hits_sent == 0 || peer->rq_recvd == 0 )
	    peer_hits_percent = 0;
	    else
		peer_hits_percent = (peer->hits_sent*1e2)/peer->rq_recvd;
        sprintf(buf, "Hits sent    : %d (%.2f %%)\n", peer->hits_sent,
			peer_hits_percent);
	write(so, buf, strlen(buf));
        sprintf(buf, "Status       : %s\n",
        	TEST(peer->state, PEER_DOWN)?"DOWN":"UP");
	write(so, buf, strlen(buf));

	peer = peer->next;
    }
    UNLOCK_CONFIG ;
    sprintf(buf,"## -- end of icp peers--\n");
    write(so, buf, strlen(buf));
    return(0);
}

int
print_htmlstat(int so)
{
char			buf[1024], *type, *info;
int			uptime = global_sec_timer - start_time;
struct	storage_st	*storage;
struct	general_module	*mod;
struct	peer		*peer;
float			last_min_req_rate, last_min_hit_rate, last_min_icp_rate;
float			tot_req_rate, tot_hit_rate;
float			max_req_rate, max_icp_rate, max_hit_rate;
float			peer_hits_percent;
float			free_pages_p;
float			drop_rate;
char			ctime_buf[30];

    if ( oops_stat.requests_http1 ) {
	last_min_req_rate = oops_stat.requests_http1/6e1;
	last_min_hit_rate = (oops_stat.hits1*1e2)/oops_stat.requests_http1;
    } else {
	last_min_req_rate = last_min_hit_rate = 0;
    }
    last_min_icp_rate = oops_stat.requests_icp1/6e1;
    if ( uptime ) {
	tot_req_rate = (oops_stat.requests_http*1e0)/uptime;
	if ( oops_stat.requests_http )
		tot_hit_rate = (oops_stat.hits*1e2)/oops_stat.requests_http;
	    else
		tot_hit_rate = 0;
    } else {
	tot_req_rate = tot_hit_rate = 0;
	uptime = 1;
    }
    max_req_rate = oops_stat.requests_http0_max/6e1;
    max_icp_rate = oops_stat.requests_icp0_max/6e1;
    max_hit_rate = oops_stat.hits0_max/6e1;
    drop_rate = oops_stat.drops0/6e1;
    sprintf(buf, "<html><title>Oops stat</title>\n");
    write(so, buf, strlen(buf));
    if ( html_refresh ) {
	sprintf(buf, "<META HTTP-EQUIV=\"Refresh\" CONTENT=\"%d\">\n", html_refresh);
	write(so, buf, strlen(buf));
    }
    sprintf(buf, "<body bgcolor=white><table><tr bgcolor=blue><td><font color=yellow>General Info<td>&nbsp</font>\n");
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td valign=top>Version<td>%s, db version: %s\n", version, db_ver);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Uptime<td>%dsec, (%dday(s), %dhour(s), %dmin(s))\n",
			uptime, uptime/(24*3600), (uptime%(24*3600))/3600,
			(uptime%3600)/60);
    write(so, buf, strlen(buf));
    CTIME_R(&global_sec_timer, ctime_buf, sizeof(ctime_buf)-1);
    sprintf(buf,  "<tr><td>Last update<td>%s", ctime_buf);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Clients<td>%d (max: %d)\n", (int)clients_number, (int)oops_stat.clients_max);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>HTTP requests<td>%d\n", (int)oops_stat.requests_http);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>ICP  requests<td>%d\n", (int)oops_stat.requests_icp);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Total hits<td>%d\n", (int)oops_stat.hits);
    write(so, buf, strlen(buf));
    if ( current_workers ) {
	sprintf(buf, "<tr><td>Thread pool<td>%d ready to serve (out of %d max)\n", current_workers, max_workers);
	write(so, buf, strlen(buf));
    }
    sprintf(buf, "<tr><td>Curr.req.rate<td>%.2f req/sec (max: %.2f)\n",
	last_min_req_rate, max_req_rate);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Tot.req.rate<td>%.2f req/sec\n",
	tot_req_rate);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Curr.hit.rate<td>%.2f %%\n",
	last_min_hit_rate);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Tot.hit.rate<td>%.2f %%\n", tot_hit_rate);
    write(so, buf, strlen(buf));
    if ( (oops_stat.drops0>0) || (oops_stat.drops>0) ) {
	sprintf(buf, "<tr><td>Cur.drop.rate<td>%.2f %%\n", drop_rate);
	write(so, buf, strlen(buf));
	sprintf(buf, "<tr><td>Tot. drops<td>%d\n", oops_stat.drops);
	write(so, buf, strlen(buf));
    }
    sprintf(buf, "<tr><td>Curr.icp.rate<td>%.2f req/sec (max: %.2f)\n",
	last_min_icp_rate, max_icp_rate);
    write(so, buf, strlen(buf));
#if	HAVE_GETRUSAGE
    {
    unsigned long utime, stime, utime0, stime0, total;
    unsigned long delta, deltatime, deltau, deltas;

    deltatime= (oops_stat.timestamp - oops_stat.timestamp0)*1000;
    if ( deltatime <= 0 ) deltatime = 60000;
    utime = oops_stat.rusage.ru_utime.tv_sec*1000 +
            oops_stat.rusage.ru_utime.tv_usec/1000;
    stime = oops_stat.rusage.ru_stime.tv_sec*1000 +
            oops_stat.rusage.ru_stime.tv_usec/1000;
    utime0 = oops_stat.rusage0.ru_utime.tv_sec*1000 +
            oops_stat.rusage0.ru_utime.tv_usec/1000;
    stime0 = oops_stat.rusage0.ru_stime.tv_sec*1000 +
            oops_stat.rusage0.ru_stime.tv_usec/1000;
    delta = (utime+stime) - (utime0+stime0);
    deltau = utime - utime0;
    deltas = stime - stime0;
    sprintf(buf, "<tr><td>Total usage<td>%dms\n", (int)(utime+stime));
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Delta usage<td>%dms\n", (int)delta);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Delta time<td>%dms\n", (int)deltatime);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Curr. CPU<td>%.2f %% (%.2fs+%.2fu)\n",
	    (1e2*delta)/deltatime,
	    (1e2*deltas)/deltatime,
	    (1e2*deltau)/deltatime);
    write(so, buf, strlen(buf));
    total=utime+stime;
    uptime = 1000*uptime;
    sprintf(buf, "<tr><td>Aver. CPU<td>%.2f %% (%.2fs+%.2fu)\n",
	    (1e2*total)/uptime,
	    (1e2*stime)/uptime,
	    (1e2*utime)/uptime);
    write(so, buf, strlen(buf));
    }
#endif
    /* storages */
    sprintf(buf, "<tr bgcolor=blue><td><font color=yellow>Storages</font><td>&nbsp\n");
    write(so, buf, strlen(buf));
    RDLOCK_CONFIG;
    storage = storages;
    while(storage) {
	sprintf(buf, "<tr><td><b>Storage<td><b>%s\n", storage->path);
	write(so, buf, strlen(buf));
	if ( storage->size != -1 )
	    sprintf(buf, "<tr><td>Size<td>%.2f MB\n",
					(1e0*storage->size/(1024*1024)));
	else
	    sprintf(buf, "<tr><td>Size<td>%d blks (%.2f MB)\n", storage->super.blks_total,
					(storage->super.blks_total*4e0)/1024);
	write(so, buf, strlen(buf));
	if ( storage->super.blks_free == 0 || storage->super.blks_total == 0 )
	    free_pages_p = 0;
	    else
		free_pages_p = (1e2*storage->super.blks_free)/storage->super.blks_total;
	sprintf(buf, "<tr><td>Free blks<td>%d blks (%.2fMb) %.2f %%\n", storage->super.blks_free,
					((1e0*storage->super.blks_free)*STORAGE_PAGE_SIZE)/(1024*1024),
					free_pages_p);
	write(so, buf, strlen(buf));
	sprintf(buf, "<tr><td>State<td>%s\n", (storage->flags&ST_READY)?
					"READY":"<font color=red>NOT_READY</font>");
	write(so, buf, strlen(buf));
	sprintf(buf, "<tr><td>Fileno<td>%d\n", storage->fd);
	write(so, buf, strlen(buf));
	storage = storage->next;
    }
    UNLOCK_CONFIG;
    /* modules */
    sprintf(buf, "<tr bgcolor=blue><td><font color=yellow>Module</font><td><font color=yellow>Type</font>\n");
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
	default:
	    type = "Unknown";
	    break;
	}
	info = mod->info?mod->info:"";
	sprintf(buf, "<tr><td>%-13s<td>%s (%s)\n", mod->name, info, type);
	write(so, buf, strlen(buf));
	mod = mod->next_global;
    }
    sprintf(buf,"<tr bgcolor=blue><td><font color=yellow>icp peers</font><td><font color=yellow>&nbsp</font>");
    write(so, buf, strlen(buf));
    RDLOCK_CONFIG ;
    peer = peers;
    while ( peer ) {
        sprintf(buf, "<tr><td><b>Name<td><b>%s %d %d\n", peer->name, peer->http_port, peer->icp_port);
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
        sprintf(buf, "<tr><td>Type<td>%s\n", type);
	write(so, buf, strlen(buf));
        sprintf(buf, "<tr><td>Req. sent<td>%d\n", peer->rq_sent);
	write(so, buf, strlen(buf));
        sprintf(buf, "<tr><td>Answ. recvd<td>%d\n", peer->an_recvd);
	write(so, buf, strlen(buf));
	if ( peer->an_recvd == 0 || peer->hits_recvd == 0 )
	    peer_hits_percent = 0;
	    else
		peer_hits_percent = (peer->hits_recvd*1e2)/peer->an_recvd;
        sprintf(buf, "<tr><td>Hits recvd<td>%d (%.2f %%)\n", peer->hits_recvd,
			peer_hits_percent);
	write(so, buf, strlen(buf));
        sprintf(buf, "<tr><td>Reqs recvd<td>%d\n", peer->rq_recvd);
	write(so, buf, strlen(buf));
	if ( peer->hits_sent == 0 || peer->rq_recvd == 0 )
	    peer_hits_percent = 0;
	    else
		peer_hits_percent = (peer->hits_sent*1e2)/peer->rq_recvd;
        sprintf(buf, "<tr><td>Hits sent<td>%d (%.2f %%)\n", peer->hits_sent,
			peer_hits_percent);
	write(so, buf, strlen(buf));
        sprintf(buf, "<tr><td>Status<td>%s\n",
        	TEST(peer->state, PEER_DOWN)?"DOWN":"UP");
	write(so, buf, strlen(buf));

	peer = peer->next;
    }
    UNLOCK_CONFIG ;
    sprintf(buf, "</table></body></html>\n");
    write(so, buf, strlen(buf));
    return(0);
}

int
process_command(int so, char *command)
{
    if ( !strcasecmp(command, "reconfigure") ) {
	kill(my_pid, SIGHUP);
    } else
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
    if ( !strcasecmp(command, "quit") ) {
	return(0);
    }
    return(0);
}

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
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "process_call(): Accept called on %d\n", so);
    /* done */
    while( read_command(so, command, sizeof(command)) &&
           process_command(so, command) );
    close(so);
    return(NULL);
}

void
open_oopsctl_so(void)
{
struct	sockaddr_un	sun_addr;
int			rc;

    oopsctl_so = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( oopsctl_so == -1 ) {
	verb_printf("oopsctl: socket: %m\n");
	return;
    }
    bzero(&sun_addr, sizeof(sun_addr));
    sun_addr.sun_family = AF_UNIX;
    strncpy(sun_addr.sun_path, socket_path, sizeof(sun_addr.sun_path)-1);
    unlink(socket_path);
    rc = bind(oopsctl_so, (struct sockaddr*)&sun_addr, sizeof(sun_addr));
    if ( rc == -1 ) {
	verb_printf("oopsctl: bind: %m\n");
	close(oopsctl_so);
	oopsctl_so = -1;
	return;
    }
    chmod(socket_path, 0600);
    listen(oopsctl_so, 5);
    add_socket_to_listen_list(oopsctl_so, 0, 0, &process_call);

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
	return;
    }
    listen(so,5);
    add_socket_to_listen_list(so, 0, &process_call);
*/
}
