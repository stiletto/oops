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

#if	defined(SOLARIS)
#include	<thread.h>
#endif

#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/file.h>
#include	<sys/time.h>
#include	<sys/un.h>

#include	<netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include	"../oops.h"
#include	"../modules.h"

char	module_type   = MODULE_LISTENER ;
char	module_name[] = "oopsctl" ;
char	module_info[] = "Oops contlolling module" ;

static	rwl_t		oopsctl_config_lock;

static	char		socket_path[MAXPATHLEN];

int	oopsctl_so	= -1;

#define	WRLOCK_OOPSCTL_CONFIG	rwl_wrlock(&oopsctl_config_lock)
#define	RDLOCK_OOPSCTL_CONFIG	rwl_rdlock(&oopsctl_config_lock)
#define	UNLOCK_OOPSCTL_CONFIG	rwl_unlock(&oopsctl_config_lock)

static	void	open_oopsctl_so();

int
mod_load()
{
    printf("oopsctl started\n");
    rwl_init(&oopsctl_config_lock);
    socket_path[0] = 0;
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
    UNLOCK_OOPSCTL_CONFIG ;
}

int
mod_config_end()
{

    WRLOCK_OOPSCTL_CONFIG ;
    if ( socket_path[0] ) {
	open_oopsctl_so();
    }
    UNLOCK_OOPSCTL_CONFIG ;
}

int
mod_config(char *config)
{
char	*p = config;

    WRLOCK_OOPSCTL_CONFIG ;

    while( *p && isspace(*p) ) p++;
    if ( !strncasecmp(p, "socket_path", 11) ) {
	p += 11;
	while (*p && isspace(*p) ) p++;
	strncpy(socket_path, p, sizeof(socket_path) -1 );
    }
done:
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
	if ( (ptr==buff) && isspace(c) ) continue;
	if ( c == '\n' || c == '\r' ) return(1);
	*ptr = c; ptr++; *ptr = 0;
        if ( ptr - buff >= len -1 )
            return(1);
    }
    return(0);
}

int
process_command(int so, char *command)
{
    if ( !strcasecmp(command, "reconfigure") ) {
	kill(my_pid, SIGHUP);
    } else
    if ( !strcasecmp(command, "shutdown") ) {
	kill(my_pid, SIGTERM);
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
}

int
print_stat(int so)
{
char			buf[1024], *type;
int			uptime = global_sec_timer - start_time;
struct	storage_st	*storage;
struct	general_module	*mod;
struct	peer		*peer;
int			last_min_req_rate, last_min_hit_rate;

    if ( oops_stat.requests_http1 ) {
	last_min_req_rate = oops_stat.requests_http1/6;
	last_min_hit_rate = (oops_stat.hits1*1000)/oops_stat.requests_http1;
    } else {
	last_min_req_rate = last_min_hit_rate = 0;
    }
    write(so, "## --  General info   --\n", 25);
    sprintf(buf, "Version: %s, db version: %s\n", version, db_ver);
    write(so, buf, strlen(buf));
    sprintf(buf, "Uptime       : %dsec, (%dday(s), %dhour(s), %dmin(s))\n",
			uptime, uptime/(24*3600), (uptime%(24*3600))/3600,
			(uptime%3600)/60);
    write(so, buf, strlen(buf));
    sprintf(buf, "Clients      : %d\n", clients_number);
    write(so, buf, strlen(buf));
    sprintf(buf, "HTTP requests: %d\n", oops_stat.requests_http);
    write(so, buf, strlen(buf));
    sprintf(buf, "ICP  requests: %d\n", oops_stat.requests_icp);
    write(so, buf, strlen(buf));
    sprintf(buf, "Total hits   : %d\n", oops_stat.hits);
    write(so, buf, strlen(buf));
    sprintf(buf, "Thread pool  : %d ready to serve (out of %d max)\n", current_workers, max_workers);
    write(so, buf, strlen(buf));
    sprintf(buf, "Curr.req.rate: %d.%d req/sec\n", last_min_req_rate/10, last_min_req_rate%10);
    write(so, buf, strlen(buf));
    sprintf(buf, "Curr.hit.rate: %d.%d %%\n", last_min_hit_rate/10, last_min_hit_rate%10);
    write(so, buf, strlen(buf));
    /* storages */
    write(so, "## --    storages     --\n", 25);
    RDLOCK_CONFIG;
    storage = storages;
    while(storage) {
	sprintf(buf, "Storage      : %s\n", storage->path);
	write(so, buf, strlen(buf));
	sprintf(buf, "Size         : %d bytes (%dMb)\n", storage->size,
					storage->size/(1024*1024));
	write(so, buf, strlen(buf));
	sprintf(buf, "Free blks    : %d blks (%dMb)\n", storage->super.blks_free,
					(storage->super.blks_free*4096)/(1024*1024));
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
	default:
	    break;
	}
	sprintf(buf, "%-13s (%s)\n", mod->name, type);
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
        sprintf(buf, "Hits recvd   : %d\n", peer->hits_recvd);
	write(so, buf, strlen(buf));
        sprintf(buf, "Reqs recvd   : %d\n", peer->rq_recvd);
	write(so, buf, strlen(buf));

	peer = peer->next;
    }
    UNLOCK_CONFIG ;
    sprintf(buf,"## -- end of icp peers--\n");
    write(so, buf, strlen(buf));
}

int
print_htmlstat(int so)
{
char			buf[1024], *type;
int			uptime = global_sec_timer - start_time;
struct	storage_st	*storage;
struct	general_module	*mod;
struct	peer		*peer;
int			last_min_req_rate, last_min_hit_rate;

    if ( oops_stat.requests_http1 ) {
	last_min_req_rate = oops_stat.requests_http1/6;
	last_min_hit_rate = (oops_stat.hits1*10)/oops_stat.requests_http1;
    } else {
	last_min_req_rate = last_min_hit_rate = 0;
    }

    sprintf(buf, "<html><title>Oops stat</title><body bgcolor=white>\n");
    write(so, buf, strlen(buf));
    sprintf(buf, "<table><tr bgcolor=blue><td><font color=yellow>General Info<td>&nbsp</font>\n");
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td valign=top>Version<td>%s, db version: %s\n", version, db_ver);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Uptime<td>%dsec, (%dday(s), %dhour(s), %dmin(s))\n",
			uptime, uptime/(24*3600), (uptime%(24*3600))/3600,
			(uptime%3600)/60);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Clients<td>%d\n", clients_number);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>HTTP requests<td>%d\n", oops_stat.requests_http);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>ICP  requests<td>%d\n", oops_stat.requests_icp);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Total hits<td>%d\n", oops_stat.hits);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Thread pool<td>%d ready to serve (out of %d max)\n", current_workers, max_workers);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Curr.req.rate<td>%d.%d req/sec\n", last_min_req_rate/10, last_min_req_rate%10);
    write(so, buf, strlen(buf));
    sprintf(buf, "<tr><td>Curr.hit.rate<td>%d.%d %%\n", last_min_hit_rate/10, last_min_hit_rate%10);
    write(so, buf, strlen(buf));
    /* storages */
    sprintf(buf, "<tr bgcolor=blue><td><font color=yellow>Storages</font><td>&nbsp\n");
    write(so, buf, strlen(buf));
    RDLOCK_CONFIG;
    storage = storages;
    while(storage) {
	sprintf(buf, "<tr><td>Storage<td>%s\n", storage->path);
	write(so, buf, strlen(buf));
	sprintf(buf, "<tr><td>Size<td>%d bytes (%dMb)\n", storage->size,
					storage->size/(1024*1024));
	write(so, buf, strlen(buf));
	sprintf(buf, "<tr><td>Free blks<td>%d blks (%dMb)\n", storage->super.blks_free,
					(storage->super.blks_free*4096)/(1024*1024));
	write(so, buf, strlen(buf));
	sprintf(buf, "<tr><td>State<td>%s\n", (storage->flags&ST_READY)?
					"READY":"NOT_READY");
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
	default:
	    break;
	}
	sprintf(buf, "<tr><td>%-13s<td>%s\n", mod->name, type);
	write(so, buf, strlen(buf));
	mod = mod->next_global;
    }
    sprintf(buf,"<tr bgcolor=blue><td><font color=yellow>icp peers</font><td><font color=yellow>&nbsp</font>");
    write(so, buf, strlen(buf));
    RDLOCK_CONFIG ;
    peer = peers;
    while ( peer ) {
        sprintf(buf, "<tr><td>Name<td>%s %d %d\n", peer->name, peer->http_port, peer->icp_port);
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
        sprintf(buf, "<tr><td>Hits recvd<td>%d\n", peer->hits_recvd);
	write(so, buf, strlen(buf));
        sprintf(buf, "<tr><td>Reqs recvd<td>%d\n", peer->rq_recvd);
	write(so, buf, strlen(buf));

	peer = peer->next;
    }
    UNLOCK_CONFIG ;
    sprintf(buf, "</table></body></html>\n");
    write(so, buf, strlen(buf));
}

void*
process_call(void *arg)
{
int	so = (int)arg;
char	command[128];

    my_log("Accept called on %d\n", so);
    /* done */
    while( read_command(so, command, sizeof(command)) &&
           process_command(so, command) );
    close(so);
}

void
open_oopsctl_so()
{
struct	sockaddr_un	sun_addr;
struct	sockaddr_in	sin_addr;
int			rc;
int			so, one = -1;

    oopsctl_so = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( oopsctl_so == -1 ) {
	printf("oopsctl:socket: %s\n", strerror(errno));
	return;
    }
    bzero(&sun_addr, sizeof(sun_addr));
    sun_addr.sun_family = AF_UNIX;
    strncpy(sun_addr.sun_path, socket_path, sizeof(sun_addr.sun_path)-1);
    unlink(socket_path);
    rc = bind(oopsctl_so, (struct sockaddr*)&sun_addr, sizeof(sun_addr));
    if ( rc == -1 ) {
	printf("oopsctl:bind: %s\n", strerror(errno));
	close(oopsctl_so);
	oopsctl_so = -1;
	return;
    }
    chmod(socket_path, 0600);
    listen(oopsctl_so, 5);
    add_socket_to_listen_list(oopsctl_so, 0, &process_call);

/*
    so = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(so, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
    bzero(&sin_addr, sizeof(sin_addr));
    sin_addr.sin_family = AF_INET;
    sin_addr.sin_port   = htons(20050);
    rc = bind(so, (struct sockaddr*)&sin_addr, sizeof(sin_addr));
    if ( rc == -1 ) {
	printf("oopsctl:bind2: %s\n", strerror(errno));
	close(so);
	return;
    }
    listen(so,5);
    add_socket_to_listen_list(so, 0, &process_call);
*/
}
