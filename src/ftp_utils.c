#include        <stdio.h>
#include        <stdlib.h>
#include        <fcntl.h>
#include        <errno.h>
#include        <stdarg.h>
#include        <string.h>
#include        <strings.h>
#include        <netdb.h>
#include        <unistd.h>
#include        <ctype.h>
#include        <signal.h>
#include        <time.h>

#include        <sys/param.h>
#include        <sys/socket.h>
#include        <sys/types.h>
#include        <sys/stat.h>
#include        <sys/file.h>
#include        <sys/time.h>

#include        <netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"

extern	char	icons_host[MAXPATHLEN];
extern	char	icons_path[MAXPATHLEN];
extern	char	icons_port[64];
int	server_connect(struct ftp_r *);
int	get_server_greeting(struct ftp_r *);
int	send_user_pass_type(struct ftp_r *);
int	try_passive(struct ftp_r *);
int	try_port(struct ftp_r *);
int	try_retr(struct ftp_r *);
int	try_cwd(struct ftp_r *);
int	try_size(struct ftp_r *);
int	recv_ftp_list(struct ftp_r *);
int	recv_ftp_data(struct ftp_r *);
int	list_parser(char *, void *);
int	add_nlst_entry(char *, void *);
int	send_http_header(int, char *, int, struct mem_obj *);
int	parse_answ(struct buff*, int*, int (*f)(char *, void*), void *);
int	parse_ftp_srv_answ(struct buff *, int *, struct ftp_r *);
void	send_ftp_err(struct ftp_r *);
char	*in_nlst(char *, struct string_list *);
int	recv_ftp_nlst(struct ftp_r *req);
int	request_list(struct ftp_r *ftp_r);

void
ftp_fill_mem_obj(int so, struct request *rq,
		 char *headers, struct mem_obj *obj)
{
int			server_so = -1;
int			r;
struct	url		*url = &rq->url;
struct	ftp_r		ftp_request;
struct  sockaddr_in     dst_sa;
struct timeval		start_tv, stop_tv;
int			delta_tv;

    my_xlog(LOG_FTP, "Ftp...\n");
    if ( parent_port ) {
        bzero(&dst_sa, sizeof(dst_sa));
	if ( local_networks_sorted && local_networks_sorted_counter ) {
	    if (str_to_sa(rq->url.host, (struct sockaddr*)&dst_sa) )
		bzero(&dst_sa, sizeof(dst_sa));
	}
	if ( !is_local_dom(rq->url.host) && !is_local_net(&dst_sa) ) {
	    fill_mem_obj(so, rq, headers, obj);
	    return;
	}
    }
    gettimeofday(&start_tv, NULL);
    bzero(&ftp_request, sizeof(ftp_request));
    ftp_request.client	= so;
    ftp_request.obj	= obj;
    ftp_request.request = rq;
    ftp_request.control = -1;
    ftp_request.data    = -1;
    ftp_request.dehtml_path = dehtmlize(url->path);
    ftp_request.server_log  = alloc_buff(CHUNK_SIZE);
    ftp_request.type	= "text/html";
    ftp_request.container = alloc_buff(CHUNK_SIZE);
    if ( ! ftp_request.container )
	   goto error;
    server_so = server_connect(&ftp_request);
    if ( server_so == -1 ) goto done;
    ftp_request.control = server_so;

    r = get_server_greeting(&ftp_request);	if ( r == -1 ) goto error;

    r = send_user_pass_type(&ftp_request);	if ( r == -1 ) goto error;

    r = try_passive(&ftp_request);		if ( r == -1 ) {
	r = try_port(&ftp_request);		if ( r == -1 ) goto error;
	ftp_request.mode = MODE_PORT;
    }

    r = try_size(&ftp_request);
    r = try_retr(&ftp_request);
    if ( r == -1 ) {
	r = try_cwd(&ftp_request);
	if ( r == -1 ) {
	    goto error;
	} else {
	    ftp_request.size = 0 ;
	    r = recv_ftp_nlst(&ftp_request);
	    if ( r == -1 )
		goto error;
	    /* now we must build data connection again */
	    ftp_request.mode = MODE_PASV;
    	    r = try_passive(&ftp_request);	if ( r == -1 ) {
		r = try_port(&ftp_request);	if ( r == -1 ) goto error;
		ftp_request.mode = MODE_PORT;
	    }
	    r = request_list(&ftp_request);
	    if ( r ) goto error;
	    r = recv_ftp_list(&ftp_request);
	    if ( r ) goto error;
	}
    } else {
	r = recv_ftp_data(&ftp_request);
	if ( r ) goto error;
    }

    goto done;
error:
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    send_ftp_err(&ftp_request);
    log_access(delta_tv, &rq->client_sa,
	"TCP_MISS", 555, ftp_request.received,
	"GET", &rq->url, "DIRECT", ftp_request.type, rq->url.host);
    obj->flags |= FLAG_DEAD;
    goto free_ftp_resources;
done:
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    log_access(delta_tv, &rq->client_sa,
    	"TCP_MISS", 200, ftp_request.received,
	"GET", &rq->url, "DIRECT", ftp_request.type, rq->url.host);
    /* when we shall not cache ftp answer */
    if ( rq->url.login ) obj->flags |= FLAG_DEAD;
    if ( ftp_request.file_dir==FTP_TYPE_FILE &&
       (!ftp_request.size ||				/* unknown SIZE		*/
	 (ftp_request.received < ftp_request.size)))	/* received incomplete	*/
		obj->flags |= FLAG_DEAD;

free_ftp_resources:
    if ( server_so != -1 ) close(server_so);
    if ( ftp_request.data != -1 ) close(ftp_request.data);
    if ( ftp_request.control != -1 ) close(ftp_request.control);
    if ( ftp_request.dehtml_path ) free(ftp_request.dehtml_path);
    if ( ftp_request.server_log ) free_chain(ftp_request.server_log);
    if ( ftp_request.nlst ) free_string_list(ftp_request.nlst);
    if ( ftp_request.container ) free_container(ftp_request.container);
    obj->readers = obj->writers = 0;
    obj->state = OBJ_READY;
    obj->times.date = obj->request_time = obj->response_time = global_sec_timer;
    obj->times.expires = obj->times.date + ftp_expire_value ;
    obj->flags |= ANSW_HAS_EXPIRES;
    obj->doc_type = FTP_DOC;
    obj->size = calculate_container_datalen(obj->container);
    obj->resident_size = calculate_resident_size(obj);
    increase_hash_size(obj->hash_back, obj->resident_size);
    obj->flags &= ~ANSW_NO_CACHE;	/* it can be cached if it is good (not dead */
}

int
recv_ftp_data(struct ftp_r *ftp_r)
{
int	client = ftp_r->client;
int	data = ftp_r->data;
struct	mem_obj *obj=ftp_r->obj;
char	buf[1024];
int	r, sa_len, read_size, pass=0;
struct  sockaddr_in sa;
struct	request	*rq = ftp_r->request;
char	*mime_type;

    my_xlog(LOG_FTP, "receiving data\n");
    ftp_r->file_dir = FTP_TYPE_FILE;
    if ( !ftp_r->size || (ftp_r->size >= maxresident) )
    		SET(obj->flags, FLAG_DEAD);
    if ( ftp_r->mode == MODE_PORT ) {
	sa_len = sizeof(sa);
	r = -1;
	if ( wait_for_read(data, 10*1000) )
	    r = accept(data, (struct sockaddr*)&sa, &sa_len);
	close(data); ftp_r->data = -1;
	if ( r < 0 ) return(r);
	data = ftp_r->data = r;
    }
    mime_type = lookup_mime_type(ftp_r->obj->url.path);
    ftp_r->type = mime_type;
    if ( !obj->container ) {
	obj->container = alloc_buff(CHUNK_SIZE);
        if ( ! obj->container )
	   return(-1);
	obj->hot_buff = obj->container;
    } else {
	my_xlog(LOG_FTP, "something wrong rcv_ftp_list: container already allocated\n");
	return(-1);
    }
    r = send_http_header(client, mime_type, ftp_r->size, ftp_r->obj);
    if ( r < 0 ) return(r);
    ftp_r->received = 0;
    read_size = (TEST(rq->flags, RQ_HAS_BANDWIDTH))?(MIN(512,(sizeof(buf)-1))):
		(sizeof(buf)-1);
    if (TEST(rq->flags, RQ_HAS_BANDWIDTH)) my_xlog(LOG_FTP, "Slow down request\n");
    while((r = readt(data, buf, read_size, READ_ANSW_TIMEOUT)) > 0) {
	ftp_r->received += r;
	buf[r] = 0;
	if (TEST(rq->flags, RQ_HAS_BANDWIDTH) && ((++pass)%2) ) SLOWDOWN ;
	if ( writet(client, buf, r, READ_ANSW_TIMEOUT) < 0 ) {
	    my_xlog(LOG_FTP, "Ftp aborted\n");
	    return(-1);
	}
	if (TEST(rq->flags, RQ_HAS_BANDWIDTH)) update_transfer_rate(rq, r);
	if ( obj && !TEST(obj->flags, FLAG_DEAD) )
		store_in_chain(buf, r, obj);
    }
    my_xlog(LOG_FTP, "Data connection closed\n");
    return(0);
}


int
recv_ftp_nlst(struct ftp_r *req)
{
char			buf[160];
int			r, received = 0, sa_len, checked, r_code;
int			data = req->data;
char			*tmpbuf = NULL;
struct  sockaddr_in 	sa;
struct	buff		*nlst_buff = NULL;
struct	buff		*resp_buff = NULL;
int			server_so = req->control;
char			answer[ANSW_SIZE+1];
time_t			started;

    my_xlog(LOG_FTP, "receiving nlst\n");

    if ( req->mode == MODE_PORT ) {
	sa_len = sizeof(sa);
	r = -1;
	if ( wait_for_read(data, 10*1000) )
	    r = accept(data, (struct sockaddr*)&sa, &sa_len);
        close(data); req->data = -1;
	if ( r < 0 ) return(r);
	data = req->data = r;
    }
    nlst_buff = alloc_buff(CHUNK_SIZE);
    if ( !nlst_buff ) {
	close(data);req->data = -1;
	return(-1);
    }
    req->received = 0;
    while((r = readt(data, buf, sizeof(buf)-1, READ_ANSW_TIMEOUT)) > 0) {
	req->received += r;
	buf[r] = 0;
	attach_data(buf, r, nlst_buff);
	parse_answ(nlst_buff, &received, &add_nlst_entry, (void*)req);
    }
    if ( r < 0 ) my_xlog(LOG_FTP, "read list: %s\n", strerror(errno));
    my_xlog(LOG_FTP, "Data connection closed\n");
    resp_buff = alloc_buff(CHUNK_SIZE);
    checked = 0;
    r = -1;
    started = time(NULL);
    r=0;goto done;
read_srv:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( !r ) {
	my_xlog(LOG_FTP, "server closed connection too early in ftp_fill_mem\n");
	goto error;
    }
    if ( r == -2 ) {
	/* read timed put */
        if ( time(NULL) - started >= 10*60 ) {
	    /* it is completely timed out */
	    my_xlog(LOG_FTP, "timeout reading from server in ftp_fill_mem\n");
	    goto error;
        }
	goto read_srv;
    }
    if ( r < 0 ) {
	my_xlog(LOG_FTP, "error reading from server in ftp_fill_mem\n");
	goto error;
    }
    /* wait for for '2xx '	*/
    if ( attach_data(answer, r, resp_buff) ) {
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    if ( resp_buff ) while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, req)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at nlst\n");
	    r = -1;
	    goto error;
	}
	my_xlog(LOG_FTP, "server code: %d\n", r_code);
	r_code = r_code/100;
	if ( r_code == 2 )
	    {r = 0;  goto done;}
	if ( r_code == 3 )
	    {r = 0;  goto done;}
	if ( r_code >= 4 )
	    {r = -1; goto done;}
    }
    goto read_srv;
error:;
done:;
    if ( tmpbuf ) free(tmpbuf);
    if ( nlst_buff ) free_container(nlst_buff);
    if ( resp_buff ) free_chain(resp_buff);
    close(data);req->data = -1;
    return(r);
}


int
recv_ftp_list(struct ftp_r *req)
{
char	buf[160];
int	r, received = 0, sa_len, rc = 0;
int	client = req->client;
int	data = req->data;
struct	mem_obj *obj = req->obj;
char	*tmpbuf = NULL;
struct  sockaddr_in sa;

    my_xlog(LOG_FTP, "receiving list\n");

    req->file_dir = FTP_TYPE_DIR ;
    if ( req->mode == MODE_PORT ) {
	sa_len = sizeof(sa);
	r = -1;
	if ( wait_for_read(data, 10*1000) )
	    r = accept(data, (struct sockaddr*)&sa, &sa_len);
        close(data); req->data = -1;
	if ( r < 0 ) return(r);
	data = req->data = r;
    }
    if ( !obj->container ) {
	obj->container = alloc_buff(CHUNK_SIZE);
        if ( ! obj->container )
            return(-1);
	obj->hot_buff = obj->container;
    } else {
	my_log("something wrong rcv_ftp_list: container already allocated\n");
	return(-1);
    }
    r = send_http_header(client, "text/html", 0, req->obj);
    if ( r < 0 ) return(r);
    sendstr(client, "<html><head><title>ftp LIST</title>\n");
    store_in_chain("<html><head><title>ftp LIST</title>\n",
    	    strlen("<html><head><title>ftp LIST</title>\n"), req->obj);
    tmpbuf = xmalloc(strlen((req->obj->url).proto)+
		strlen((req->obj->url).host)+
		strlen((req->obj->url).path)+ 256, "recv_ftp_list");
    if ( tmpbuf ) {
	sprintf(tmpbuf, "<base href=\"%s://%s%s\">", req->obj->url.proto,
		req->obj->url.host,
		req->obj->url.path);
	sendstr(client, tmpbuf);
	store_in_chain(tmpbuf, strlen(tmpbuf), req->obj);
    }
    sendstr(client, "</head><body><pre>\n");
    store_in_chain("</head><body><pre>\n", strlen("</head><body><pre>\n"), req->obj);
    req->received = 0;
    while((r = readt(data, buf, sizeof(buf)-1, READ_ANSW_TIMEOUT)) > 0) {
	req->received += r;
	buf[r] = 0;
	attach_data(buf, r, req->container);
	parse_answ(req->container, &received, &list_parser, (void*)req);
    }
    if ( r < 0 ) {
	my_xlog(LOG_FTP, "read list: %s\n", strerror(errno));
	rc = -1;
    }
    if ( writet(client, "</body>", strlen("</body>"), READ_ANSW_TIMEOUT) < 0 )
	rc = -1;
    store_in_chain("</body>", strlen("</body>"), req->obj);
    my_xlog(LOG_FTP, "Data connection closed\n");
    if ( tmpbuf ) free(tmpbuf);
    return(rc);
}

int
parse_answ(struct buff *b, int *checked, int (*f)(char *, void*), void *arg)
{
char	*start, *beg, *end, *p;
char	holder;

    if ( !b || !b->data )
	return(-1);
    beg = b->data;
    end = b->data + b->used;
go:
    start = beg+*checked;
    if ( !*checked ) {
	p = memchr(beg, '\r', end-beg);
	holder = '\r';
	if ( !p ) {
	    p = memchr(beg, '\n', end-beg);
	    holder = '\n';
	}
	if ( !p ) return(0);
	*p = 0;
	*checked = strlen(start);
	/* start point to beg of server line */
	/*my_log("answer:<---'%s'\n", start);*/
	(*f)(start, arg);
        *p = holder;
	goto go;
    }
    p = start;
    while( (p < end) && ( *p == '\r' || *p == '\n' ) ) p++;
    if ( (p < end) && *p ) {
	char *t = memchr(p, '\r', end-p);
	holder = '\r';
	if ( !t ) {
	    t = memchr(p, '\n', end-p);
	    holder = '\n';
	}
	if ( !t ) return(0);
	*t = 0;
/*	my_log("answer:<---'%s'\n", p);*/
	(*f)(p, arg);
	*t = holder;
	*checked = t - beg;
	goto go;
    }
    return(0);
}

/* buld http_header in mem (so it can be saved on disk)
   and send it to user */
int
send_http_header(int so, char* type, int size, struct mem_obj *obj)
{
int	r;
char	b[50];
char	*fmt;
struct	buff	*nextb;

    r=writet(so, "HTTP/1.0 200 Ftp Gateway\r\n", strlen("HTTP/1.0 200 Ftp Gateway\r\n"), READ_ANSW_TIMEOUT);
    if ( obj ) {
	put_av_pair(&obj->headers, "HTTP/1.0","200 Ftp Gateway");
	fmt = format_av_pair("HTTP/1.0","200 Ftp Gateway");
	attach_data(fmt, strlen(fmt), obj->container);
	xfree(fmt);
    }
    if ( r >= 0 )
    r=writet(so, "Content-Type: ", strlen("Content-Type: "), READ_ANSW_TIMEOUT);
    if ( r >= 0 )
    r=writet(so, type, strlen(type), READ_ANSW_TIMEOUT);
    if ( r >= 0 ) r=writet(so, CRLF, 2, READ_ANSW_TIMEOUT);
    if ( obj ) {
	put_av_pair(&obj->headers, "Content-Type:", type);
	fmt = format_av_pair("Content-Type:", type);
	attach_data(fmt, strlen(fmt), obj->container);
	xfree(fmt);
    }
    if ( (r >= 0) && size ) {
	sprintf(b, "Content-Length: %d\r\n", size);
	r=writet(so, b, strlen(b), READ_ANSW_TIMEOUT);
	if ( obj ) {
	    put_av_pair(&obj->headers, b, "");
	    attach_data(b, strlen(b), obj->container);
	}
    }
    mk1123time(global_sec_timer + ftp_expire_value, b, sizeof(b));
    if ( r >= 0 )
    r=writet(so, "Expires: ", strlen("Expires: "), READ_ANSW_TIMEOUT);
    if ( r >= 0 )
    r=writet(so, b, strlen(b), READ_ANSW_TIMEOUT);
    if ( r >= 0 )
    r=writet(so, CRLF, 2, READ_ANSW_TIMEOUT);
    if ( obj ) {
	put_av_pair(&obj->headers, "Expires:", b);
	fmt = format_av_pair("Expires:", b);
	attach_data(fmt, strlen(fmt), obj->container);
	xfree(fmt);
	mk1123time(global_sec_timer, b, sizeof(b));
	put_av_pair(&obj->headers, "Date:", b);
	fmt = format_av_pair("Date:", b);
	attach_data(fmt, strlen(fmt), obj->container);
	xfree(fmt);
    }
    if ( r >= 0 )
    r=writet(so, "Via: oops\r\n", strlen("Via: oops\r\n"), READ_ANSW_TIMEOUT);
    if ( obj ) {
	put_av_pair(&obj->headers, "Via:", "oops");
	fmt = format_av_pair("Via:", "oops");
	attach_data(fmt, strlen(fmt), obj->container);
	xfree(fmt);
    }
    if ( r >= 0 )
    r=writet(so, CRLF, 2, READ_ANSW_TIMEOUT);
    if ( obj ) {
	fmt = format_av_pair("", NULL);
	attach_data(fmt, strlen(fmt), obj->container);
	xfree(fmt);
	if ( obj->hot_buff->used > 4 ) {
	    obj->insertion_point = obj->hot_buff->used - 4;
	    obj->tail_length = 4;
	}
    }
    nextb = alloc_buff(CHUNK_SIZE);
    if ( nextb ) {
	obj->container->next = nextb;
	obj->hot_buff = nextb;
    }
    return(r);
}

int
add_nlst_entry(char* line, void* arg)
{
struct	ftp_r	*req = (struct ftp_r*) arg;

    add_to_string_list(&req->nlst, line);
    return(0);
}

int
list_parser(char* line, void *arg)
{
struct	ftp_r	*req = (struct ftp_r*) arg;
int		so;
struct	mem_obj *obj;
struct	url	*url;
enum	{
	PLAIN,
	DIR,
	LINK,
	UNKNOWN
} type;
char	*icons[] = {
	"binary.gif",
	"dir.gif",
	"link.gif",
	"unknown.gif"
};
char	*alts[] = {
	"[File] ",
	"[Dir ] ",
	"[Link] ",
	"[Unkn] "
};
char	*p = line, *tok_ptr, *t;
int	tok_cnt = 0, dovesok;
char	*tempbuf = NULL;
char	*htmlized_path = NULL;
char	*htmlized_file = NULL;
char	*htmlized_something = NULL;
char	myhostname[MAXHOSTNAMELEN];
/* if not in nlst, then assumed line is something like that:
drwxr-xr-x   2 ms    ms          512 Jul 28 09:52 usr
-rw-r--r--   1 ms    ms        19739 Jan 17  1997 www.FAQ.alt
lrwxrwxrwx   1 root  wheel         7 May  2  1997 www.FAQ.koi8 -> www.FAQ
*/

    if ( !req ) {
	my_log("fatal: req==NULL in list parser\n");
	return(-1);
    }
    so = req->client;
    if ( !(obj = req->obj) ) {
	my_log("fatal: obj==NULL in list parser\n");
	return(-1);
    }
    url= &obj->url;
    if ( !strlen(url->path) ) {
	my_log("fatal: path=="" in list parser\n");
	return(-1);
    }
    /* move to first non-space	*/
    while( *p && isspace(*p) ) p++;
    /* well, now we can find is it dir, link or plain file	*/
    if ( !*p ) return(0);

    myhostname[0] = 0;
    gethostname(myhostname, sizeof(myhostname)-1);
    /* allocate space to hold all components */
    dovesok = 128;
    if ( req->request->url.login ) {
	dovesok += strlen(req->request->url.login);
    }
    if ( req->request->url.password ) {
	dovesok += strlen(req->request->url.password);
    }
    tempbuf = xmalloc(strlen(line)*3 + strlen(myhostname) + dovesok , "list_parser1");
    if ( !tempbuf ) {
	my_log("No space for tembuf\n");
	return(0);
    }
    switch (tolower(*p)) {
	case '-':	type = PLAIN; 	break;
	case 'd':	type = DIR; 	break;
	case 'l':	type = LINK; 	break;
	default:	type = UNKNOWN; break;
    }
    if ( (t = in_nlst(p, req->nlst)) ) {
	if ( (t > p) && ( t<=p+strlen(p) ) ) *(t-1)=0;
	htmlized_something = html_escaping(p);
	sprintf(tempbuf, "<img src=\"http://%s:%s/%s/%s\" alt=\"%s\">%s ",
	    		      icons_host[0]?icons_host:myhostname,
	    		      icons_port[0]?icons_port:"80",
			      icons_path[0]?icons_path:"icons",
	    		      icons[type],
	    		      alts[type],
	    		      htmlized_something);
	writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	store_in_chain(tempbuf, strlen(tempbuf), obj);
	htmlized_path = htmlize((url->path)+1);
	htmlized_file = htmlize(t);
	if ( req->request->url.login && req->request->url.password) {
	    sprintf(tempbuf, "<a href=\"%s://%s:%s@%s/%s%s%s\">%s</a> ",
			url->proto,
			req->request->url.login,req->request->url.password,
			url->host,htmlized_path,
			url->path[strlen(url->path)-1]=='/'?"":"/",
			htmlized_file, t);
	} else {
	    sprintf(tempbuf, "<a href=\"%s://%s/%s%s%s\">%s</a> ",
			url->proto,url->host,htmlized_path,
			url->path[strlen(url->path)-1]=='/'?"":"/",
			htmlized_file, t);
	}
	writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	store_in_chain(tempbuf, strlen(tempbuf), obj);
	
	goto fin_line;
    }
    t = p;
    while( ( p = (char*)strtok_r(t, " \t", &tok_ptr) ) ) {
	t = NULL;
	switch (tok_cnt) {
	case 0:
	    /* type */
	    sprintf(tempbuf, "<img src=\"http://%s:%s/%s/%s\" alt=\"%s\">%s ",
	    		      icons_host[0]?icons_host:myhostname,
	    		      icons_port[0]?icons_port:"80",
			      icons_path[0]?icons_path:"icons",
	    		      icons[type],
	    		      alts[type],
	    		      p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	case 1:
	case 2:
	case 3:
	    sprintf(tempbuf, "%4s ",p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	case 4:
	    /* this happens if ls give no links number in output */
	    if ( strlen(p) == 3 ) {
		if (!strcasecmp(p,"jan") || !strcasecmp(p,"feb") ||
		    !strcasecmp(p,"mar") || !strcasecmp(p,"apr") ||
		    !strcasecmp(p,"may") || !strcasecmp(p,"jun") ||
		    !strcasecmp(p,"jul") || !strcasecmp(p,"aug") ||
		    !strcasecmp(p,"sep") || !strcasecmp(p,"oct") ||
		    !strcasecmp(p,"nov") || !strcasecmp(p,"dec")
		) tok_cnt++;
	    }
	case 7:
	    sprintf(tempbuf, "%5s ",p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	case 5:
	case 6:
	    sprintf(tempbuf, "%3.3s ",p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	case 8:	/* file name */
	    htmlized_path = htmlize((url->path)+1);
	    htmlized_file = htmlize(p);
	    if ( req->request->url.login && req->request->url.password) {
	        sprintf(tempbuf, "<a href=\"%s://%s:%s@%s/%s%s%s\">%s</a> ",
			url->proto,
			req->request->url.login,req->request->url.password,
			url->host,htmlized_path,
			url->path[strlen(url->path)-1]=='/'?"":"/",
			htmlized_file, p);
	    } else {
	        sprintf(tempbuf, "<a href=\"%s://%s/%s%s%s\">%s</a> ",
			url->proto,url->host,htmlized_path,
			url->path[strlen(url->path)-1]=='/'?"":"/",
			htmlized_file, p);
	    }
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	case 9:
	    sprintf(tempbuf, "%s ",p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	default:
	    sprintf(tempbuf, "%s ",p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	}
    }
fin_line:;
    writet(so, "\n", 1, READ_ANSW_TIMEOUT);
    store_in_chain("\n", 1, obj);
    if ( tempbuf ) free(tempbuf);
    if ( htmlized_path ) free(htmlized_path);
    if ( htmlized_file ) free(htmlized_file);
    if ( htmlized_something ) free(htmlized_something);
    return(0);
}


int
server_connect(struct ftp_r *rq)
{
int			server_so = -1, so = rq->client, r;
struct	url		*url = &rq->obj->url;
struct	sockaddr_in	server_sa;

    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	say_bad_request(so, "Can't create socket", strerror(errno), ERR_INTERNAL, rq->request);
	goto error;
    }
    if ( str_to_sa(url->host, (struct sockaddr*)&server_sa) ) {
	say_bad_request(so, "Can't translate name to address", url->host, ERR_DNS_ERR, rq->request);
	goto error;
    }
    server_sa.sin_port = htons(url->port);
    my_xlog(LOG_FTP, "Connecting %s for '%s'\n", url->host, url->path);
    r = connect(server_so, (struct sockaddr*)&server_sa, sizeof(server_sa));
    if ( r == -1 ) {
	say_bad_request(so, "Can't connect", strerror(errno), ERR_TRANSFER, rq->request);
	goto error;
    }

    return(server_so);
error:
    if ( server_so != -1) close(server_so);
    return(-1);
}

int
get_server_greeting(struct ftp_r *ftp_r)
{
int		r, checked, r_code;
int		server_so = ftp_r->control;
char		answer[ANSW_SIZE+1];
time_t		started = time(NULL);
struct	buff	*resp_buff=NULL;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

read_srv:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( !r ) {
	my_xlog(LOG_FTP, "server closed connection too early in ftp_fill_mem\n");
	goto error;
    }
    if ( r == -2 ) {
	/* read timed put */
        if ( time(NULL) - started >= 10*60 ) {
	    /* it is completely timed out */
	    my_xlog(LOG_FTP, "timeout reading from server in ftp_fill_mem\n");
	    goto error;
        }
	goto read_srv;
    }
    if ( r < 0 ) {
	my_xlog(LOG_FTP, "error reading from server in ftp_fill_mem\n");
	goto error;
    }
    /* wait for for '220 '	*/
    if ( attach_data(answer, r, resp_buff) ) {
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at ftp_fill_mem\n");
	    goto error;
	}
	r_code = r_code/100;
    	if ( r_code >= 4 ) {
	    my_xlog(LOG_FTP, "server refused connection at ftp_fill_mem\n");
	    goto error;
	}
	if ( r_code == 2 )
	    goto done;
    }
    goto read_srv;
done:
    if ( resp_buff ) free_chain(resp_buff);
    return(r);
error:
    if ( resp_buff ) free_chain(resp_buff);
    return(-1);
}

int
send_user_pass_type(struct ftp_r *ftp_r)
{
int		r, checked, r_code;
int		server_so = ftp_r->control;
char		answer[ANSW_SIZE+1];
time_t		started = time(NULL);
struct	buff	*resp_buff=NULL;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    if ( ftp_r->request->url.login ) {
	r = writet(server_so, "USER ", 5, READ_ANSW_TIMEOUT);
	r = writet(server_so, ftp_r->request->url.login, strlen(ftp_r->request->url.login), READ_ANSW_TIMEOUT);
	r = writet(server_so, "\r\n", 2, READ_ANSW_TIMEOUT);
    } else {
	my_xlog(LOG_FTP, "ftp_srv --->'%s'\n", "USER anonymous");
	r = writet(server_so, "USER anonymous\r\n", 16, READ_ANSW_TIMEOUT);
    }
    if ( r < 0 ) {
	my_xlog(LOG_FTP, "error at 'USER anonymous' in ftp_fill_mem\n");
	goto error;
    }
wait_user_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_log("no server answer after USER in ftp_fill_mem\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at ftp_fill_mem\n");
	    goto error;
	}
	my_xlog(LOG_FTP, "server code: %d\n", r_code);
	r_code = r_code/100;
	if ( r_code == 2 )
	    goto send_type;
	if ( r_code == 3 )
	    goto send_pass;
	if ( r_code >= 4 )
	    goto error;
    }
    goto wait_user_ok;
send_pass:
    /* can clear prev. results */
    resp_buff->used = 0;
    started = time(NULL);
    checked = 0;
    if ( ftp_r->request->url.password ) {
	r = writet(server_so, "PASS ", 5, READ_ANSW_TIMEOUT);
	r = writet(server_so, ftp_r->request->url.password, strlen(ftp_r->request->url.password), READ_ANSW_TIMEOUT);
	r = writet(server_so, "\r\n", 2, READ_ANSW_TIMEOUT);
    } else {
	my_xlog(LOG_FTP, "ftp_srv --->PASS oops@\n");
	r = writet(server_so, "PASS oops@\r\n", strlen("PASS oops@\r\n"), READ_ANSW_TIMEOUT);
    }
    if ( r < 0 ) {
	my_xlog(LOG_FTP, "error at 'USER anonymous' in ftp_fill_mem: %s\n", strerror(errno));
	goto error;
    }
wait_pass_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(LOG_FTP, "no server answer after PASS in ftp_fill_mem\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at ftp_fill_mem\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 2 )
	    goto send_type;
	if ( r_code >= 3 )
	    goto error;
    }
    goto wait_pass_ok;
    
send_type:
    /* can clear prev. results */
    resp_buff->used = 0;
    started = time(NULL);
    checked = 0;
    my_xlog(LOG_FTP, "ftp_srv: --->TYPE I\n");
    r = writet(server_so, "TYPE I\r\n", 8, READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_log("error at 'TYPE I' in ftp_fill_mem\n");
	goto error;
    }
wait_type_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_log("no server answer after PASS in ftp_fill_mem\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at ftp_fill_mem\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 2 )
	    goto done;
	if ( r_code >= 3 )
	    goto error;
    }
    goto wait_type_ok;

done:
    if ( resp_buff ) free_chain(resp_buff);
    return(r);
error:
    if ( resp_buff ) free_chain(resp_buff);
    return(-1);
}

int
try_passive(struct ftp_r *ftp_r)
{
int		r, checked, r_code, data_so = -1;
int		server_so = ftp_r->control;
char		answer[ANSW_SIZE+1], *p;
time_t		started = time(NULL);
struct	buff	*resp_buff=NULL;
u_int		i[6], j;
u_int		pasv_addr;
u_short		pasv_port = 0;
struct	sockaddr_in	pasv_sa;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

		/* <<<	TRYING PASSIVE MODE  >>> */
		/* _____________________________ */

    my_xlog(LOG_FTP, "ftp_srv: --->PASV\n");
    r = writet(server_so, "PASV\r\n", 6, READ_ANSW_TIMEOUT);
    if ( r < 0) {
	my_xlog(LOG_FTP, "error sending PASV\n");
	goto error;
    }

wpasv:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(LOG_FTP, "no server answer after PASS in ftp_fill_mem\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at ftp_fill_mem\n");
	    goto error;
	}
	if ( r_code == 226 ) {
	    checked+=3;
	    continue;
	}
	r_code = r_code/100;
	if ( r_code == 2 )
	    goto use_pasv;
	if ( r_code >= 3 )
	    goto error;
    }
    goto wpasv;
use_pasv:
    /* retrive info about server pasive port */
    p = memchr(resp_buff->data, '(', resp_buff->used);
    if ( !p || !*++p) {
	my_log("Unrecognized format of PASV answer\n");
	goto error;
    }
    for(j=0;j<6;j++) {
	i[j] = atoi(p);
	while(*p && isdigit(*p) ) p++;
	if ( j < 5 )
	if ( (*p != ',') || !*++p ) {
	    my_log("Unrecognized format of PASV answer\n");
	    goto error;
        }
    }
    pasv_addr = (i[0]<<24) | (i[1]<<16) | (i[2]<<8) | i[3];
    pasv_port = (i[4]<<8)  |  i[5];
    data_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	my_log("can't create socket: %s\n", strerror(errno));
	goto error;
    }
    pasv_sa.sin_family = AF_INET;
    pasv_sa.sin_addr.s_addr = htonl(pasv_addr);
    pasv_sa.sin_port        = htons(pasv_port);
    r = connect(data_so, (struct sockaddr*)&pasv_sa, sizeof(pasv_sa));
    if ( r < 0 ) {
	my_xlog(LOG_FTP, "ftp: pasv connect: %s\n", strerror(errno));
	goto error;
    }
    ftp_r->data = data_so;
    if ( resp_buff ) free_chain(resp_buff);
    return(r);
error:
    if ( data_so != -1 ) close(data_so);
    if ( resp_buff ) free_chain(resp_buff);
    return(-1);
}

int
try_port(struct ftp_r *ftp_r)
{
int			r, checked, r_code, data_so = -1;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1], *p;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;
struct	sockaddr_in	my_data_sa;
int			my_data_sa_len;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;
		/* <<<  TRYING PORT MODE  >>> */
		/* __________________________ */
    data_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	my_log("can't create socket: %s\n", strerror(errno));
	goto error;
    }
    my_data_sa_len = sizeof(my_data_sa);
    r = getsockname(server_so, (struct sockaddr*)&my_data_sa, &my_data_sa_len);
    if ( r == -1 ) {
	my_log("can't getsockname: %s\n", strerror(errno));
	goto error;
    }
    my_data_sa.sin_port = 0;
    r = bind(data_so, (struct sockaddr*)&my_data_sa, sizeof(my_data_sa));
    if ( r == -1 ) {
	my_log("can't bind for PORT: %s\n", strerror(errno));
	goto error;
    }
    r = getsockname(data_so, (struct sockaddr*)&my_data_sa, &my_data_sa_len);
    if ( r == -1 ) {
	my_log("can't do 2-nd getsockname: %s\n", strerror(errno));
	goto error;
    }
    /* this is dangerous, but solaris has no snprintf */
    sprintf(answer, "PORT %d,%d,%d,%d,%d,%d\r\n",
    	(unsigned)(ntohl(my_data_sa.sin_addr.s_addr) & 0xff000000) >> 24,
    	(unsigned)(ntohl(my_data_sa.sin_addr.s_addr) & 0x00ff0000) >> 16,
    	(unsigned)(ntohl(my_data_sa.sin_addr.s_addr) & 0x0000ff00) >> 8,
    	(unsigned)(ntohl(my_data_sa.sin_addr.s_addr) & 0x000000ff) ,
    	(unsigned)(ntohs(my_data_sa.sin_port) & 0xff00) >> 8 ,
    	(unsigned)(ntohs(my_data_sa.sin_port) & 0x00ff));
    r = writet(server_so, answer, strlen(answer), READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_log("error sending PORT: %s\n", strerror(errno));
	goto error;
    }
    p = strchr(answer, '\n'); *p = 0; my_xlog(LOG_FTP, "ftp_srv: --->'%s'\n", answer);
    resp_buff->used = 0;
    started = time(NULL);
    checked = 0;
w_port_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_log("no server answer after PORT in ftp_fill_mem\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at ftp_fill_mem\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 2 )
	    goto prep_data_so;
	if ( r_code >= 3 )
	    goto error;
    }
    goto w_port_ok;
prep_data_so:
    r = listen(data_so, 5);
    if ( r < 0 ) {
	my_log("Can't accept: %d\n", strerror(errno));
	goto error;
    }

    ftp_r->data = data_so;
    if ( resp_buff ) free_chain(resp_buff);
    return(0);
error:
    if ( data_so != -1 ) close(data_so);
    if ( resp_buff ) free_chain(resp_buff);
    return(-1);
}

int
try_size(struct ftp_r *ftp_r)
{
int			r, checked, r_code;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1];
char			*rq_buff = NULL, *c, *sn;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;
struct	mem_obj		*obj = ftp_r->obj;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    rq_buff=xmalloc(strlen(ftp_r->dehtml_path)+strlen("SIZE \r\n")+1,"rq_buff");
    if ( !rq_buff ) {
	SET(obj->flags, FLAG_DEAD);
	my_log("Can't alloc mem\n");
	goto error;
    }
    sprintf(rq_buff, "SIZE %s\r\n", ftp_r->dehtml_path);
    my_xlog(LOG_FTP, "ftp_srv: %s", rq_buff);

    r = writet(server_so, rq_buff, strlen(rq_buff), READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	SET(obj->flags, FLAG_DEAD);
	my_xlog(LOG_FTP, "error sending SIZE in ftp_fill_mem\n");
	goto error;
    }
w_retr_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	SET(obj->flags, FLAG_DEAD);
	my_log("no server answer after SIZE in ftp_fill_mem\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	SET(obj->flags, FLAG_DEAD);
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at ftp_fill_mem\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto retrieve_size;
	if ( r_code == 2 )
	    goto retrieve_size;
	if ( r_code >= 3 ) {
	    goto error;
	}
    }
    goto w_retr_ok;
retrieve_size:
    /* stand at the end of answer */
    c = resp_buff->data + checked ;
    sn = strchr(c, '\n');
    if ( !sn ) sn = strchr(c, '\r');
    if ( (sn > resp_buff->data) && (sn < resp_buff->data + resp_buff->used) )
	*sn = 0;
    else
	goto error;

    c+=3;while(*c && isspace(*c) ) c++;
    ftp_r->size = atoi(c);
    my_xlog(LOG_FTP, "SIZE: %d\n", ftp_r->size);
    /* we will not store large files */
error:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(-1);
}
int
try_retr(struct ftp_r *ftp_r)
{
int			r, checked, r_code;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1];
char			*rq_buff = NULL;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    rq_buff=xmalloc(strlen(ftp_r->dehtml_path)+strlen("RETR \r\n")+1,"rq_buff");
    if ( !rq_buff ) {
	my_log("Can't alloc mem\n");
	goto error;
    }
    sprintf(rq_buff, "RETR %s\r\n", ftp_r->dehtml_path);
    my_xlog(LOG_FTP, "ftp_srv: %s", rq_buff);
    r = writet(server_so, rq_buff, strlen(rq_buff), READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_log("error sending RETR in ftp_fill_mem\n");
	goto error;
    }
w_retr_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_log("no server answer after PORT in ftp_fill_mem\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at ftp_fill_mem\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto receive_data;
	if ( r_code == 2 )
	    goto receive_data;
	if ( r_code >= 3 )
	    goto error;
    }
    goto w_retr_ok;
receive_data:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(0);
error:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(-1);
}

int
try_cwd(struct ftp_r *ftp_r)
{
int			r, checked, r_code;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1];
char			*rq_buff = NULL;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    rq_buff=xmalloc(strlen(ftp_r->dehtml_path)+strlen("CWD \r\n")+1,"rq_buff");
    if ( !rq_buff ) {
	my_log("Can't alloc mem\n");
	goto error;
    }
    sprintf(rq_buff, "CWD %s\r\n", ftp_r->dehtml_path);
    my_xlog(LOG_FTP, "ftp_srv: %s", rq_buff);
    r = writet(server_so, rq_buff, strlen(rq_buff), READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_log("error sending RETR in ftp_fill_mem\n");
	goto error;
    }
w_cwd_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_log("no server answer after CWD in ftp_fill_mem\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at ftp_fill_mem\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto request_list;
	if ( r_code == 2 )
	    goto request_list;
	if ( r_code >= 3 )
	    goto error;
    }
    goto w_cwd_ok;

request_list:
    r = writet(server_so, "NLST -a\r\n", 9, READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_log("ftp_srv: error sending NLST\n", strerror(errno));
	goto error;
    }
    resp_buff->used = 0;
    started = time(NULL);
    checked = 0;
w_list_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_log("no server answer after PORT in ftp_fill_mem\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at ftp_fill_mem\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto receive_data;
	if ( r_code == 2 )
	    goto receive_data;
	if ( r_code >= 3 )
	    goto error;
    }
    goto w_list_ok;
receive_data:
    if ( resp_buff ) free_chain(resp_buff); if ( rq_buff ) free(rq_buff);
    return(0);
error:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(-1);
}

int
request_list(struct ftp_r *ftp_r)
{
int			r, checked, r_code;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1];
char			*rq_buff = NULL;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    r = writet(server_so, "LIST\r\n", 6, READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_log("ftp_srv: error sending LIST\n", strerror(errno));
	goto error;
    }
    resp_buff->used = 0;
    started = time(NULL);
    checked = 0;
w_list_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_log("no server answer after LIST in ftp_fill_mem\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_log("no space at ftp_fill_mem\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) ) {
	if ( r_code < 100 ) {
	    my_log("some fatal error at ftp_fill_mem\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto receive_data;
	if ( r_code == 2 )
	    goto receive_data;
	if ( r_code >= 3 )
	    goto error;
    }
    goto w_list_ok;
receive_data:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(0);
error:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(-1);
}

int
parse_ftp_srv_answ(struct buff *b, int *checked, struct ftp_r *ftp_r)
{
char	*start, *beg, *end, *p;
char	holder;
int	res=0;

    if ( !b || !b->data )
	return(-1);
    beg = b->data;
    end = b->data + b->used;
/*    if ( ftp_r->server_log )
	attach_data(b->data, b->used, ftp_r->server_log);
*/
go:
    start = beg+*checked;
    if ( !*checked ) {
	if ( (beg < end) && isspace(*beg) ) {
	    (*checked)++;
	    goto go;
	}
	p = memchr(beg, '\r', end-beg);
	holder = '\r';
	if ( !p ) {
	    p = memchr(beg, '\n', end-beg);
	    holder = '\n';
	}
	if ( !p ) return(0);
	if ( ftp_r->server_log )
		attach_data(start, p-start+1, ftp_r->server_log);
	*p = 0;
	*checked = strlen(start);
	/* start point to beg of server line */
	my_xlog(LOG_FTP, "ftp_srv1 <---'%s'\n", start);
        if ( (strlen(start) > 3) && (start[3] == ' ') ) {
	    res = atoi(start);
	    if ( res ) {
		*p = holder; *checked = start - beg;
		return(res);
	    }
        }
        *p = holder;
	goto go;
    }
    p = start;
    while( (p < end) && ( *p == '\r' || *p == '\n' ) ) p++;
    if ( p<end && *p ) {
	char *t = memchr(p, '\r', end-p);
	char *tt = memchr(p, '\n', end-p);
	holder = '\r';
	if ( tt && (tt < t) ) {
	    t = tt;
	    holder = '\n';
	}
	if ( !t ) return(0);
	if ( ftp_r->server_log )
		attach_data(start, t-start+1, ftp_r->server_log);
	*t = 0;
	my_xlog(LOG_FTP, "ftp_srv2 <---'%s'\n", p);
        if ( (strlen(p) > 3) &&
        	isdigit(p[0]) &&
        	isdigit(p[1]) &&
        	isdigit(p[2]) && (p[3] == ' ') ) {
	    res = atoi(start);
	    if ( res ) {
		*t = holder;
		*checked = start - beg;
		my_xlog(LOG_FTP, "returned %d\n", res);
		return(res);
	    }
	}	
	*t = holder;
	*checked = t - beg;
	goto go;
    }
    return(0);
}

void
send_ftp_err(struct ftp_r *ftp_r)
{
char	*err_header =
"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html><header>FTP error</header><body>Document can't be retrieved.<p>Server answers:<hr><p><pre>";
char	*epilog = "</body></html>";

    writet(ftp_r->client, err_header, strlen(err_header), READ_ANSW_TIMEOUT);
    ftp_r->server_log?writet(ftp_r->client,
    		ftp_r->server_log->data, ftp_r->server_log->used, READ_ANSW_TIMEOUT):
    	writet(ftp_r->client, "Undefined error\n", strlen("Undefined error\n"), READ_ANSW_TIMEOUT);
    writet(ftp_r->client, epilog, strlen(epilog), READ_ANSW_TIMEOUT);
}

char*
in_nlst(char *line, struct string_list *list)
{
char *t, *best = NULL, *most_right;
char *longest, *wb,*we, *start;
int   len, longest_len, most_right_len;
struct search_list *res = NULL, *curr;

    if ( list && list->string ) {
        longest = list->string;
	longest_len = 0;
	most_right = line;
    } else
	return(NULL);

    while(list) {
	start = line;
refind:
	if ( (t = strstr(start, list->string)) ) {
	    /*while( *t && (p = strstr(t+1, list->string)) ) t = p;*/
	    len = strlen(list->string);
	    wb = t; we = t+len;
	    if ( !isspace(*(t-1)) || (*we && !isspace(*we))) {
		goto sss;
	    }
	    if ( t > most_right ) {
		most_right = t;
		most_right_len = len;
	    }
	    add_to_search_list(&res, t, len);
sss:;
	    start = t+1; if ( *start ) goto refind;
	}
	list = list->next;
    }
    best = NULL;
    curr = res;
    while ( curr ) {
	if ( (curr->off <= most_right) &&
	     (curr->off + curr->len >= most_right+most_right_len) ) {
	    best = curr->off;
	    longest_len = curr->len;
	}
	curr = curr->next;
    } 
    if ( best ) {
	*(best + longest_len) = 0;
    }
    free_search_list(res);
    return(best);
}
