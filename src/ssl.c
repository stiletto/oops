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
#include	<time.h>

#include        <sys/param.h>
#include        <sys/socket.h>
#include        <sys/types.h>
#include        <sys/stat.h>
#include        <sys/file.h>
#include	<sys/time.h>

#include        <netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"

void
send_ssl(int so, struct request *rq)
{
int			server_so = -1, r;
struct	sockaddr_in	server_sa;
char			*ce = "HTTP/1.0 200 Connection established\r\n\r\n";
int			celen = sizeof("HTTP/1.0 200 Connection established\r\n\r\n");
struct	url		*url = &rq->url;
struct	pollarg		pollarg[2];

    my_log("CONNECTING %s:%d\n", rq->url.host, rq->url.port);
    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	say_bad_request(so, "Can't create socket", strerror(errno), ERR_INTERNAL, rq);
	goto done;
    }
    if ( str_to_sa(url->host, (struct sockaddr*)&server_sa) ) {
	say_bad_request(so, "Can't translate name to address", url->host, ERR_DNS_ERR, rq);
	goto done;
    }
    server_sa.sin_port = htons(url->port);
    my_log("Connecting %s:%d\n", url->host, url->port);
    r = connect(server_so, (struct sockaddr*)&server_sa, sizeof(server_sa));
    if ( r == -1 ) {
	say_bad_request(so, "Can't connect", strerror(errno), ERR_TRANSFER, rq);
	goto done;
    }
    if ( fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK) )
	my_log("fcntl: %s\n", strerror(errno));
    if ( fcntl(server_so, F_SETFL, fcntl(server_so, F_GETFL, 0)|O_NONBLOCK) )
	my_log("fcntl: %s\n", strerror(errno));

    r = writet(so, ce, celen, READ_ANSW_TIMEOUT);
    if ( r < 0 ) goto done;
    while(1) {
    sel_again:
	pollarg[0].fd = server_so;
	pollarg[1].fd = so;
	pollarg[0].request = FD_POLL_RD;
	pollarg[1].request = FD_POLL_RD;
	r = poll_descriptors(2, &pollarg[0], READ_ANSW_TIMEOUT*1000);
	if ( r <= 0) {
	    goto done;
	}
	if ( IS_READABLE(&pollarg[0]) ) {
	    char b[1024];
	    /* read from server */
	    r = read(server_so, b, sizeof(b));
	    if ( r < 0 && errno == EAGAIN )
		goto sel_again;
	    if ( r <= 0 )
		goto done;
	    r = writet(so, b, r, READ_ANSW_TIMEOUT);
	    if ( r < 0 ) goto done;
	}
	if ( IS_READABLE(&pollarg[1]) ) {
	    char b[1024];
	    /* read from client */
	    r = read(so, b, sizeof(b));
	    if ( r < 0 && errno == EAGAIN )
		goto sel_again;
	    if ( r <= 0 )
		goto done;
	    r = writet(server_so, b, r, READ_ANSW_TIMEOUT);
	    if ( r < 0 ) goto done;
	}
    }
done:
    if ( server_so != -1 ) close(server_so);
    return;
}
