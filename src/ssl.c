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

#include	"oops.h"

void
send_ssl(int so, struct request *rq)
{
int			server_so = -1, r;
struct	sockaddr_in	server_sa;
char			*ce = "HTTP/1.0 200 Connection established\r\n\r\n";
int			celen = strlen(ce);
struct	url		*url = &rq->url;
struct	pollarg		pollarg[2];
int			received = 0, delta_tv;
struct	timeval		start_tv, stop_tv;
ERRBUF ;

    my_xlog(LOG_DBG, "send_ssl(): Connecting %s:%d\n", rq->url.host, rq->url.port);
    gettimeofday(&start_tv, NULL);
    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	say_bad_request(so, "Can't create socket", STRERROR_R(ERRNO, ERRBUFS),
			ERR_INTERNAL, rq);
	goto done;
    }
    if ( str_to_sa(url->host, (struct sockaddr*)&server_sa) ) {
	say_bad_request(so, "Can't translate name to address", url->host, ERR_DNS_ERR, rq);
	goto done;
    }
    server_sa.sin_port = htons(url->port);
    my_xlog(LOG_DBG, "send_ssl(): Connecting %s:%d\n", url->host, url->port);
    r = connect(server_so, (struct sockaddr*)&server_sa, sizeof(server_sa));
    if ( r == -1 ) {
	say_bad_request(so, "Can't connect", STRERROR_R(ERRNO, ERRBUFS),
			ERR_TRANSFER, rq);
	goto done;
    }
    if ( fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK) )
	my_xlog(LOG_SEVERE, "send_ssl(): fcntl(): %m\n");
    if ( fcntl(server_so, F_SETFL, fcntl(server_so, F_GETFL, 0)|O_NONBLOCK) )
	my_xlog(LOG_SEVERE, "send_ssl(): fcntl(): %m\n");

    r = writet(so, ce, celen, READ_ANSW_TIMEOUT);
    if ( r < 0 ) goto done;
    forever() {
    sel_again:
	pollarg[0].fd = server_so;
	pollarg[1].fd = so;
	pollarg[0].request = FD_POLL_RD;
	pollarg[1].request = FD_POLL_RD;
	r = poll_descriptors(2, &pollarg[0], READ_ANSW_TIMEOUT*1000);
	if ( r <= 0) {
	    goto done;
	}
	if ( IS_HUPED(&pollarg[0]) || IS_HUPED(&pollarg[1]) )
	    goto done;
	if ( IS_READABLE(&pollarg[0]) ) {
	    char b[1024];
	    /* read from server */
	    r = read(server_so, b, sizeof(b));
	    if ( (r < 0) && (ERRNO == EAGAIN) )
		goto sel_again;
	    received += r;
	    if ( r <= 0 )
		goto done;
	    r = writet(so, b, r, READ_ANSW_TIMEOUT);
	    if ( r < 0 ) goto done;
	}
	if ( IS_READABLE(&pollarg[1]) ) {
	    char b[1024];
	    /* read from client */
	    r = read(so, b, sizeof(b));
	    if ( (r < 0) && (ERRNO == EAGAIN) )
		goto sel_again;
	    if ( r <= 0 )
		goto done;
	    r = writet(server_so, b, r, READ_ANSW_TIMEOUT);
	    if ( r < 0 ) goto done;
	}
    }
done:
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    if ( server_so != -1 ) CLOSE(server_so);
    rq->tag = strdup("TCP_MISS");
    rq->code = 555;
    rq->received = received;
    rq->hierarchy = strdup("DIRECT");
    rq->source = strdup(rq->url.host);
    log_access(delta_tv, rq, NULL);
    return;
}
