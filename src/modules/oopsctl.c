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
#include	<sys/un.h>

#include	<netinet/in.h>

#include	"../config.h"

char		path[MAXPATHLEN];
char		*command = "help";

int
main(int argc, char **argv)
{
struct	sockaddr_un	sun_addr;
int			oopsctl_so;
char			answer[1024];
int			alen;

    path[0] = 0;
    argc--;argv++;
    while ( argc && *argv) {
	if ( !strncasecmp(*argv, "-s", 2) ) {
	    /* path to socket */
	    if ( strlen(*argv) <= 2 ) {
		/* mustbe next argv */
		argv++;argc--;
		strncpy(path, *argv, sizeof(path));
	    } else
		strncpy(path, (*argv+2), sizeof(path));
	} else {
	    command = *argv;
	}
	argc--; argv++;
    }
    if ( !path[0] ) {
	strncpy(path, OOPS_HOME, sizeof(path));
	strncat(path, "/logs/oopsctl", sizeof(path)-strlen(path));
    }
    if ( !strcasecmp(command, "help") ) {
	printf("oopsctl [-s pathtosocket] [command]\n");
	printf("Commands:\n");
	printf("help		- get help\n");
	printf("stat		- get stat\n");
	printf("htmlstat	- get stat in html format\n");
	printf("chkconfig	- check config file\n");
	printf("reconfigure	- re-read config file\n");
	printf("shutdown	- shutdown oops\n");
	printf("start		- start oops (same as %s/oops -c %s/oops.cfg)\n", OOPS_HOME,OOPS_HOME);
	exit(0);
    } else
    if ( !strcasecmp(command, "start") ) {
	pid_t	child;
	char	cmdpath[1024], cmdname[5], cmdarg[1024];

	sprintf(cmdpath,"%s/oops", OOPS_HOME);
	sprintf(cmdarg,"%s/oops.cfg", OOPS_HOME);
	strcpy(cmdname, "oops");
        chdir(OOPS_HOME);
	child = fork();
	switch(child) {
	case(-1):
		printf("Can't start child: %s\n", strerror(errno));
		exit(1);
	case(0):
		execl(cmdpath, cmdname, "-c", cmdarg, NULL);
		printf("Can't execute: %s\n", strerror(errno));
	defailt:
		exit(0);
	}
    }
    if ( !strcasecmp(command, "chkconfig") ) {
	char	cmdpath[1024], cmdname[5], cmdarg[1024];

	sprintf(cmdpath,"%s/oops", OOPS_HOME);
	sprintf(cmdarg,"%s/oops.cfg", OOPS_HOME);
	strcpy(cmdname, "oops");
	execl(cmdpath, cmdname, "-C", cmdarg, NULL);
	printf("Can't execute: %s\n", strerror(errno));
    }
    /* connecting to server */
    oopsctl_so = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( oopsctl_so == -1 ) {
	printf("oopsctl:socket: %s\n", strerror(errno));
	exit(1);
    }
    bzero(&sun_addr, sizeof(sun_addr));
    sun_addr.sun_family = AF_UNIX;
    strncpy(sun_addr.sun_path, path, sizeof(sun_addr.sun_path)-1);
    if ( connect(oopsctl_so, (struct sockaddr*)&sun_addr, sizeof(sun_addr)) ) {
	printf("oopsctl:connect: %s\n", strerror(errno));
	exit(1);
    }
    write(oopsctl_so, command, strlen(command));
    write(oopsctl_so, "\n", 1);
    fflush(stdout);
    while ( (alen = read(oopsctl_so, answer, sizeof(answer))) > 0 ) {
	write(1, answer, alen);
    }
    exit(0);
}
