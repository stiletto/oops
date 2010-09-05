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
char		cpath[MAXPATHLEN];
char		*command[20];

int
main(int argc, char **argv)
{
struct	sockaddr_un	sun_addr;
int			oopsctl_so;
char			answer[1024];
int			alen,i,first_arg = 1;
char 			cmdarg[1024];

    for (i=0; i< 20; i++) { *(i+command) = NULL;}
    *command = strdup("help");
    *(2 + command) = strdup("-c");
    sprintf(cmdarg,"%s/oops.cfg", OOPS_HOME);
    *(3 + command) = strdup(cmdarg);
    i = 4;
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
        } else if (!strncasecmp(*argv, "-c", 2)) {
            /* path to config file */
            if ( strlen(*argv) <= 2 ) {
                /* mustbe next argv */
                argv++;argc--;
		strncpy(cpath, *argv, sizeof(cpath));
	    } else
		strncpy(cpath, (*argv+2), sizeof(cpath));
            *(3 + command) = cpath;
	} else {
            if ( i < 19 ) {
 	      if ( first_arg ) {
		*command = *argv;
		first_arg = 0 ;
	      } else {
	        *(i+command) = *argv;
                i++;
	      }
            } else {
              printf("Too many argc !\n\n");
            }
	}
	argc--; argv++;
    }
    if ( !path[0] ) {
	strncpy(path, OOPS_HOME, sizeof(path));
	strncat(path, "/logs/oopsctl", sizeof(path)-strlen(path));
    }
    if ( !strcasecmp(*command, "help") ) {
	printf("oopsctl [-s pathtosocket] [command]\n");
	printf("Commands:\n");
	printf("help		- get help\n");
	printf("stat		- get stat\n");
	printf("htmlstat	- get stat in html format\n");
	printf("chkconfig	- check config file\n");
	printf("reconfigure	- re-read config file\n");
	printf("shutdown(stop)	- shutdown oops\n");
	printf("rotate		- rotate logs\n");
	printf("start		- start oops (same as %s/oops -c %s/oops.cfg)\n", OOPS_HOME,OOPS_HOME);
	exit(0);
    } else
    if ( !strcasecmp(*command, "start") ) {
	pid_t	child;
	char	cmdpath[1024];

	sprintf(cmdpath,"%s/oops", OOPS_HOME);
	*(1+command) = cmdpath;
        chdir(OOPS_HOME);
	child = fork();
	switch(child) {
	case(-1):
		printf("Can't start child: %s\n", strerror(errno));
		exit(1);
	case(0):
		i = 4;
		if (*(command + 4)) {
		 printf ("args: ");
		 while ( *(command + i) ) printf ("%s ",*(command + i++));
		 printf ("\n");
		}
		execv(cmdpath, command+1);
		printf("Can't execute: %s\n", strerror(errno));
	default:
		exit(0);
	}
    }
    if ( !strcasecmp(*command, "chkconfig") ) {
	char	cmdpath[1024], cmdarg[1024];

	sprintf(cmdpath,"%s/oops", OOPS_HOME);
	*(1+command) = cmdpath;
	execv(cmdpath, command+1);
	printf("Can't execute: %s\n", strerror(errno));
    }
    if ( !strcasecmp(*command,"stat") || 
	 !strcasecmp(*command,"htmlstat") ||
	 !strcasecmp(*command,"reconfigure") ||
	 !strcasecmp(*command,"rotate") ||
	 !strcasecmp(*command,"stop") ||
	 !strcasecmp(*command,"shutdown")
        ) {
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
     write(oopsctl_so, *command, strlen(*command));
     write(oopsctl_so, "\n", 1);
     fflush(stdout);
     while ( (alen = read(oopsctl_so, answer, sizeof(answer))) > 0 ) {
 	write(1, answer, alen);
     }
    } else printf("Unknown command %s\n", *command);
    exit(0);
}
