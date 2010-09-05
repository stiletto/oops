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

#define		NO_NEED_XMALLOC 1
#include	"../oops.h"

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
    sprintf(cmdarg,"%s", OOPS_CFG);
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
		strncpy(path, *argv, sizeof(path)-1);
	    } else
		strncpy(path, (*argv+2), sizeof(path));
	    path[sizeof(path)-1] = 0;
        } else if (!strncasecmp(*argv, "-c", 2)) {
            /* path to config file */
            if ( strlen(*argv) <= 2 ) {
                /* mustbe next argv */
                argv++;argc--;
		strncpy(cpath, *argv, sizeof(cpath)-1);
	    } else
		strncpy(cpath, (*argv+2), sizeof(cpath)-1);
	    cpath[sizeof(cpath)-1] = 0;
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
	strncpy(path, OOPS_LOCALSTATEDIR, sizeof(path)-1);
	strncat(path, "/oopsctl", sizeof(path)-strlen(path)-1);
	path[sizeof(path)-1] = 0;
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
	printf("verbosity=LVL	- set verbosity (like -x LVL)\n");
	printf("start		- start oops (same as %s/oops -c %s)\n", OOPS_SBINDIR,OOPS_CFG);
	exit(0);
    } else
    if ( !strcasecmp(*command, "start") ) {
	pid_t	child;
	char	cmdpath[1024];

	sprintf(cmdpath,"%s/oops", OOPS_SBINDIR);
	*(1+command) = cmdpath;
        chdir(OOPS_HOME);
	child = fork();
	switch(child) {
	case(-1):
		printf("oopsctl: Can't start child: %s\n", strerror(ERRNO));
		exit(1);
	case(0):
		i = 4;
		if (*(command + 4)) {
		 printf ("args: ");
		 while ( *(command + i) ) printf ("%s ",*(command + i++));
		 printf ("\n");
		}
		execv(cmdpath, command+1);
		printf("oopsctl: Can't execute: %s\n", strerror(ERRNO));
	default:
		exit(0);
	}
    }
    if ( !strcasecmp(*command, "chkconfig") ) {
	char	cmdpath[1024], cmdarg[1024];
	sprintf(cmdpath,"%s/oops", OOPS_SBINDIR);
	sprintf(cmdarg, "-C%s", OOPS_CFG);
	*(1+command) = cmdpath;
	*(2+command) = cmdarg;
	execv(cmdpath, command+1);
	printf("oopsctl: Can't execute: %s\n", strerror(ERRNO));
    }
    if ( !strcasecmp(*command, "reconfigure") ) {
	char	cmdpath[1024], cmdarg[1024];
	pid_t	child;
	int	stat;

	/* first check if config is OK */
	sprintf(cmdpath,"%s/oops", OOPS_SBINDIR);
	sprintf(cmdarg, "-C%s", OOPS_CFG);
	*(1+command) = cmdpath;
	*(2+command) = cmdarg;
	child = fork();
	switch (child) {
	case -1:
		printf("oopsctl: Can't start child: %s\n", strerror(ERRNO));
		exit(1);
	case 0:
		execv(cmdpath, command+1);
		printf("oopsctl: Can't execute: %s\n", strerror(ERRNO));
	default:
		/* wait for child */
		waitpid((pid_t)-1, &stat, 0);
		if ( WIFEXITED(stat) && !WEXITSTATUS(stat) ) { /* ok */
		    *(1+command) = NULL;
		    goto srv_conn;
		}
		printf("oopsctl: Check config failed: exitcode: %d\n", WEXITSTATUS(stat));
		exit(1);
	}
    }
    if ( !strcasecmp(*command,"stat") || 
	 !strcasecmp(*command,"htmlstat") ||
	 !strcasecmp(*command,"reconfigure") ||
	 !strcasecmp(*command,"rotate") ||
	 !strcasecmp(*command,"stop") ||
	 !strncasecmp(*command,"verbosity=", 10) ||
	 !strncasecmp(*command,"requests", 8) ||
	 !strcasecmp(*command,"shutdown")
        ) {
srv_conn:
     /* connecting to server */
     oopsctl_so = socket(AF_UNIX, SOCK_STREAM, 0);
     if ( oopsctl_so == -1 ) {
	printf("oopsctl: socket(): %s\n", strerror(ERRNO));
	exit(1);
     }
     bzero(&sun_addr, sizeof(sun_addr));
     sun_addr.sun_family = AF_UNIX;
     strncpy(sun_addr.sun_path, path, sizeof(sun_addr.sun_path)-1);
     if ( connect(oopsctl_so, (struct sockaddr*)&sun_addr, sizeof(sun_addr)) ) {
 	printf("oopsctl: connect(): %s\n", strerror(ERRNO));
	exit(1);
     }
     write(oopsctl_so, *command, strlen(*command));
     write(oopsctl_so, "\n", 1);
     fflush(stdout);
     while ( (alen = read(oopsctl_so, answer, sizeof(answer))) > 0 ) {
 	write(1, answer, alen);
     }
    } else printf("oopsctl: Unknown command %s\n", *command);
    exit(0);
}
