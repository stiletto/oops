#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<stdarg.h>
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

#include	<netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include "../oops.h"
#include "../modules.h"

char	module_type = MODULE_LOG;
char	module_info[] ="Dummy logging module";
char	module_name[] ="DummyLog";
int
mod_load()
{
    printf("Dummy logger started\n");
    return(MOD_CODE_OK);
}
int
mod_unload()
{
    printf("Dummy logging stopped\n");
    return(MOD_CODE_OK);
}
