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

#include "../oops.h"
#include "../modules.h"

#define	MODULE_INFO	"Dummy logging module"
#define	MODULE_NAME	"DummyLog"

#if	defined(MODULES)
char		module_type	= MODULE_LOG;
char		module_info[]	= MODULE_INFO;
char		module_name[]	= MODULE_NAME;
int		mod_load();
int		mod_unload();
int		mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run();
#define		MODULE_STATIC
#else
static	char	module_type	= MODULE_LOG;
static	char	module_info[]	= MODULE_INFO;
static	char	module_name[]	= MODULE_NAME;
static	int	mod_load();
static	int	mod_unload();
static	int	mod_config_beg(int), mod_config_end(int), mod_config(char*, int), mod_run();
#define		MODULE_STATIC	static
#endif

struct	log_module log_dummy = {
	{
	NULL,NULL,
	MODULE_NAME,
	mod_load,
	mod_unload,
	mod_config_beg,
	mod_config_end,
	mod_config,
	NULL,
	MODULE_LOG,
	MODULE_INFO,
	mod_run
	}
};

MODULE_STATIC
int
mod_load()
{
    printf("Dummy logger started\n");
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_unload()
{
    printf("Dummy logging stopped\n");
    return(MOD_CODE_OK);
}
MODULE_STATIC
int
mod_config_beg(int i)
{
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
mod_config(char* config, int i)
{
    return(MOD_CODE_OK);
}
MODULE_STATIC
int
mod_run()
{
    return(MOD_CODE_OK);
}
