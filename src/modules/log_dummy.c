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
