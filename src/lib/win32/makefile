#
# Copyright (C) 1999, 2000 Igor Khasilev, igor@paco.net
# Copyright (C) 2000 Andrey Igoshin, ai@vsu.ru
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

#
# This makefile is designed for building Oops using IBM VisualAge C++ 4.0
# for NT.
#
# For making a WIN32 binary, run the command "nmake -f win32/makefile"
# in the src directory.
#


INCLUDE=$(INCLUDE);.\;..\;
LDFLAG=/SUBSYSTEM:console /DEBUG /STACK:0x100000
CFLAGS=/Q+ /W3 /Gm+ /Ti+ /qarch=pentium2 /qtune=pentium2
LD=ilink
CC=iccv4
LIB=$(LIB);.\win32;c:\Program Files\DevStudio\VC\lib;

all: oops.exe

.c.obj:
	$(CC) $(CFLAGS) /C %s

{win32}.c.obj:
	$(CC) $(CFLAGS) /C %s

y.tab.c:
	yacc -d parser.y

lex.yy.c:
	flex parser.l

oops.exe: oops.obj lib.obj run.obj run_client.obj common.obj http_utils.obj \
	ftp_utils.obj storage.obj garbage_c.obj icp.obj acl.obj y.tab.obj lex.yy.obj \
	rotate_logs.obj clean_disk.obj ssl.obj list.obj statistics.obj worker.obj \
	queue.obj hash.obj modules.obj strtok_r.obj getopt.obj ulib.obj
	$(LD) $(LDFLAG) -out:$@ $** \
	CPPRMS40.LIB \
	WSOCK32.LIB \
	PTHREAD.LIB \
	LIBDBIS4.LIB

oops.obj:		oops.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
lib.obj:		lib.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
run.obj:		run.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
run_client.obj:		run_client.c extern.h win32\config.h oops.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
common.obj:		common.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
http_utils.obj:		http_utils.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
ftp_utils.obj:		ftp_utils.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
storage.obj:		storage.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
garbage_c.obj:		garbage_c.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
icp.obj:		icp.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
acl.obj:		acl.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
y.tab.obj:		parser.y y.tab.c y.tab.h oops.h extern.h win32\config.h \
			win32\environment.h win32\ulib.h win32\db.h win32\pthread.h
lex.yy.obj:		parser.l lex.yy.c y.tab.h oops.h extern.h win32\config.h \
			win32\environment.h win32\ulib.h win32\db.h win32\pthread.h
rotate_logs.obj:	rotate_logs.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
clean_disk.obj:		clean_disk.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
ssl.obj:		ssl.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
list.obj:		list.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
statistics.obj:		statistics.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
worker.obj:		worker.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\db.h win32\pthread.h
queue.obj:		queue.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\pthread.h
hash.obj:		hash.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\pthread.h
modules.obj:		modules.c modules.h oops.h extern.h win32\config.h \
			win32\environment.h win32\ulib.h win32\db.h win32\pthread.h
strtok_r.obj:		strtok_r.c oops.h win32\config.h win32\environment.h \
			win32\ulib.h win32\pthread.h
getopt.obj:		getopt.c getopt.h win32\config.h win32\environment.h \
			win32\ulib.h win32\pthread.h
#getopt1.obj:		getopt1.c getopt.h win32\config.h win32\environment.h \
#			win32\ulib.h
ulib.obj:		win32\ulib.c oops.h extern.h win32\config.h win32\environment.h \
			win32\ulib.h win32\pthread.h

clean:
	-del *.obj *.exe *.dbg *.dll y.tab.c y.tab.h lex.yy.c 2>nul
