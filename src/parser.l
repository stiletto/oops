%a 5000
%o 10000
%p 5000
%n 1000
%e 2000
%{
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include "y.tab.h"
int	atline;
int	parser_errors;
%}

%s	groupst peerst
%s	httpst icpst
%s	storagest modulest modulebody

nl	\n
number	[0-9]+
numberk	{number}[Kk]
numberm	{number}[Mm]
sp		[\t ]+
comment		\#.*
network		{number}("."{number})*"/"{number}
group		[Gg][Rr][Oo][Uu][Pp]
networks	[Nn][Ee][Tt][Ww][Oo][Rr][Kk][Ss]
logfile		[Ll][Oo][Gg][Ff][Ii][Ll][Ee]
accesslog	[Aa][Cc][Cc][Ee][Ss][Ss][Ll][Oo][Gg]
pidfile		[Pp][Ii][Dd][Ff][Ii][Ll][Ee]
nameserver	[Nn][Aa][Mm][Ee][Ss][Ee][Rr][Vv][Ee][Rr]
http_port	[Hh][Tt][Tt][Pp]_[Pp][Oo][Rr][Tt]
icp_port	[Ii][Cc][Pp]_[Pp][Oo][Rr][Tt]
icons_host	[Ii][Cc][Oo][Nn][Ss]-[Hh][Oo][Ss][Tt]
icons_path	[Ii][Cc][Oo][Nn][Ss]-[Pp][Aa][Tt][Hh]
icons_port	[Ii][Cc][Oo][Nn][Ss]-[Pp][Oo][Rr][Tt]
expire_value	[Dd][Ee][Ff][Aa][Uu][Ll][Tt]-[Ee][Xx][Pp][Ii][Rr][Ee]-[Vv][Aa][Ll][Uu][Ee]
expire_interval	[Dd][Ee][Ff][Aa][Uu][Ll][Tt]-[Ee][Xx][Pp][Ii][Rr][Ee]-[Ii][Nn][Tt][Ee][Rr][Vv][Aa][Ll]
mem_max		[Mm][Ee][Mm]_[Mm][Aa][Xx]
lo_mark		[Ll][Oo]_[Mm][Aa][Rr][Kk]
hi_mark		[Hh][Ii]_[Mm][Aa][Rr][Kk]
stop_cache	[Ss][Tt][Oo][Pp]_[Cc][Aa][Cc][Hh][Ee]
http		[Hh][Tt][Tt][Pp]
icp		[Ii][Cc][Pp]
allow		[Aa][Ll][Ll][Oo][Ww]
deny		[Dd][Ee][Nn][Yy]
dstdomain	[Dd][Ss][Tt][Dd][Oo][Mm][Aa][Ii][Nn]
badports	[Bb][Aa][Dd][Pp][Oo][Rr][Tt][Ss]
storage		[Ss][Tt][Oo][Rr][Aa][Gg][Ee]
path		[Pp][Aa][Tt][Hh]
size		[Ss][Ii][Zz][Ee]
dbname		[Dd][Bb][Nn][Aa][Mm][Ee]
dbhome		[Dd][Bb][Hh][Oo][Mm][Ee]
maxresident	[Mm][Aa][Xx][Rr][Ee][Ss][Ii][Dd][Ee][Nn][Tt]
connect_from	[Cc][Oo][Nn][Nn][Ee][Cc][Tt]-[Ff][Rr][Oo][Mm]
disk_low_free	[Dd][Ii][Ss][Kk]-[Ll][Oo][Ww]-[Ff][Rr][Ee][Ee]
disk_hi_free	[Dd][Ii][Ss][Kk]-[Oo][Kk]-[Ff][Rr][Ee][Ee]
bandwidth	[Bb][Aa][Nn][Dd][Ww][Ii][Dd][Tt][Hh]
miss		[Mm][Ii][Ss][Ss]
parent		[Pp][Aa][Rr][Ee][Nn][Tt]
peer		[Pp][Ee][Ee][Rr]
sibling		[Ss][Ii][Bb][Ll][Ii][Nn][Gg]
local_domain	[Ll][Oo][Cc][Aa][Ll]-[Dd][Oo][Mm][Aa][Ii][Nn]
local_networks	[Ll][Oo][Cc][Aa][Ll]-[Nn][Ee][Tt][Ww][Oo][Rr][Kk][Ss]
icp_timeout	[Ii][Cc][Pp]_[Tt][Ii][Mm][Ee][Oo][Uu][Tt]
statistics	[Ss][Tt][Aa][Tt][Ii][Ss][Tt][Ii][Cc][Ss]
module		[Mm][Oo][Dd][Uu][Ll][Ee]
string		[^ \t\n\{\}\;\[\]\:\,]+
line		[^\n]+
%%

{comment}	;

<INITIAL>{storage}	{
		BEGIN(storagest);
		return(STORAGE);
		}
<storagest>{path} {
		return(PATH) ;
		}
<storagest>{size} {
		return(SIZE);
		}
<storagest>\}	{
		BEGIN(INITIAL);
		return('}');
		}
<INITIAL>{group}		{
		BEGIN(groupst);
		return(GROUP);
		}
<INITIAL>{module}	{
		BEGIN(modulest);
		return(MODULE);
		}
{network}	{
		yylval.STRPTR=(char*)xmalloc(strlen(yytext)+1, "network");
		strcpy(yylval.STRPTR, yytext);
		return(NETWORK);
		}
{networks}	{
		return(NETWORKS);
		}
<INITIAL>{logfile}	{
		return(LOGFILE);
		}
<INITIAL>{accesslog}	{
		return(ACCESSLOG);
		}
<INITIAL>{statistics}	{
		return(STATISTICS);
		}
<INITIAL>{pidfile}	{
		return(PIDFILE);
		}
<INITIAL>{nameserver}	{
		return(NAMESERVER);
		}
<INITIAL>{connect_from}	{
		return(CONNECT_FROM);
		}
<INITIAL>{http_port}	{
		return(HTTP_PORT);
		}
<INITIAL>{icp_port}	{
		return(ICP_PORT);
		}
<INITIAL>{icp_timeout}	{
		return(ICP_TIMEOUT);
		}
<INITIAL>{expire_value}	{
		return(EXPIRE_VALUE);
		}
<INITIAL>{expire_interval} {
		return(EXPIRE_INTERVAL);
		}
<INITIAL>{disk_low_free}	{
		return(DISK_LOW_FREE_T);
		}
<INITIAL>{disk_hi_free}	{
		return(DISK_HI_FREE_T);
		}
<INITIAL>{local_domain}	{
		return(LOCAL_DOMAIN_T);
		}
<INITIAL>{local_networks} {
		return(LOCAL_NETWORKS_T);
		}
<peerst>{parent} {
		return(PEER_PARENT_T);
		}
<peerst>{sibling} {
		return(PEER_SIBLING_T);
		}
<INITIAL>{parent}	{
		return(PARENT_T);
		}
<INITIAL>{peer}		{
		BEGIN(peerst);
		return(PEER_T);
		}
{sibling}	{
		return(SIBLING_T);
		}
<INITIAL>{stop_cache}	{
		return(STOP_CACHE);
		}
<INITIAL>{maxresident}	{
		return(MAXRESIDENT);
		}
<INITIAL>{icons_host}	{
		return(ICONS_HOST);
		}
<INITIAL>{icons_path}	{
		return(ICONS_PATH);
		}
<INITIAL>{icons_port}	{
		return(ICONS_PORT);
		}
<INITIAL>{mem_max}	{
		return(MEM_MAX);
		}
<INITIAL>{lo_mark}	{
		return(LO_MARK);
		}
<INITIAL>{hi_mark}	{
		return(HI_MARK);
		}
<INITIAL>{dbhome} 	{
		return(DBHOME);
		}
<INITIAL>{dbname}	{
		return(DBNAME);
		}
{number}	{
		yylval.INT = atoi(yytext);
		return(NUMBER);
		}
{numberk}	{
		yylval.INT = atoi(yytext) * 1024;
		return(NUMBER);
		}
{numberm}	{
		yylval.INT = atoi(yytext) * 1024 * 1024;
		return(NUMBER);
		}
<modulest>\{	{
		BEGIN(modulebody);
		return('{');
		}
\{		{
		return('{');
		}
<INITIAL>\}	{
		return('}');
		}
\;		{
		return(';');
		}
<peerst>\}	{
		BEGIN(INITIAL);
		return('}');
		}
<groupst>\}	{
		BEGIN(INITIAL);
		return('}');
		}
<modulebody>\}	{
		BEGIN(INITIAL);
		return('}');
		}
<modulebody>{line} {
		yylval.STRPTR=(char*)xmalloc(strlen(yytext)+1, "string");
		strcpy(yylval.STRPTR, yytext);
		return(STRING);
		}
<groupst>{badports} {
		return(BADPORTS_T);
		}
<groupst>{miss} {
		return(MISS_T);
		}
<groupst>{bandwidth} {
		return(BANDWIDTH_T);
		}
<groupst>{http} {
		BEGIN(httpst);
		return(HTTP);
		}
<groupst>[Aa][Uu][Tt][Hh]_[Mm][Oo][Dd][Ss] {
		return(AUTH_MODS_T);
		}
<groupst>[Rr][Ee][Dd][Ii][Rr]_[Mm][Oo][Dd][Ss] {
		return(REDIR_MODS_T);
		}
<groupst>{icp}	{
		BEGIN(icpst);
		return(ICP);
		}
<httpst,icpst>\}	{
		BEGIN(groupst);
		return('}');
		}
<peerst,httpst,icpst,groupst>{allow}	{
		return(ALLOW);
		}
<peerst,httpst,icpst,groupst>{deny}	{
		return(DENY);
		}
<peerst,httpst,icpst>{dstdomain} {
		return(DSTDOMAIN);
		}
\[		{
		return('[');
		}
\]		{
		return(']');
		}
\:		{
		return(':');
		}
\,		{
		return(',');
		}
{string}	{
		yylval.STRPTR=(char*)xmalloc(strlen(yytext)+1, "string");
		strcpy(yylval.STRPTR, yytext);
		return(STRING);
		}
<peerst,groupst>{nl}	{atline++;}
<httpst,icpst,storagest,modulest,modulebody>{nl} {
		atline++;
		}
{nl}		{atline++;return(L_EOS);}
.		;
%%

yyerror()
{
	parser_errors++;
	printf("lex: error on \"%s\" at line %d\n", yytext, atline);
	return(0);
}

