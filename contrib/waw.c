/* Who & Where statistic generator for Oops log files

   Make it with 'gcc -o waw waw.c'. Should compile without errors.

   Run it with './waw -h' to get help on usage.

   Note: It's my first attempt in C. It's probably buggy, unstable, badly structured and using
         strange and/or non-standard methods of doing things.
         Nevertheless it works for me. :-) And again I just learn C coding this. Have patience.

   Dan Bilik (dbilik@ov.lekis.cz)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *skipchars(char *string, char character, int count) /* Skips `count' chars `char' in `string' */
{
  int x;

  for (x = 1; x <= count; x++)
    while (*string++ != character) ;

  return string;
} /* skipchars */

int myfgets(FILE *xfile, char *dest, int count) /* Reads whole line from `xfile' and put max. `count' chars from it to `dest' */
{
  int y;

  while (count != -1) {
    y = getc(xfile);
    if (y == EOF) count = -1;
    if ((y == 10) && (count == 0)) count = -1;
    if (count > 0) {
      if (y == 10) {
        count = -1;
        y = 0;
      } /* if */
      else if (count == 1) y = 0;
      *dest++ = y;
      if (count != -1) count--;
    } /* if */
  } /* while */

  return y;
} /* getline */

int main(int argc, char **argv)
{
  typedef
  struct structinfo {
    char name[1023]; /* Server hostname */
    int hits; /* Number of requests to that server */
    long bytes; /* Total bytes from that server */
    FILE *details; /* Where to write details about each request */
    struct structinfo *next; /* Pointer to info about next host */
  } hostinfo;

  const char roothtml[] = "index.html";
  const char txtext[] = ".txt";
  const char htmlhead1[] = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n<HTML lang=\"en\" dir=\"LTR\">\n<HEAD>\n<META name=\"description\" lang=\"en\" content=\"\">\n<META content=\"text/html; charset=iso-8859-1\" http-equiv=Content-Type>\n<TITLE>";
  const char htmlhead2[] = "</TITLE>\n</HEAD>\n<BODY>\n";
  const char htmlfoot[] = "</BODY>\n</HTML>\n";

  FILE *infile = NULL, *outfile = NULL;
  char ipaddress[17] = ""; /* IP address to spy */
  char logname[255] = "access.log"; /* Logfile */
  char dirname[255] = ""; /* Directory for generated files */
  struct {
    char line[1023]; /* Whole line */
    char url[1023]; /* Whole name of object requested */
    char hostname[1023]; /* Pure hostname requested */
  } log; /* Data extracted from one line of logfile */
  struct {
    char userlog, userdir, verbose;
  } options = {0, 0, 0};  /* Options given as arguments */
  char dead = 0; /* How and why it ended */
  hostinfo *acthost = NULL, *firsthost = NULL, *tmphost = NULL;
  int hostcount = 0, totalhits = 0;
  long bytescount = 0;
  char *a, *b;
  int c, d, e;
  char f[255];
  long g;

  for (c = 1; c < argc; c++)
    if (argv[c][0] != '-') { /* Argument is probably a file/directory/IP */
      if (options.userlog) {
        strncpy(logname, argv[c], 255);
        options.userlog = 0;
      } /* if */
      else if (options.userdir) {
        strncpy(dirname, argv[c], 255);
        options.userdir = 0;
      } /* else if */
      else strncpy(ipaddress, argv[c], 15);
    } /* if */
    else { /* Argument is a switch */
      options.userlog = 0;
      options.userdir = 0;
      switch (argv[c][1]) {
        case 'l': options.userlog = 1;
                  break;
        case 'd': options.userdir = 1;
                  break;
        case 'v': options.verbose = 1;
                  break;
        case 'h':
        default: dead = 5;
      } /* switch */
    } /* else */

  if ((d = strlen(ipaddress)) == 0) dead = 5;
  else {
    if ((c = strlen(dirname)) == 0) strncpy(dirname, ipaddress, 16);
    strncat(dirname, "/", 1);
    if (d > 15) d = 15;
    for (c = (d - 1); c >= 0; c--) ipaddress[c + 1] = ipaddress[c];
    ipaddress[0] = ' ';
    ipaddress[d + 1] = ' ';
    ipaddress[d + 2] = '\0';
  } /* else */
  if ((options.verbose != 0) || (dead == 5)) {
    printf(" Who&Where v0.1.4 \n");
    printf(" Statistic generator for Oops log files \n\n");
  }
  if (options.verbose != 0) {
    printf("IP address: %s\n", ipaddress);
    printf("Logfile: %s\n", logname);
    printf("Work directory: %s\n", dirname);
  } /* if */

  if (dead == 5) ;
  else if ((infile = fopen(logname, "rt")) == NULL) dead = 1;
  else {
    mkdir(dirname, 493);
    chdir(dirname);
    while (((c = myfgets(infile, log.line, 1023)) != EOF) && (dead == 0))
      if ((a = strstr(log.line, ipaddress)) != 0) {
        if (options.verbose != 0) printf("Hosts: %d   Hits: %d   Bytes: %d\r", hostcount, totalhits, bytescount);
        totalhits++;
        a = skipchars(log.line, ' ', 4);
        b = f;
        while (((*b++ = *a++) != ' ') && (*a != '\0')) ;
        *b = '\0';
        g = atol(f);
        bytescount += g;
        a = skipchars(log.line, ' ', 6);
        b = log.url;
        while (((*b++ = *a++) != ' ') && (*a != '\0') && (*a != '%')) ;
        *b++ = '\n';
        *b = '\0';
        a = skipchars(log.url, '/', 2);
        b = log.hostname;
        while (((*b++ = *a++) != '/') && (*a != '\0')) ;
        b--;
        *b = '\0';
        acthost = firsthost;
        for (c = 1; c <= hostcount; c++) {
          if ((d = strcmp(acthost->name, log.hostname)) == 0) {
            acthost->hits += 1;
            acthost->bytes += g;
            if ((d = fprintf(acthost->details, log.url)) == EOF) dead = 31;
            c = hostcount + 2;
          } /* if */
          acthost = acthost->next;
        } /* for */
        if (c == (hostcount + 1)) {
          if ((tmphost = malloc(sizeof(hostinfo))) == NULL) dead = 4;
          else {
            if (hostcount > 0) acthost->next = tmphost;
            else firsthost = tmphost;
            acthost = tmphost;
            acthost->next = tmphost;
            strncpy(acthost->name, log.hostname, 1023);
            acthost->hits = 1;
            acthost->bytes = g;
            hostcount += 1;
            strncpy(f, acthost->name, 251);
            strncat(f, txtext, 4);
            if ((acthost->details = fopen(f, "w+t")) == NULL) dead = 3;
            else if ((d = fprintf(acthost->details, log.url)) == EOF) dead = 31;
          } /* else */
        } /* if */
      } /* if */
  } /* else */

  if ((dead != 1) && (dead != 5)) {
    if ((outfile = fopen(roothtml, "w+t")) == NULL) dead = 2;
    else if ((d = fprintf(outfile, htmlhead1)) == EOF) dead = 21;
    else if ((d = fprintf(outfile, ipaddress)) == EOF) dead = 21;
    else if ((d = fprintf(outfile, htmlhead2)) == EOF) dead = 21;
    else if ((d = fprintf(outfile, "<H1><U>Proxy request statistic for%s</U></H1>\n<P>\n<B>Hosts requested:</B> %d<BR>\n<B>Total requests:</B> %d<BR>\n<B>Total bytes:</B> %d<BR>\n</P>\n", ipaddress, hostcount, totalhits, bytescount)) == EOF) dead = 21;
    for (e = 1; e <= hostcount; e++) {
      acthost = firsthost;
      tmphost = firsthost;
      while (tmphost->details == NULL) tmphost = tmphost->next;
      for (c = 1; c <= hostcount; c++) {
        if ((acthost->hits > tmphost->hits) && (acthost->details != NULL)) tmphost = acthost;
        acthost = acthost->next;
      } /* for */
      if ((d = fprintf(outfile, "<P><B>%s</B> (%d <A HREF=\"%s%s\">hit(s)</A>/%d bytes)</P>\n", tmphost->name, tmphost->hits, tmphost->name, txtext, tmphost->bytes)) == EOF) dead = 21;
      fclose(tmphost->details);
      tmphost->details = NULL;
    } /* for */
    if ((d = fprintf(outfile, htmlfoot)) == EOF) dead = 21;
    acthost = firsthost;
    for (c = 1; c <= hostcount; c++)
      if (acthost == NULL) c = hostcount + 1;
      else {
        tmphost = acthost;
        acthost = acthost->next;
        free(tmphost);
      } /* else */
    if (outfile != NULL) fclose(outfile);
  } /* if */

  if (infile != NULL) fclose(infile);

  switch (dead) {
    case 0: if (options.verbose != 0) printf("\nDone. See '%sindex.html' for results.\n\n", dirname);
            break;
    case 1: printf("\nError opening input file.\n\n");
            break;
    case 2: printf("\nError opening output file.\n\n");
            break;
    case 3: printf("\nError opening details output file.\n\n");
            break;
    case 21: printf("\nError writing output file.\n\n");
             break;
    case 31: printf("\nError writing details output file.\n\n");
             break;
    case 4: printf("\nError allocating memory.\n\n");
             break;
    case 5: printf("Usage: waw IP_address [-l logfile_name] [-d work_directory] [-v] [-h]\n\n");
            printf("-l specify Oops log file, default is ./access.log\n");
            printf("-d specify directory to save results, default is same as given IP address\n");
            printf("-v be verbose\n");
            printf("-h print this help\n\n");
  } /* switch */

  return 0;
} /* main */
