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

#define	RDLOCK_CL   pthread_rwlock_rdlock(&nflock)
#define	WRLOCK_CL   pthread_rwlock_wrlock(&nflock)
#define	UNLOCK_CL   pthread_rwlock_unlock(&nflock)

#define     MODULE_INFO "Netflow  access log."
#define     MODULE_NAME "netflow"

#if	defined(MODULES)
char            module_type 	= MODULE_LOG;
char            module_info[]	= MODULE_INFO;
char            module_name[]	= MODULE_NAME;
int             mod_load(void);
int             mod_unload(void);
int             mod_config_beg(int), mod_config_end(int), mod_config(char*, int), mod_run(void);
int             mod_log(int elapsed, struct request *rq, struct mem_obj *obj);
int             mod_reopen(void);
int             mod_tick(void);
#define     MODULE_STATIC
#else
static  char    module_type 	= MODULE_LOG;
static  char    module_info[]	= MODULE_INFO;
static  char    module_name[]	= MODULE_NAME;
static  int     mod_load(void);
static  int     mod_unload(void);
static  int     mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run(void);
static  int     mod_log(int elapsed, struct request *rq, struct mem_obj *obj);
static  int     mod_reopen(void);
static  int     mod_tick(void);
#define     MODULE_STATIC   static
#endif

struct	log_module netflow = {
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
        mod_run,
        mod_tick
    },
    mod_log,
    mod_reopen
};

typedef struct  _collector {
    struct sockaddr_in   addr;
    struct _collector   *next;
} collector_t;

static void                 flush(void);
static collector_t          *collectors = NULL, *clast = NULL;
static pthread_rwlock_t     nflock;
static pthread_mutex_t      record_lock;
static void                 process_log_record(int elapsed, struct request *rq, struct mem_obj *);
static struct sockaddr_in   source;
static int                  flow_so = -1;
static uint32_t             flowseq = 0;

typedef struct  flow_header {
    uint16_t    version;        /* NetFlow export format version number                          */
    uint16_t    count;          /* Number of flows exported in this packet (1-30)                */
    uint32_t    SysUptime;      /* Current time in milliseconds since the export device booted   */
    uint32_t    unix_secs;      /* Current count of seconds since 0000 UTC 1970                  */
    uint32_t    unix_nsecs;     /* Residual nanoseconds since 0000 UTC 1970                      */
    uint32_t    flow_sequence;  /* Sequence counter of total flows seen                          */
    char        engine_type;    /* Type of flow-switching engine                                 */
    char        engine_id;      /* Slot number of the flow-switching engine                      */
    uint16_t    reserved;       /* Unused (zero) bytes                                           */

} flow_header_t;

typedef struct  flow_record {
    uint32_t    srcaddr;        /* Source IP address                                             */
    uint32_t    dstaddr;        /* Destination IP address                                        */
    uint32_t    nexthop;        /* IP address of next hop router                                 */
    uint16_t    input;          /* SNMP index of input interface                                 */
    uint16_t    output;         /* SNMP index of output interface                                */
    uint32_t    dPkts;          /* Packets in the flow                                           */
    uint32_t    dOctets;        /* Total number of Layer 3 bytes in the packets of the flow      */
    uint32_t    First;          /* SysUptime at start of flow                                    */
    uint32_t    Last;           /* SysUptime at the time the last packet of the flow was received*/
    uint16_t    srcport;        /* TCP/UDP source port number or equivalent                      */
    uint16_t    dstport;        /* TCP/UDP destination port number or equivalent                 */
    char        pad1;           /* Unused (zero) bytes                                           */
    char        tcp_flags;      /* Cumulative OR of TCP flags                                    */
    char        prot;           /* IP protocol type (for example, TCP = 6; UDP = 17)             */
    char        tos;            /* IP type of service (ToS)                                      */
    uint16_t    src_as;         /* Autonomous system number of the source, either origin or peer */
    uint16_t    dst_as;         /* Autonomous system number of the destination, either origin or peer */
    char        src_mask;       /* Source address prefix mask bits                               */
    char        dst_mask;       /* Destination address prefix mask bits                          */
    uint16_t    pad2;           /* Unused (zero) bytes                                           */
} flow_record_t;

#define MAXRTTABLESZ    200000 /* max routes in table */
#define MAX_FLOWRECORDS 30     /* max flow records in flow_packet */

typedef struct {
    flow_header_t	header;
    flow_record_t       record[MAX_FLOWRECORDS];
} flow_packet_t;

typedef struct {
    uint32_t    network;
    uint32_t    mask;
    uint16_t    asn;
    uint16_t    masklen;
} route_entry_t;

static  time_t          file_mtime = 0;
static  char            file_name[MAXPATHLEN];
static  int             tick_counter = 0;
static  int             rtsize=0;
static  route_entry_t   *rtable = NULL;
static  route_entry_t   *rtables[2] = {NULL,NULL};
static  int             rtable_index = 0;

static  int             flow_records = 0;
static  flow_packet_t   flow_packet;

static  int cmprt(const void* ap, const void* bp) {
    route_entry_t *a = (route_entry_t*)ap;
    route_entry_t *b = (route_entry_t*)bp;

    if ( a->network < b->network ) return(-1);
    if ( a->network > b->network ) return(1);
    return(a->mask - b->mask);
}

MODULE_STATIC
int
mod_tick(void)
{
struct  stat    sb;
int             rc, new_rt_entries = 0;
FILE           *file;
char            buf[1024];
route_entry_t  *rt, *rt_ptr;

    if ( 0 == file_name[0] ) return;
    rc = stat(file_name, &sb);
    if ( rc < 0 ) {
        my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "netflow: can't stat(`%s'): %s\n", file_name, strerror(errno));
        return;
    }
    if ( sb.st_mtime <= file_mtime ) {
        my_xlog(OOPS_LOG_DBG, "netflow: %s already seen\n", file_name);
        return;
    }
    /* reload */
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG, "netflow: reload from `%s'\n", file_name);
    file = fopen(file_name, "r");
    if ( file == NULL ) {
        my_xlog(OOPS_LOG_SEVERE, "netflow: can't fopen(`%s'): %s\n", file_name, strerror(errno));
        return;
    }
    WRLOCK_CL;
    /* allocate tables once and forever to avoid memory fragmentation */
    if ( NULL == rtables[0] ) rtables[0] = calloc(MAXRTTABLESZ, sizeof(route_entry_t));
    if ( NULL == rtables[1] ) rtables[1] = calloc(MAXRTTABLESZ, sizeof(route_entry_t));
    rt = rtables[rtable_index++]; rtable_index = rtable_index%2;
    rt_ptr = rt;
    if ( NULL == rt_ptr ) {
        fclose(file);
        UNLOCK_CL;
        return;
    }
    while(fgets(buf, sizeof(buf) - 1, file) && (new_rt_entries < MAXRTTABLESZ)) {
        char        *p = buf, *d;
        char        netbuf[20];
        uint32_t    net;
        uint16_t    len;
        uint16_t    asn;

        /* format: net/len as */
        while (*p && isspace(*p) ) p++;
        if ( 0 == *p ) continue;
        d = netbuf;
        while ( *p && (*p != '/') ) {
            *d = *p;
            d++;p++;
        }
        if ( 0 == *p ) continue;
        *d = 0;
        net = inet_addr(netbuf);
        if ( net == INADDR_ANY ) continue;
        p++;

        /* copy len */
        d = netbuf;
        while ( *p && !isspace(*p) ) {
            *d=*p;
            d++;p++;
        }
        *d=0;
        len = (uint16_t)atoi(netbuf);
        if ( len > 32 ) continue;
        while (*p && isspace(*p) ) p++;

        /* copy AS */
        d = netbuf;
        while ( *p && !isspace(*p) ) {
            *d=*p;
            d++;p++;
        }
        *d=0;
        asn = (uint16_t)atoi(netbuf);
        rt_ptr->network = ntohl(net); /* store in host order for qsort and search */
        rt_ptr->masklen = len;
        rt_ptr->asn     = asn;
        if ( len > 0 ) rt_ptr->mask = (int)0x80000000 >> ( len - 1 );
        new_rt_entries++;
        rt_ptr++;
    }
    fclose(file);
    /* sort */
    qsort(rt, new_rt_entries, sizeof(route_entry_t), cmprt);
    file_mtime = sb.st_mtime;
    rtable = rt;
    rtsize = new_rt_entries;
    UNLOCK_CL;
    /* flush what is in packet buffer */
    tick_counter++;
    if ( tick_counter > 30 ) {
        flush();
        tick_counter = 0;
    }
}

/*
    addr - in_addr in net order
    result - enttry in route table
 */
static
route_entry_t  *lookup(uint32_t addr, int left, int right) {
/*
  |A-------B|C--------D|
  addr must be lt C and eq B
*/
int         Ai,Bi,Ci,Di;
int         Av,Bv,Cv,Dv;
uint32_t    haddr;          /* addr in host order */

    if ( !rtable ) return(NULL);
    haddr = ntohl(addr);
    /*printf("%08.8X[%d:%d]\n", haddr,left, right);*/
    if ( right - left <= 1 ) {
        if (rtable[left].network == ( haddr & rtable[left].mask )) {
            return(&rtable[left]);
        }
        return(NULL);
    }
    Ai = left;
    Di = right;
    Bi = (Ai+Di)/2;
    Ci = (Ai+Di)/2 + 1;

    if ( rtable[Bi].network == ( haddr & rtable[Bi].mask ) ) {
        /* found */
        return(&rtable[Bi]);
    } else
    if ( rtable[Bi].network > ( haddr & rtable[Bi].mask ) ) {
        /* continue with A and B */
        return(lookup(addr, Ai, Bi));
    } else {
        /* continue with C and D */
        return(lookup(addr, Ci, Di));
    }
}

MODULE_STATIC
int
mod_log(int elapsed, struct request *rq, struct mem_obj *obj)
{
collector_t *curr;
int         rc;

    RDLOCK_CL;
    pthread_mutex_lock(&record_lock);
    process_log_record(elapsed, rq, obj);
    if ( flow_records == MAX_FLOWRECORDS ) {
        flow_packet.header.count = htons(flow_records);
        curr = collectors;
        while ( curr ) {
            rc = sendto(flow_so, (void*)&flow_packet, sizeof(flow_packet), 0, (struct sockaddr*)&curr->addr, sizeof(struct sockaddr_in));
            curr = curr->next;
        }
        flow_records = 0;
    }
    pthread_mutex_unlock(&record_lock);
    UNLOCK_CL;
    return(MOD_CODE_OK);
}

static void flush(void)
{
collector_t *curr;
int         rc;

    RDLOCK_CL;
    pthread_mutex_lock(&record_lock);
    if ( flow_records > 0 ) {
	size_t	flow_packet_size = sizeof(flow_header_t) + sizeof(flow_record_t)*flow_records;
        flow_packet.header.count = htons(flow_records);
        curr = collectors;
        while ( curr ) {
            rc = sendto(flow_so, (void*)&flow_packet, flow_packet_size, 0, (struct sockaddr*)&curr->addr, sizeof(struct sockaddr_in));
            curr = curr->next;
        }
        flow_records = 0;
    }
    pthread_mutex_unlock(&record_lock);
    UNLOCK_CL;
    return;
}

MODULE_STATIC
void
process_log_record(int elapsed, struct request *rq,
                    struct mem_obj *obj)
{
int                 rc;
struct sockaddr_in  temp_sa;
route_entry_t       *rtentry;
flow_record_t       *record = &flow_packet.record[flow_records];
uint16_t            src_asn = 0, dst_asn = 0;

    if ( rq->doc_sent <= 0 ) return;

    /* Fill all needed fields   */
    /* first - header           */
    flow_packet.header.flow_sequence = htonl(flowseq++);
    flow_packet.header.SysUptime     = htonl(global_sec_timer - start_time);
    flow_packet.header.unix_secs     = htonl(global_sec_timer);
    /* then record              */
    /* source = document source host (or peer)  */
    /* desctination = client                    */
    record->srcaddr = 0;
    if ( rq->source && !str_to_sa(rq->source, (struct sockaddr*)&temp_sa)) {
        record->srcaddr = temp_sa.sin_addr.s_addr;
        record->srcport = rq->source_port;
    }
    record->dstaddr  = rq->client_sa.sin_addr.s_addr;
    record->dstport  = rq->client_sa.sin_port;
    record->dPkts    = htonl(1);
    record->dOctets  = htonl(rq->doc_sent);
    record->First    = htonl(rq->request_time - start_time);
    record->Last     = htonl(rq->request_time - start_time + elapsed/1000);
    record->prot     = IPPROTO_TCP;

    rtentry = lookup(temp_sa.sin_addr.s_addr, 0, rtsize);
    if ( rtentry ) {
        record->src_as   = htons(rtentry->asn);
        record->src_mask = rtentry->masklen;
    } else {
        record->src_as   = 0;
        record->src_mask = 32;
    }
    rtentry = lookup(rq->client_sa.sin_addr.s_addr, 0, rtsize);
    if ( rtentry ) {
        record->dst_as   = htons(rtentry->asn);
        record->dst_mask = rtentry->masklen;
    } else {
        record->dst_as   = 0;
        record->dst_mask = 32;
    }
    flow_records++;
}

MODULE_STATIC
int
mod_reopen(void)
{
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_load(void)
{
    file_mtime = 0;
    file_name[0] = 0;
    collectors = NULL;
    pthread_rwlock_init(&nflock, NULL);
    pthread_mutex_init(&record_lock, NULL);
    memset(&flow_packet, 0, sizeof(flow_packet));
    flow_packet.header.version = htons(5); /* always version 5 */
    printf("Netflow started\n");

    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_unload(void)
{
    printf("mod_unload(): Netflow stopped\n");
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_beg(int i)
{
collector_t *curr, *next;

    WRLOCK_CL;
    memset(&source, 0, sizeof(source));
    if ( flow_so != -1 ) {
        close(flow_so);
        flow_so = -1;
    }
    curr = collectors;
    while ( curr ) {
        next = curr->next;
        free(curr);
        curr = next;
    }
    UNLOCK_CL;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_end(int i)
{
int rc;

    flow_so = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( flow_so >= 0 ) {
        rc = bind(flow_so, (struct sockaddr*)&source, sizeof(source));
        if ( rc != 0 ) {
            printf("netflow:mod_config_end(): bind(): %s\n", strerror(errno));
        }
    }
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_run(void)
{
collector_t *curr;

    WRLOCK_CL;
    curr = collectors;
    while ( curr ) {
        printf("collector %s:%d\n", inet_ntoa(curr->addr.sin_addr), ntohs(curr->addr.sin_port));
        curr = curr->next;
    }
    UNLOCK_CL;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config(char* config, int i)
{
char        *p = config;
collector_t *coll;

    while( *p && IS_SPACE(*p) ) p++;

    if ( !strncasecmp(p, "collector", 9) ) {
        /* line looks like 'collector xxx.xxx.xxx.xxx:yyyyy */
        char    *cp = p+9, *port;

        while ( *cp && IS_SPACE(*cp) ) cp++;
        if ( !*cp ) {
            verb_printf("mod_config(): Wrong line `%s'.\n", config);
            return(MOD_CODE_ERR);
        }
        coll = calloc(sizeof(*coll), 1);
        if ( !coll ) {
            return(MOD_CODE_ERR);
        }
        coll->addr.sin_family = AF_INET;
        #if     !defined(SOLARIS) && !defined(LINUX) && !defined(OSF) && !defined(_WIN32)
        coll->addr.sin_len = sizeof(coll->addr);
        #endif
        port = cp;
        while ( *port && *port != ':' ) port++;
        if ( *port && *(port+1)!=0 ) {
            coll->addr.sin_port = htons(atoi(port+1));
            *port = 0;
        }
        coll->addr.sin_addr.s_addr = inet_addr(cp);
        /* put in list */
        if ( clast != NULL ) {
            clast->next = coll;
        } else {
            collectors = coll;
        }
        clast = coll;
        return(MOD_CODE_OK);
    }
    if ( !strncasecmp(p, "file", 4) ) {
        /* line looks like 'file: /var/tmp/route-table */
        char    *cp = p+4, *port;

        while ( *cp && IS_SPACE(*cp) ) cp++;
        if ( !*cp ) {
            verb_printf("mod_config(): Wrong line `%s'.\n", config);
            return(MOD_CODE_ERR);
        }
        strncpy(file_name, cp, sizeof(file_name) - 1);
        file_name[sizeof(file_name)-1] = 0;
        return(MOD_CODE_OK);
    }
    if ( !strncasecmp(p, "source", 6) ) {
        /* line looks like 'source xxx.xxx.xxx.xxx:yyyy */
        char    *cp = p+6, *port;

        while ( *cp && IS_SPACE(*cp) ) cp++;
        if ( !*cp ) {
            verb_printf("mod_config(): Wrong line `%s'.\n", config);
            return(MOD_CODE_ERR);
        }
        source.sin_family = AF_INET;
        #if     !defined(SOLARIS) && !defined(LINUX) && !defined(OSF) && !defined(_WIN32)
        source.sin_len = sizeof(coll->addr);
        #endif
        port = cp;
        while ( *port && *port != ':' ) port++;
        if ( *port && *(port+1)!=0 ) {
            source.sin_port = htons(atoi(port+1));
            *port = 0;
        }
        source.sin_addr.s_addr = inet_addr(cp);
        return(MOD_CODE_OK);
    }
    return(MOD_CODE_OK);
}

/*

http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_0/nfc_ug/nfcform.htm

----------------------------------------------------------------------------------------------\
Table B-3   Version 5 Header Format                                                           |
                                                                                              |
Bytes   Contents        Description                                                           |
----------------------------------------------------------------------------------------------\
0-1     version         NetFlow export format version number                                  |
2-3     count           Number of flows exported in this packet (1-30)                        |
4-7     SysUptime       Current time in milliseconds since the export device booted           |
8-11    unix_secs       Current count of seconds since 0000 UTC 1970                          |
12-15   unix_nsecs      Residual nanoseconds since 0000 UTC 1970                              |
16-19   flow_sequence   Sequence counter of total flows seen                                  |
20      engine_type     Type of flow-switching engine                                         |
21      engine_id       Slot number of the flow-switching engine                              |
22-23   reserved        Unused (zero) bytes                                                   |
----------------------------------------------------------------------------------------------/

----------------------------------------------------------------------------------------------\
Table B-4   Version 5 Flow Record Format                                                      |
                                                                                              |
Bytes   Contents        Description                                                           |
----------------------------------------------------------------------------------------------\
0-3     srcaddr         Source IP address                                                     |
4-7     dstaddr         Destination IP address                                                |
8-11    nexthop         IP address of next hop router                                         |
12-13   input           SNMP index of input interface                                         |
14-15   output          SNMP index of output interface                                        |
16-19   dPkts           Packets in the flow                                                   |
20-23   dOctets         Total number of Layer 3 bytes in the packets of the flow              |
24-27   First           SysUptime at start of flow                                            |
28-31   Last            SysUptime at the time the last packet of the flow was received        |
32-33   srcport         TCP/UDP source port number or equivalent                              |
34-35   dstport         TCP/UDP destination port number or equivalent                         |
36      pad1            Unused (zero) bytes                                                   |
37      tcp_flags       Cumulative OR of TCP flags                                            |
38      prot            IP protocol type (for example, TCP = 6; UDP = 17)                     |
39      tos             IP type of service (ToS)                                              |
40-41   src_as          Autonomous system number of the source, either origin or peer         |
42-43   dst_as          Autonomous system number of the destination, either origin or peer    |
44      src_mask        Source address prefix mask bits                                       |
45      dst_mask        Destination address prefix mask bits                                  |
46-47   pad2            Unused (zero) bytes                                                   |
----------------------------------------------------------------------------------------------/
*/
