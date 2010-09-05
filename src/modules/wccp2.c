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


#include    "../oops.h"
#include    "../modules.h"

#include    <sys/uio.h>

#define     WCCP2_PORT                     (2048)

#define     WCCP2_HERE_I_AM                (10)
#define     WCCP2_I_SEE_YOU                (11)
#define     WCCP2_REDIRECT_ASSIGN          (12)
#define     WCCP2_REMOVAL_QUERY            (13)
#define     WCCP2_SECURITY_INFO            (0)
#define     WCCP2_NO_SECURITY              (0)
#define     WCCP2_MD5_SECURITY             (1)
#define     WCCP2_SERVICE_INFO             (1)
#define     WCCP2_SERVICE_STANDARD         (0)
#define     WCCP2_SERVICE_DYNAMIC          (1)
#define     WCCP2_ROUTER_ID_INFO           (2)
#define     WCCP2_WC_ID_INFO               (3)
#define     WCCP2_RTR_VIEW_INFO            (4)
#define     WCCP2_WC_VIEW_INFO             (5)
#define     WCCP2_REDIRECT_ASSIGNMENT      (6)
#define     WCCP2_QUERY_INFO               (7)
#define     WCCP2_CAPABILITY_INFO          (8)
#define     WCCP2_ALT_ASSIGNMENT           (13)
#define     WCCP2_HASH_ASSIGNMENT          (0x00)
#define     WCCP2_MASK_ASSIGNMENT          (0x01)
#define     WCCP2_ASSIGN_MAP               (14)
#define     WCCP2_COMMAND_EXTENSION        (15)
#define     WCCP2_COMMAND_TYPE_SHUTDOWN    (01)
#define     WCCP2_COMMAND_TYPE_SHUTDOWN_RESPONSE (02)
#define     WCCP2_FORWARDING_METHOD        0x01
#define     WCCP2_ASSIGNMENT_METHOD        0x02
#define     WCCP2_PACKET_RETURN_METHOD     0x03
#define     WCCP2_FORWARDING_METHOD_GRE    0x00000001
#define     WCCP2_FORWARDING_METHOD_L2     0x00000002
#define     WCCP2_ASSIGNMENT_METHOD_HASH   0x00000001
#define     WCCP2_ASSIGNEMNT_METHOD_MASK   0x00000002
#define     WCCP2_PACKET_RETURN_METHOD_GRE 0x00000001
#define     WCCP2_PACKET_RETURN_METHOD_L2  0x00000002

#define     PortsDefined                   (0x0010)

#define     MAX_ROUTERNAME_LEN              64

#define     MODULE_NAME "wccp2"
#define     MODULE_INFO "Web Cache Coordination Protocol v2.0"

#if	defined(MODULES)
char	    module_type   = MODULE_LISTENER ;
char	    module_name[] = MODULE_NAME ;
char	    module_info[] = MODULE_INFO;
int         mod_load(void);
int         mod_unload(void);
int         mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run(void);
void*       process_call(void *arg);
int         mod_tick(void);
#define     MODULE_STATIC
#else
static	char	module_type   = MODULE_LISTENER ;
static	char	module_name[] = MODULE_NAME ;
static	char	module_info[] = MODULE_INFO ;
static  int     mod_load(void);
static  int     mod_unload(void);
static  int     mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run(void);
static	void*	process_call(void *arg);
static  int        mod_tick();
#define     MODULE_STATIC	static
#endif

struct	listener_module	wccp2_mod = {
	{
	NULL, NULL,
	MODULE_NAME,
	mod_load,
	mod_unload,
	mod_config_beg,
	mod_config_end,
	mod_config,
	NULL,
	MODULE_LISTENER,
	MODULE_INFO,
	mod_run,
        mod_tick
	},
	process_call
};

static  pthread_rwlock_t        wccp2_config_lock;
static  int                     wccp2_socket = -1;
static  int                     tick_cnt;

typedef enum {
    HASH_DEST_IP    = 0x01,
    HASH_DEST_PORT  = 0x02,
    HASH_SOURCE_IP  = 0x04,
    HASH_SOURCE_PORT= 0x08
} hash_type_t;

typedef enum {
    Here_I_Am       = WCCP2_HERE_I_AM,
    I_See_You       = WCCP2_I_SEE_YOU,
    Redirect_Assign = WCCP2_REDIRECT_ASSIGN,
    Removal_Query   = WCCP2_REMOVAL_QUERY
} MessageType;

typedef struct  wccp2_web_cache_identity_element_ {
    uint32_t        WC_Address;
    uint16_t        HashRevision;
    uint16_t        U_Reserved;
    uint32_t        BucketBlock[8];
    uint16_t        AssignmentWeight;
    uint16_t        Status;
} web_cache_identity_element_t;

typedef struct  wccp2_router_ {
    char        name[MAX_ROUTERNAME_LEN+1];
    uint32_t    RouterID;
    uint32_t    ReceiveID;
    uint32_t    MemberChangeNumber;
    uint32_t    address;
    int         Num_Of_I_See_You;   /* To know how much answers we received         */
    int         hash_type;          /* can be combination of several hash_type_t    */
    int         forwarding_method;
    int         return_method;
    int         assignment_method;
} wccp2_router_t;

typedef struct  assignment_key_element_ {
    uint32_t        KeyIPAddress;
    uint32_t        KeyChangeNumber;
} assignment_key_element_t;

typedef struct  router_id_element_ {
    uint32_t        RouterID;
    uint32_t        ReceiveID;
} router_id_element_t;

typedef struct  router_view_ {
        router_id_element_t             Router;         /* his Id                       */
        uint32_t                        his_IP;         /* IP from which he answers     */
        uint32_t                        ChangeNumber;   /* received ChangeNumber        */
        assignment_key_element_t        AssignmentKey;  /* received AssKey              */
        int                             Usable;         /* Usable router                */
        uint32_t                        LastI_See_You;  /* When we received last ISY    */
        int                             n_routers;      /* number of routers he know about */
        uint32_t                        r_ID[32];       /* their Ip's                   */
        int                             n_caches;       /* num ov caches he know about  */
        web_cache_identity_element_t    c_ID[32];       /* their identities             */
} router_view_t;

typedef struct  view_routers_ {
        int                     n_routers;      /* number of known routers */
        router_view_t           r_views[32];    /* and their views         */
} view_routers_t;

typedef struct  cache_view_ {
        web_cache_identity_element_t    Cache;          /* his ID               */
        uint32_t                        ChangeNumber;   /* his ChangeNumber     */
        uint32_t                        Usable;         /* N of routers which know about this cache  */
        uint32_t                        n_routers;      /* n of known routers   */
        router_id_element_t             r_ID[32];       /* Their ID's           */
        uint32_t                        n_caches;       /* n of known caches    */
        uint32_t                        c_ID[32];       /* their IP's           */
} cache_view_t;

typedef struct  view_caches_ {
        int                     n_caches;       /* number of known caches */
        cache_view_t            c_views[32];    /* their views            */
} view_caches_t;

typedef struct  service_group_view_ {
        uint32_t                ChangeNumber;   /* my view change number         */
        view_routers_t          routers;        /* known routers and their views */
        view_caches_t           caches;         /* known caches and their views  */
} service_group_view_t;

typedef struct  wccp2_service_group_ {
    struct wccp2_service_group_ *next;
    /* config-time data         */
    int                             group_id;
    uint16_t                        port[8];
    int                             security_option;
    char                            password[9];

    /* routers in group         */
    int                             n_routers;
    wccp2_router_t                  routers[32];

    uint32_t                        ChangeNumber;
    /* caches in group          */
    int                             n_caches;
    web_cache_identity_element_t    caches[32];
    pthread_mutex_t                 view_lock;
    service_group_view_t            view;
} wccp2_service_group_t;

#define LOCK_VIEW(g)    pthread_mutex_lock(&g->view_lock);
#define UNLOCK_VIEW(g)  pthread_mutex_unlock(&g->view_lock);
static  wccp2_router_t  *router_by_ip(wccp2_service_group_t*, uint32_t);
static  router_view_t   *router_view_by_ip(wccp2_service_group_t*, uint32_t);
static  void            check_view(wccp2_service_group_t*);
static  int             known_router(uint32_t,  wccp2_service_group_t*);
static  int             cache_in_view(web_cache_identity_element_t*, wccp2_service_group_t*);
static  int             insert_cache_in_view(web_cache_identity_element_t*, wccp2_service_group_t*);
static  int             insert_router_in_config(uint32_t, wccp2_service_group_t*);

typedef struct  wccp2_cache_engine_ {
    char                identity[MAX_ROUTERNAME_LEN+1];
    struct sockaddr_in  ip_identity;
} wccp2_cache_engine_t;

static  wccp2_cache_engine_t    cache_engine;
static  wccp2_service_group_t   *service_groups, *config_service_group;
static  wccp2_service_group_t   *last_service_group;
static  int                     config_router_index;

static  void free_service_groups(void);
static  int  send_Here_I_Am(wccp2_service_group_t *g, wccp2_router_t *r);
typedef struct  wccp2_message_header_ {
    uint32_t    Type;
    uint16_t    Version;
    uint16_t    Length;
} wccp2_message_header_t;

wccp2_message_header_t              send_message_header;

typedef struct  wccp2_security_info_component_ {
    uint16_t    Type;
    uint16_t    Length;
    uint32_t    Security_Option;
    uint32_t    Secutity_Implementation[4];
} wccp2_security_info_component_t;

wccp2_security_info_component_t     send_security_info_component;

typedef struct  wccp2_service_info_component_ {
    uint16_t        Type;
    uint16_t        Length;
    unsigned char   Service_Type;
    unsigned char   Service_ID;
    unsigned char   Priority;
    unsigned char   Protocol;
    uint32_t        Service_Flags;
    uint16_t        Port[8];
} wccp2_service_info_component_t;

wccp2_service_info_component_t send_service_info_component;
static  wccp2_service_group_t* group_by_info(wccp2_service_info_component_t*);

typedef struct  wccp2_cache_identity_info_component_ {
    uint16_t                        Type;
    uint16_t                        Length;
    web_cache_identity_element_t    Identity;
} wccp2_cache_identity_info_component_t;

wccp2_cache_identity_info_component_t   send_cache_identity_info_component;

typedef struct  wccp2_cache_view_info_component_ {
    uint16_t        Type;
    uint16_t        Length;
    uint32_t        ChangeNumber;
    uint32_t        NumberOfRouters;
    uint32_t        fill[ 2*32 + 1 + 32 ];
} wccp2_cache_view_info_component_t;

wccp2_cache_view_info_component_t       send_cache_view_info_component;

typedef struct  router_assignment_element_ {
    uint32_t        RouterID;
    uint32_t        ReceiveID;
    uint32_t        ChangeNumber;
} router_assignment_element_t;

typedef struct  wccp2_router_identity_info_component_ {
    uint16_t        Type;
    uint16_t        Length;
    uint32_t        RouterID;
    uint32_t        ReceiveID;
    uint32_t        SentToAddress;
    uint32_t        NumberReceivedFrom;
    uint32_t        fill[32];
} wccp2_router_identity_info_component_t;

typedef struct  wccp2_router_view_component_ {
    uint16_t                    Type;
    uint16_t                    Length;
    uint32_t                    MemberChangeNumber;
    assignment_key_element_t    AssignKey;
    uint32_t                    NumberOfRouters;
    uint32_t                    fill[32 + 1 + 2*32];
} wccp2_router_view_component_t;

typedef struct  wccp2_cap_element_ {
    uint16_t        Type;
    uint16_t        Length;
    uint32_t        Value;
} wccp2_cap_element_t;

typedef struct  wccp2_cap_info_component_ {
    uint16_t                Type;
    uint16_t                Length;
    wccp2_cap_element_t     Forwarding;
    wccp2_cap_element_t     Assignment;
    wccp2_cap_element_t     PacketReturn;
} wccp2_cap_info_component_t;

wccp2_cap_info_component_t  send_cap_info_component;

typedef struct  wccp2_assignment_info_component_ {
    uint16_t                    Type;
    uint16_t                    Length;
    assignment_key_element_t    AssignmentKey;
    uint32_t                    NumberOfRouters;
    uint32_t                    fill[3*32 + 1 + 32 + 64];
} wccp2_assignment_info_component_t;

wccp2_assignment_info_component_t   send_assignment_component;

#define WRLOCK_WCCP2_CONFIG   pthread_rwlock_wrlock(&wccp2_config_lock)
#define RDLOCK_WCCP2_CONFIG   pthread_rwlock_rdlock(&wccp2_config_lock)
#define UNLOCK_WCCP2_CONFIG   pthread_rwlock_unlock(&wccp2_config_lock)

static	int	Send_Redirect_Assignment(wccp2_service_group_t *g, wccp2_router_t *r);


MODULE_STATIC
int
mod_load(void)
{
    pthread_rwlock_init(&wccp2_config_lock, NULL);
    service_groups = NULL;
    tick_cnt = 0;

    printf("WCCP2 started\n");

    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_unload(void)
{
    WRLOCK_WCCP2_CONFIG ;
    printf("WCCP2 Stopped\n");
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_beg(int i)
{
    wccp2_socket = -1;
    free_service_groups();
    config_service_group = NULL;
    last_service_group = NULL;
    config_router_index = 0;
    bzero(&cache_engine, sizeof(cache_engine));
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config(char *config, int i)
{
int     words;
char    *vector[10], *orig = NULL;

    orig = strdup(config);
    words = word_vector(config, " \t\n", (char **)&vector[0], 10);
    if ( words < 0 )
        goto error;
    printf ("Words: %d\n", words);
    if ( words > 0 ) {
        if ( !strncasecmp(vector[0], "identity", 4) ) {
            if ( words < 2 ) {
                printf("hostname or ip expected after 'identity' in line '%s'\n", orig);
                goto error;
            }
            bzero(&cache_engine.identity, sizeof(cache_engine.identity));
            strncpy(&cache_engine.identity[0], vector[1], sizeof(cache_engine.identity)-1);
            printf("identity: %s\n", cache_engine.identity);
        }
        if ( !strncasecmp(vector[0], "service-group", 4) ) {
            char        *password = "";
            u_short     port[8] = {0,0,0,0,0,0,0,0};
            int         group_id = 0;
            int         index;

            if ( config_service_group != 0 ) {
                /* insert configured service group in list  */
                if ( NULL == service_groups ) {
                    service_groups = config_service_group;
                    last_service_group = config_service_group;
                } else {
                /* insert                                   */
                    last_service_group->next = config_service_group;
                    last_service_group = config_service_group;
                }
            }
            if ( words < 2 ) {
                printf("Incomplete command'%s'\n", orig);
                goto error;
            }
            index = 1;
            if ( !strncasecmp(vector[index], "web-cache", 2) ) {
                group_id = 0;
                port[0] = 80;
            } else
            if ( (group_id = atoi(vector[index])) == 0 ) {
                printf("web-cache or number expected, got: '%s'\n", vector[index]);
                goto error;
            }
            index++;
            if ( index>= words ) goto do_group;
            if ( !strncasecmp(vector[index], "port", 2) ) {
                int     i;
                char    *t, *p, *tptr;

                index++;
                p = vector[index];
                for (i=0; i<8; i++) {
                    t = strtok_r(p, ",", &tptr);
                    if ( !t ) break;
                    p = NULL;
                    port[i] = (u_short)atoi(t);
                    printf("port: %d\n", port[i]);
                }

            } else {
                printf("word 'port' expected after 'service-group', but we have '%s'\n", vector[1]);
                goto error;
            }
            index++;
            if ( words <= index ) goto do_group;
            if ( !strncasecmp(vector[index], "password", 2) ) {
                if ( words >= 5 ) {
                    printf(" pass: %s\n", vector[4]);
                    password = vector[4];
                } else {
                    printf("password expected after 'password' in '%s'\n",  orig);
                }
            } else {
                printf("word 'password' expected after 'port NUM', but we have '%s'\n", vector[3]);
                goto error;
            }
    do_group:
            config_service_group = calloc(1, sizeof(*config_service_group));
            if ( !config_service_group ) {
                printf("No mem for new service group\n");
                goto error;
            }
            memcpy(config_service_group->port, port, sizeof(port));
            config_service_group->group_id = group_id;
            config_service_group->n_routers = 0;
            config_service_group->ChangeNumber = 1;
            config_service_group->n_caches = 1;
            pthread_mutex_init(&config_service_group->view_lock, NULL);
            bzero(&config_service_group->password[0], 9);
            strncpy(&config_service_group->password[0], password, 8);
            if ( 0 != password[0] )
                config_service_group->security_option = WCCP2_MD5_SECURITY;
              else
                config_service_group->security_option = WCCP2_NO_SECURITY;
            config_router_index = 0;
        }
        if ( !strncasecmp(vector[0], "router", 3) ) {
            wccp2_router_t    *router;

            if ( NULL == config_service_group ) {
                printf("Router must be configured inside service-group\n");
                goto error;
            }
            printf(" router[%d]: %s\n", config_router_index, vector[1]);
            router = &config_service_group->routers[config_router_index];
            strncpy(&router->name[0], vector[1], MAX_ROUTERNAME_LEN);
            router->name[MAX_ROUTERNAME_LEN]=0;
            router->ReceiveID = 0;
            /* set up some default values               */
            /* use HASH by default                      */
            router->assignment_method = WCCP2_ASSIGNMENT_METHOD_HASH;
            /* use L2 forwarding by default             */
            /* that is Cache must be directly reachable */
            /* from router (same Ethernet segment?)     */
            router->forwarding_method = WCCP2_FORWARDING_METHOD_L2;
            /* we never returnpackets, but something    */
            /* must be used                             */
            router->return_method = WCCP2_PACKET_RETURN_METHOD_L2;
            /* to next                      */
            config_router_index++;
            config_service_group->n_routers++;
        }
    }
done:
    free_word_vector((char **)&vector[0], words);
    if ( orig ) free(orig);
    return(MOD_CODE_OK);
error:
    free_word_vector((char **)&vector[0], words);
    if ( orig) free(orig);
    return(MOD_CODE_ERR);
}

MODULE_STATIC
int
mod_config_end(int i)
{
    if ( config_service_group != 0 ) {
        /* insert configured service group in list  */
        if ( NULL == service_groups ) {
            service_groups = config_service_group;
            last_service_group = config_service_group;
        } else {
        /* insert                                   */
            last_service_group->next = config_service_group;
            last_service_group = config_service_group;
        }
    }
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_run(void)
{
wccp2_service_group_t   *g;
wccp2_router_t          *r;
struct  sockaddr_in     wccp2_bind_sa;
int                     rc;
#if defined(LINUX) && defined(IP_PMTUDISC_DONT)
int                     sockopt_val;
#endif

    if ( !service_groups )
        return(MOD_CODE_OK);
    wccp2_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( wccp2_socket == -1 ) {
        fprintf(stderr, "Can't create wccp socket: %s\n", strerror(errno));
        return(MOD_CODE_ERR);
    }
#if defined(LINUX) && defined(IP_PMTUDISC_DONT)
    /* Linux 2.4 does not set IP IDs on UDP packets with DF flag by default,
     * force it to do so as Cisco does not like it */
    sockopt_val=IP_PMTUDISC_DONT;
    setsockopt(wccp2_socket, SOL_IP, IP_MTU_DISCOVER, (char*)&sockopt_val, sizeof(sockopt_val));
#endif
    fcntl(wccp2_socket, F_SETFL, fcntl(wccp2_socket, F_GETFL, 0)|O_NONBLOCK);
    /* bind to port */
    bzero(&wccp2_bind_sa, sizeof(wccp2_bind_sa));
    wccp2_bind_sa.sin_family = AF_INET;
    wccp2_bind_sa.sin_port = htons(WCCP2_PORT);
    wccp2_bind_sa.sin_addr.s_addr = INADDR_ANY;
#if     !defined(SOLARIS) && !defined(LINUX) && !defined(OSF) && !defined(_WIN32)
    wccp2_bind_sa.sin_len = sizeof(wccp2_bind_sa);
#endif
    rc = bind(wccp2_socket, (struct sockaddr*)&wccp2_bind_sa, sizeof(wccp2_bind_sa));
    if ( rc == -1 ) {
        fprintf(stderr, "Can't create bind socket: %s\n", strerror(errno));
        return(MOD_CODE_ERR);
    }
    add_socket_to_listen_list(wccp2_socket, 0, 0,
        LISTEN_AND_NO_ACCEPT|LISTEN_AND_DO_SYNC, &process_call);

    g = service_groups;
    while ( g ) {
        int i;
        for (i=0;i<g->n_routers;i++) {
            r = &g->routers[i];
            send_Here_I_Am(g, r);
        }
        g = g->next;
    }
    return(MOD_CODE_OK);
}

static int
I_Am_Designated_Cache(wccp2_service_group_t *g)
{
int         i;
uint32_t    my_ip;

    assert(g != NULL);

    /* 
        check if we received I_See_You from all routers in group
        WCCP2 draft, section 4.9
    for(i=0;i < g->n_routers ; i++) {
        if ( g->routers[i].Num_Of_I_See_You == 0 )
            return(FALSE);
    }
    */

    if ( g->view.caches.n_caches <= 0 )
        return(FALSE);

    if ( g->view.caches.n_caches == 1 )
        return(TRUE);

    my_ip = ntohs(cache_engine.ip_identity.sin_addr.s_addr);

    for(i=1; i < g->view.caches.n_caches; i++ ) {
        if (g->view.caches.c_views[i].Cache.WC_Address == 0)
            continue;   /* this is empty */
        if ( ntohs(g->view.caches.c_views[i].Cache.WC_Address) < my_ip )
            return(FALSE);
    }
    return(TRUE);
}

MODULE_STATIC
int
mod_tick(void)
{
    tick_cnt++;
    if ( 0 == (tick_cnt % 10) ) {
        wccp2_service_group_t   *g;
        wccp2_router_t          *r;

        g = service_groups;
        while ( g ) {
            int i;
            LOCK_VIEW(g);
            check_view(g);

            for (i=0;i<g->n_routers;i++) {
                r = &g->routers[i];
                send_Here_I_Am(g, r);
                if ( I_Am_Designated_Cache(g) ) {
                    Send_Redirect_Assignment(g, r);
                }
            }
            UNLOCK_VIEW(g);
            g = g->next;
        }
    }
    return(0);
}

MODULE_STATIC
void*
process_call(void *arg)
{
char                            buf[16*1024];
struct  sockaddr_in             source;
socklen_t                       source_len = sizeof(source);
int                             rc, Length, i, NumOfCaches;
char                            *position, *end;
uint16_t                        *portP;
uint32_t                        *fillP;
MessageType                     MType;
wccp2_service_group_t           *group;
wccp2_router_t                  *r;
router_view_t                   *router;
wccp2_message_header_t                  *hdr;
wccp2_security_info_component_t         *sec_hdr;
wccp2_service_info_component_t          *serv_hdr;
wccp2_router_identity_info_component_t  *rid_hdr;
wccp2_router_view_component_t           *rtr_view;
wccp2_cap_info_component_t              *cap_info;
web_cache_identity_element_t            *cache_element;

    rc = recvfrom(wccp2_socket, &buf[0], sizeof(buf), 0,
                (struct sockaddr*)&source, &source_len);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Source: %s\n", inet_ntoa(source.sin_addr));
    if ( rc == -1 ) {
        printf("wccp2.c:process_call():errno: %d\n", errno);
        return(MOD_CODE_OK);
    }
    position = &buf[0];
    hdr = (wccp2_message_header_t*)&buf[0];
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Type   : %d\n", ntohl(hdr->Type));
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Version: %d\n", ntohs(hdr->Version));
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Length : %d\n", ntohs(hdr->Length));
    if ( ntohs(hdr->Version) != 0x0200 ) {
        my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Invalid wccp version\n");
        return(MOD_CODE_OK);
    }
    Length = ntohs(hdr->Length);
    if ( Length + 8 != rc ) {
        my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Invalid wccp packet length\n");
        return(MOD_CODE_OK);
    }
    MType = ntohl(hdr->Type);
    position += 8;
    end = position + Length;
    sec_hdr = (wccp2_security_info_component_t*)(position);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Sec. Type: %d\n", ntohs(sec_hdr->Type));
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Sec. Leng: %d\n", ntohs(sec_hdr->Length));
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Sec. Optn: %d\n", ntohl(sec_hdr->Security_Option));
    if ( htonl(sec_hdr->Security_Option) != 0 ) {
        assert(0);
    } else {
        position += 8;
    }
    serv_hdr = (wccp2_service_info_component_t*)position;
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Serv. Type: %d\n", ntohs(serv_hdr->Type));
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Serv. Leng: %d\n", ntohs(serv_hdr->Length));
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Service_Type: %d\n", serv_hdr->Service_Type);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Service_ID  : %d\n", serv_hdr->Service_ID);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Priority    : %d\n", serv_hdr->Priority);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Protocol    : %d\n", serv_hdr->Protocol);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): ServiceFlags: %d\n", ntohl(serv_hdr->Service_Flags));
    portP = (uint16_t*)(position+12);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Ports: %d %d %d %d\n",
        ntohs(*portP), ntohs(*(portP+1)), 
        ntohs(*(portP+2)),ntohs(*(portP+3)));
    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Ports: %d %d %d %d\n",
        ntohs(*(portP+4)), ntohs(*(portP+5)), 
        ntohs(*(portP+6)), ntohs(*(portP+7)));
    /* We can now locate service_group by port */
    group = group_by_info(serv_hdr);
    if ( !group ) {
        my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): No group\n");
        return(MOD_CODE_OK);
    }
    position += sizeof(wccp2_service_info_component_t);
    LOCK_VIEW(group);
    switch(MType) {
        int OldReceiveID;
        case(I_See_You):
            r = router_by_ip(group, source.sin_addr.s_addr);
            router = router_view_by_ip(group, source.sin_addr.s_addr);
            if ( !router ) {
                router = &group->view.routers.r_views[group->view.routers.n_routers];
                router->his_IP = source.sin_addr.s_addr;
                group->view.routers.n_routers++;
                my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Add router to view: n_routers = %d\n", group->view.routers.n_routers);
            }
            if ( !r ) {
                /* it can be found after inserting in view. If not: fail */
                r = router_by_ip(group, source.sin_addr.s_addr);
                if ( !r ) {
                    char        *name = NULL;
                    name = my_inet_ntoa(&source);
                    if ( name ) {
                        my_xlog(OOPS_LOG_SEVERE, "wccp2.c:process_call(): I_See_You from unknown router %s\n", name);
                        free(name);
                    } else {
                        my_xlog(OOPS_LOG_SEVERE, "wccp2.c:process_call(): I_See_You from unknown router %0x\n",
                                ntohl(source.sin_addr.s_addr));
                    }
                }
            }	
            /*router->Num_Of_I_See_You++;*/
            router->LastI_See_You = global_sec_timer;
            OldReceiveID = router->Router.ReceiveID;
            rid_hdr = (wccp2_router_identity_info_component_t*)position;
            my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): I See You\n");
            my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Router ID info:\n");
            my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Type: %d\n", ntohs(rid_hdr->Type));
            if ( htons(rid_hdr->Type) != WCCP2_ROUTER_ID_INFO ) {
                break;
            }
            my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Leng: %d\n", ntohs(rid_hdr->Length));
            my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): IP:   %u.%u.%u.%u\n",
                (rid_hdr->RouterID & 0xff000000)>>24,
                (rid_hdr->RouterID & 0x00ff0000)>>16,
                (rid_hdr->RouterID & 0x0000ff00)>>8,
                rid_hdr->RouterID & 0x000000ff);
            my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): ReceiveID: 0x%x\n", ntohl(rid_hdr->ReceiveID));
            /* update router info */
            router->Router.ReceiveID = ntohl(rid_hdr->ReceiveID);
            router->Router.RouterID = rid_hdr->RouterID;
            my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): SentToAddress: %u.%u.%u.%u\n",
                (rid_hdr->SentToAddress & 0xff000000)>>24,
                (rid_hdr->SentToAddress & 0x00ff0000)>>16,
                (rid_hdr->SentToAddress & 0x0000ff00)>>8,
                rid_hdr->SentToAddress & 0x000000ff);
            my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): NumberReceivedFrom: %d\n", ntohl(rid_hdr->NumberReceivedFrom));
            for (i=0;i<ntohl(rid_hdr->NumberReceivedFrom);i++) {
                my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): ReceivedFrom: %u.%u.%u.%u\n",
                    (rid_hdr->fill[i] & 0xff000000)>>24,
                    (rid_hdr->fill[i] & 0x00ff0000)>>16,
                    (rid_hdr->fill[i] & 0x0000ff00)>>8,
                    rid_hdr->fill[i] & 0x000000ff);
            }
            position += ntohs(rid_hdr->Length) + 4;
            rtr_view = (wccp2_router_view_component_t*)position;
            if ( router->ChangeNumber != ntohl(rtr_view->MemberChangeNumber) ) {
                /* his view changed     */
                router->ChangeNumber = ntohl(rtr_view->MemberChangeNumber);
                my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewType: %d\n", ntohs(rtr_view->Type));
                my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewLeng: %d\n", ntohs(rtr_view->Length));
                my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewMemberChange: 0x%0x\n", ntohl(rtr_view->MemberChangeNumber));
                my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewMemberAssKeyIP: 0x%x\n", ntohl(rtr_view->AssignKey.KeyIPAddress));
                my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewMemberAssKeyChangeNum: 0x%0x\n", ntohl(rtr_view->AssignKey.KeyChangeNumber));
                router->AssignmentKey = rtr_view->AssignKey;
                router->n_routers = rtr_view->NumberOfRouters; /* in netw order */
                my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewNumberOfRouters: %d\n", ntohl(rtr_view->NumberOfRouters));
                fillP = &rtr_view->fill[0];
                for(i=0;i<ntohl(rtr_view->NumberOfRouters);i++) {
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewRouter: %0x\n", *fillP);
                    router->r_ID[i] = *fillP;
                    if ( !known_router(router->r_ID[i], group) ) {
                        my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): UNKNOWN ROUTER, go insert it\n");
                        insert_router_in_config(router->r_ID[i], group);
                    }
                    fillP++;
                }
                router->n_caches = *fillP; /* in netw order  */
                NumOfCaches = ntohl(*fillP);
                fillP++;
                cache_element = (web_cache_identity_element_t*)fillP;
                my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewNumberOfWebCaches: %d\n", NumOfCaches);
                for(i=0;i<NumOfCaches;i++) {
                    router->c_ID[i] = *cache_element;
                    if ( !cache_in_view(cache_element, group) )
                        insert_cache_in_view(cache_element, group);
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElWC_A :  0x%0x\n", ntohl(cache_element->WC_Address));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElHR   :  0x%0x\n", ntohs(cache_element->HashRevision));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElUr   :  %d\n", ntohs(cache_element->U_Reserved));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElBB[0]:  %0x\n", ntohl(cache_element->BucketBlock[0]));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElBB[1]:  %0x\n", ntohl(cache_element->BucketBlock[1]));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElBB[2]:  %0x\n", ntohl(cache_element->BucketBlock[2]));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElBB[3]:  %0x\n", ntohl(cache_element->BucketBlock[3]));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElBB[4]:  %0x\n", ntohl(cache_element->BucketBlock[4]));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElBB[5]:  %0x\n", ntohl(cache_element->BucketBlock[5]));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElBB[6]:  %0x\n", ntohl(cache_element->BucketBlock[6]));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElBB[7]:  %0x\n", ntohl(cache_element->BucketBlock[7]));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElWeight:  %0x\n", ntohl(cache_element->AssignmentWeight));
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): RtrViewCacheElStatus:  %0x\n", ntohl(cache_element->Status));
                    cache_element++;
                }
                check_view(group);
            }
            router->Usable = TRUE;
            position += ntohs(rtr_view->Length) + 4;
            cap_info = (wccp2_cap_info_component_t*)position;
            if ( OldReceiveID != router->Router.ReceiveID - 1) {
                send_Here_I_Am(group, r);
                if ( I_Am_Designated_Cache(group) ) {
                        Send_Redirect_Assignment(group, r);
                }
            } else {
                my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): OldReceiveID=%0x, router->Router.ReceiveID=%0x\n", OldReceiveID,
                                router->Router.ReceiveID);
            }
            break;
        default:
            my_xlog(OOPS_LOG_DBG, "wccp2.c:process_call(): Invalid message type: %d\n", MType);
            break;
    }
    UNLOCK_VIEW(group);
    return(MOD_CODE_OK);
}

static int
send_Here_I_Am(wccp2_service_group_t *g, wccp2_router_t *r)
{
struct  sockaddr_in     router_addr;
int                     rc, so, i;
struct  iovec           HIA[6];
struct	msghdr	        msg;
router_id_element_t     *router;
uint32_t                *filler;
web_cache_identity_element_t *scache, *dcache;

    my_xlog(OOPS_LOG_DBG, "wccp2.c:send_Here_I_Am(): send_Here_I_Am(): to %s\n", r->name);
    so = wccp2_socket;
    if ( -1 == so ) {
        my_xlog(OOPS_LOG_DBG, "send_Here_I_Am(): socket(): %m\n");
        return(-1);
    }
    rc = str_to_sa(r->name, (struct sockaddr*)&router_addr);
    if ( rc != 0 ) {
        my_xlog(OOPS_LOG_DBG, "send_Here_I_Am(): can't resolve %s\n", r->name);
        return(-1);
    }
    r->address = router_addr.sin_addr.s_addr;
    router_addr.sin_port = htons(WCCP2_PORT);
    bzero(&msg, sizeof(msg));
    msg.msg_name    = (void*)&router_addr;
    msg.msg_namelen = sizeof(router_addr);
    msg.msg_iov = &HIA[0];
    msg.msg_iovlen = 6;

    /* fill components */
    /* Message Header                                       */
    send_message_header.Type=htonl(WCCP2_HERE_I_AM);
    send_message_header.Version=htons(0x200);
    send_message_header.Length=0;
    HIA[0].iov_base = (char*)&send_message_header;
    HIA[0].iov_len = 8;

    /* Security Info Component                              */
    if ( 0 == g->password[0] ) {
        send_security_info_component.Type=htons(WCCP2_SECURITY_INFO);
        send_security_info_component.Length=htons(4);
        send_security_info_component.Security_Option=htonl(WCCP2_NO_SECURITY);
        HIA[1].iov_base = (char*)&send_security_info_component;
        HIA[1].iov_len = 8;
        send_message_header.Length += HIA[1].iov_len;
    } else {
        abort();
    }

    /* service Info Component                               */
    bzero(&send_service_info_component, sizeof(send_service_info_component));
    send_service_info_component.Type = htons(WCCP2_SERVICE_INFO);    
    send_service_info_component.Length = htons(sizeof(send_service_info_component)-4);
    if ( g->group_id == 0 ) {
        send_service_info_component.Service_Type = WCCP2_SERVICE_STANDARD;
        send_service_info_component.Service_ID = 0;
        HIA[2].iov_base = (char*)&send_service_info_component;
        HIA[2].iov_len = sizeof(send_service_info_component);
        send_message_header.Length += HIA[2].iov_len;
    } else {
        send_service_info_component.Service_Type = WCCP2_SERVICE_DYNAMIC;
        send_service_info_component.Service_ID = g->group_id;
        send_service_info_component.Service_Flags |=  htons(PortsDefined);
        send_service_info_component.Protocol = 6; /* TCP */
        send_service_info_component.Port[0] = htons(g->port[0]);
        send_service_info_component.Port[1] = htons(g->port[1]);
        send_service_info_component.Port[2] = htons(g->port[2]);
        send_service_info_component.Port[3] = htons(g->port[3]);
        send_service_info_component.Port[4] = htons(g->port[4]);
        send_service_info_component.Port[5] = htons(g->port[5]);
        send_service_info_component.Port[6] = htons(g->port[6]);
        send_service_info_component.Port[7] = htons(g->port[7]);
        HIA[2].iov_base = (char*)&send_service_info_component;
        HIA[2].iov_len = sizeof(send_service_info_component);
        send_message_header.Length += HIA[2].iov_len;
    }

    /* web cache identity info component                    */
    if ( 0 == cache_engine.ip_identity.sin_addr.s_addr ) {
        struct  sockaddr_in ip_id;
        if ( cache_engine.identity[0] )
            str_to_sa(cache_engine.identity, (struct sockaddr*)&cache_engine.ip_identity);
          else {
            str_to_sa(host_name, (struct sockaddr*)&cache_engine.ip_identity);
        }
        g->caches[0].WC_Address = cache_engine.ip_identity.sin_addr.s_addr;
    }

    bzero(&send_cache_identity_info_component, sizeof(send_cache_identity_info_component));
    send_cache_identity_info_component.Type = htons(WCCP2_WC_ID_INFO);
    send_cache_identity_info_component.Length = htons(sizeof(send_cache_identity_info_component) - 4);
    send_cache_identity_info_component.Identity.WC_Address = cache_engine.ip_identity.sin_addr.s_addr;
    my_xlog(OOPS_LOG_DBG, "wccp2.c:send_Here_I_Am(): <<<WCID.WCAddr>>>:   0x%0x\n", ntohl(send_cache_identity_info_component.Identity.WC_Address));

    HIA[3].iov_base = (char*)&send_cache_identity_info_component;
    HIA[3].iov_len = sizeof(send_cache_identity_info_component);
    send_message_header.Length += HIA[3].iov_len;

    /* web cache view info component                        */
    send_cache_view_info_component.Type = htons(WCCP2_WC_VIEW_INFO);
    send_cache_view_info_component.Length = (uint16_t)
            htons(8 + g->view.routers.n_routers*8 + 4 + 
                g->view.caches.n_caches*4);
    send_cache_view_info_component.ChangeNumber = htonl(g->ChangeNumber);
    send_cache_view_info_component.NumberOfRouters = htonl(g->view.routers.n_routers);
    filler = &send_cache_view_info_component.fill[0];
    for (i = 0;i<g->view.routers.n_routers;i++) {
        router = &g->view.routers.r_views[i].Router;
        str_to_sa(r->name, (struct sockaddr*)&router_addr);
        *filler = router->RouterID;
        filler++;
        *filler = htonl(router->ReceiveID);
        filler++;
    }
    *filler = htonl(g->view.caches.n_caches);
    filler++;

    dcache = (web_cache_identity_element_t*)filler;
    for (i = 0;i<g->view.caches.n_caches;i++) {
        scache = &g->view.caches.c_views[i].Cache;
        *filler = scache->WC_Address;
        dcache++;
        filler++;
    }


    HIA[4].iov_base = (char*)&send_cache_view_info_component;
    HIA[4].iov_len = 4 + 8 + g->view.routers.n_routers*8 + 4 +
                             g->view.caches.n_caches*4;
    send_message_header.Length += HIA[4].iov_len;

    send_cap_info_component.Type  = htons(WCCP2_CAPABILITY_INFO);
    send_cap_info_component.Length= htons(sizeof(send_cap_info_component)-4);
    send_cap_info_component.Forwarding.Type=htons(WCCP2_FORWARDING_METHOD);
    send_cap_info_component.Forwarding.Length = htons(4);
    send_cap_info_component.Forwarding.Value = htonl(r->forwarding_method);
    send_cap_info_component.Assignment.Type=htons(WCCP2_ASSIGNMENT_METHOD);
    send_cap_info_component.Assignment.Length = htons(4);
    send_cap_info_component.Assignment.Value = htonl(r->assignment_method);
    send_cap_info_component.PacketReturn.Type=htons(WCCP2_PACKET_RETURN_METHOD);
    send_cap_info_component.PacketReturn.Length = htons(4);
    send_cap_info_component.PacketReturn.Value = htonl(r->return_method);
    HIA[5].iov_base = (char*)&send_cap_info_component;
    HIA[5].iov_len  = sizeof(send_cap_info_component);
    send_message_header.Length += HIA[5].iov_len;
    send_message_header.Length = htons(send_message_header.Length);
#if     defined(SOLARIS_)
    rc = connect(so, (struct sockaddr*)&router_addr, sizeof(router_addr));
    if ( rc == -1 ) perror("connect");
    rc = writev(so, &HIA[0], 6);
    if ( rc == -1 ) perror("writev");
#else
    rc = sendmsg(so, &msg, 0);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:send_Here_I_Am(): writev(): %d\n", rc);
    if ( rc == -1 ) perror("sendmsg");
#endif
    return(0);
}

static int
Send_Redirect_Assignment(wccp2_service_group_t *g, wccp2_router_t *r)
{
struct  sockaddr_in     router_addr;
int                     rc, so, i;
struct  iovec           RA[4];
struct	msghdr	        msg;
uint32_t                *filler;
router_assignment_element_t     *rae;
u_char                  *bucket;

    assert( g != NULL );
    assert( r != NULL );

    my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): send_redirect_Assignment(): to %s\n", r->name);
    so = wccp2_socket;
    str_to_sa(r->name, (struct sockaddr*)&router_addr);
    router_addr.sin_port = htons(WCCP2_PORT);
    bzero(&msg, sizeof(msg));
    msg.msg_name    = (void*)&router_addr;
    msg.msg_namelen = sizeof(router_addr);
    msg.msg_iov = &RA[0];
    msg.msg_iovlen = 4;

    /* fill components */
    /* Message Header                                       */
    send_message_header.Type=htonl(WCCP2_REDIRECT_ASSIGN);
    send_message_header.Version=htons(0x200);
    send_message_header.Length=0;
    RA[0].iov_base = (char*)&send_message_header;
    RA[0].iov_len = 8;

    /* Security Info Component                              */
    if ( 0 == g->password[0] ) {
        send_security_info_component.Type=htons(WCCP2_SECURITY_INFO);
        send_security_info_component.Length=htons(4);
        send_security_info_component.Security_Option=htonl(WCCP2_NO_SECURITY);
        RA[1].iov_base = (char*)&send_security_info_component;
        RA[1].iov_len = 8;
        send_message_header.Length += RA[1].iov_len;
    } else {
        abort();
    }

    /* service Info Component                               */
    bzero(&send_service_info_component, sizeof(send_service_info_component));
    send_service_info_component.Type = htons(WCCP2_SERVICE_INFO);
    send_service_info_component.Length = htons(sizeof(send_service_info_component)-4);
    if ( g->group_id == 0 ) {
        send_service_info_component.Service_Type = WCCP2_SERVICE_STANDARD;
        send_service_info_component.Service_ID = 0;
        RA[2].iov_base = (char*)&send_service_info_component;
        RA[2].iov_len = sizeof(send_service_info_component);
        send_message_header.Length += RA[2].iov_len;
    } else {
        send_service_info_component.Service_Type = WCCP2_SERVICE_DYNAMIC;
        send_service_info_component.Service_ID = g->group_id;
        send_service_info_component.Service_Flags |=  htons(PortsDefined);
        send_service_info_component.Protocol = 6; /* TCP */
        send_service_info_component.Port[0] = htons(g->port[0]);
        send_service_info_component.Port[1] = htons(g->port[1]);
        send_service_info_component.Port[2] = htons(g->port[2]);
        send_service_info_component.Port[3] = htons(g->port[3]);
        send_service_info_component.Port[4] = htons(g->port[4]);
        send_service_info_component.Port[5] = htons(g->port[5]);
        send_service_info_component.Port[6] = htons(g->port[6]);
        send_service_info_component.Port[7] = htons(g->port[7]);
        RA[2].iov_base = (char*)&send_service_info_component;
        RA[2].iov_len = sizeof(send_service_info_component);
        send_message_header.Length += RA[2].iov_len;
    }

    bzero(&send_assignment_component, sizeof(send_assignment_component));
    send_assignment_component.Type = htons(WCCP2_REDIRECT_ASSIGNMENT);
    send_assignment_component.Length = htons( 8 + 4 +
                sizeof(router_assignment_element_t)*g->view.routers.n_routers + 4 +
                4*g->view.caches.n_caches + 256);

    my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): AssInfo.Type:   0x%x\n", WCCP2_REDIRECT_ASSIGNMENT);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): AssInfo.Leng:   0x%x\n", ntohs(send_assignment_component.Length));

    send_assignment_component.AssignmentKey.KeyIPAddress = cache_engine.ip_identity.sin_addr.s_addr;
    send_assignment_component.AssignmentKey.KeyChangeNumber = htonl(g->view.ChangeNumber);
    send_assignment_component.NumberOfRouters = htonl(g->view.routers.n_routers);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): AssInfo.Key.IP:   0x%x\n", ntohl(send_assignment_component.AssignmentKey.KeyIPAddress));
    my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): AssInfo.Key.CN:   0x%x\n", ntohl(send_assignment_component.AssignmentKey.KeyChangeNumber));
    my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): AssInfo.No of R:   0x%x\n", ntohl(send_assignment_component.NumberOfRouters));
    
    rae = (router_assignment_element_t*)&send_assignment_component.fill[0];
    for(i=0;i<g->view.routers.n_routers;i++) {
        rae->RouterID = g->view.routers.r_views[i].Router.RouterID;
        rae->ReceiveID= htonl(g->view.routers.r_views[i].Router.ReceiveID+1);
        rae->ChangeNumber = htonl(g->view.routers.r_views[i].ChangeNumber);
        my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): AssInfo.RAE.RoID:   0x%0x\n", ntohl(rae->RouterID));
        my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): AssInfo.RAE.ReID:   0x%0x\n", ntohl(rae->ReceiveID+1));
        my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): AssInfo.RAE.ChNu:   0x%0x\n", ntohl(rae->ChangeNumber));

        rae++;
    }

    filler = (uint32_t*)rae;
    *filler = htonl(g->view.caches.n_caches);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): AssInfo.Ncaches:   0x%0x\n", ntohl(*filler));
    filler++;

    for(i=0; i<g->view.caches.n_caches ;i++) {
        *filler = g->view.caches.c_views[i].Cache.WC_Address;
        my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): AssInfo.WCAddr:   0x%0x\n", ntohl(*filler));
        filler++;
    }

    bucket = (u_char*)filler;
    for (i=0;i<256;i++) {
        *bucket = i % g->view.caches.n_caches;

        ++bucket;
    }

    RA[3].iov_base = (char*)&send_assignment_component;
    RA[3].iov_len = 4 + ntohs(send_assignment_component.Length);
    send_message_header.Length += RA[3].iov_len;

    send_message_header.Length = htons(send_message_header.Length);

#if     defined(SOLARIS_)
    rc = connect(so, (struct sockaddr*)&router_addr, sizeof(router_addr));
    if ( rc == -1 ) perror("connect");
    rc = writev(so, &RA[0], 4);
    if ( rc == -1 ) perror("writev");
#else
    rc = sendmsg(so, &msg, 0);
    my_xlog(OOPS_LOG_DBG, "wccp2.c:Send_Redirect_Assignment(): writev(): %d\n", rc);
    if ( rc == -1 ) perror("sendmsg");
#endif
    return(0);
}

static wccp2_service_group_t*
group_by_info(wccp2_service_info_component_t *info)
{
wccp2_service_group_t  *res = NULL, *g = service_groups;

    while ( g ) {
        if ( (info->Service_Type == WCCP2_SERVICE_STANDARD) 
                && (g->group_id == 0))
            return(g);
        if ( (info->Service_Type == WCCP2_SERVICE_DYNAMIC)
                && (g->group_id == info->Service_ID) )
            return(g);
        g = g->next;
    }
    return(res);
}

static wccp2_router_t*
router_by_ip(wccp2_service_group_t* g, uint32_t addr)
{
int i;

    assert(g != NULL);
    for(i=0;i<g->n_routers;i++) {
        if ( addr == g->routers[i].address ) {
            return(&g->routers[i]);
        }
    }
    for(i=0;i<g->view.routers.n_routers;i++) {
        if ( addr == g->view.routers.r_views[i].his_IP ) {
            return(&g->routers[i]);
        }
    }
    return(NULL);
}

static router_view_t*
router_view_by_ip(wccp2_service_group_t* g, uint32_t addr)
{
int i;

    assert(g != NULL);
    for(i=0;i<g->view.routers.n_routers;i++) {
        if (    (addr == g->view.routers.r_views[i].Router.RouterID) 
             || (addr == g->view.routers.r_views[i].his_IP) ) {
            return(&g->view.routers.r_views[i]);
        }
    }
    return(NULL);
}


static int
known_router(uint32_t ID, wccp2_service_group_t *g)
{
int     i;

    assert( g != NULL);
    assert( g->view.routers.n_routers >= 0 );
    if ( g->n_routers == 0 ) return(FALSE);
    for (i=0; i<32; i++) {
        if ( (g->routers[i].RouterID == ID)
                ||  (g->routers[i].address == ID))
                return(TRUE);
    }
    for (i=0; i<g->view.routers.n_routers; i++) {
        if ( g->view.routers.r_views[i].Router.RouterID == ID )
                return(TRUE);
    }
    return(FALSE);
}

static int
cache_in_view(web_cache_identity_element_t *c, wccp2_service_group_t *g)
{
int i;

    assert( c != NULL);
    assert( g != NULL);
    assert( g->view.caches.n_caches >= 0 );
    if ( g->view.caches.n_caches == 0 ) return(FALSE);
    for ( i = 0; i < 32 ; i++ ) {
        if ( g->view.caches.c_views[i].Cache.WC_Address == c->WC_Address )
            return(TRUE);
    }
    return(FALSE);
}

static int
insert_router_in_config(uint32_t ID, wccp2_service_group_t *g)
{
int                     i;
char                    *name = NULL;
struct  sockaddr_in     sa;

    assert( g != NULL);
    if ( g->n_routers == 32 ) return(FALSE);
    i = g->n_routers;
    sa.sin_addr.s_addr = ID;
    name = my_inet_ntoa(&sa);
    if ( name ) {
        strncpy(g->routers[i].name, name, sizeof(g->routers[i].name)-1);
        my_xlog(OOPS_LOG_DBG, "wccp2.c:insert_router_in_config(): NEW ROUTER %s\n", g->routers[i].name);
        g->n_routers++;
        free(name);
    }
    return(TRUE);
}

static int
insert_cache_in_view(web_cache_identity_element_t *c, wccp2_service_group_t *g)
{
int i;

    assert( c != NULL);
    assert( g != NULL);
    assert( g->view.caches.n_caches >= 0 && g->view.caches.n_caches < 32);
    for ( i = 0; i < 32 ; i++ ) {
        if ( g->view.caches.c_views[i].Cache.WC_Address == 0 ) {
            g->view.caches.c_views[i].Cache = *c;
            g->view.caches.n_caches++;
            if (++g->view.ChangeNumber == 0) g->view.ChangeNumber=1;
            my_xlog(OOPS_LOG_DBG, "wccp2.c:insert_cache_in_view(): INSERTED, now %d caches\n", g->view.caches.n_caches);
            return(TRUE);
        }
    }
    return(FALSE);
}

/* must be called for locked view */
static void
check_view(wccp2_service_group_t *g)
{
int             i, j, k, changed = 0;
router_view_t   *r_view, *r_view_next, *r_view_continue;
cache_view_t    *c_view, *c_view_next, *c_view_continue;
uint32_t        Cache_ID;

    /* for each router check if we received ISY recently        */
    for ( i = 0; i<g->view.routers.n_routers; i++ ) {
        r_view = &g->view.routers.r_views[i];
        if ( global_sec_timer - r_view->LastI_See_You > 30 ) {
            /* it is not usable */
            my_xlog(OOPS_LOG_DBG, "wccp2.c:check_view(): router vanished\n");
            r_view_next = r_view + 1;
            r_view_continue = r_view;
	        for (j=0; j<g->view.routers.n_routers-i-1; j++) {
                *r_view = *r_view_next;
                r_view++;
                r_view_next++;
	        }
            g->view.routers.n_routers--;
            changed = TRUE;
            i = i-1; /* to check "next" */
        }
    }
    /* for each cache check if we have router which refer to it */
    for ( i = 0; i<g->view.caches.n_caches; i++ ) {
        int cache_seen = FALSE;

        c_view = &g->view.caches.c_views[i];
        /* check if this cache seen by any router */
        Cache_ID = c_view->Cache.WC_Address;
        for (j=0; j<g->view.routers.n_routers; j++) {
            r_view = &g->view.routers.r_views[j];
            my_xlog(OOPS_LOG_DBG, "wccp2.c:check_view(): Caches: %d\n", ntohl(r_view->n_caches));
            for(k=0; k < ntohl(r_view->n_caches); k++ ) {
                my_xlog(OOPS_LOG_DBG, "wccp2.check_view(): COMPARE: 0x%0x==0x%0x\n", r_view->c_ID[k].WC_Address, Cache_ID);
                if ( r_view->c_ID[k].WC_Address == Cache_ID ) {
                    cache_seen = TRUE;
                    my_xlog(OOPS_LOG_DBG, "wccp2.c:check_view(): CACHE ALIVE\n");
                }
                if ( cache_seen == TRUE ) break;
            } /* over caches in router view */
            if ( cache_seen == TRUE ) break;
        } /* over routers */
        if ( cache_seen != TRUE ) {
            my_xlog(OOPS_LOG_DBG, "wccp2.c:check_view(): Remove cache\n");
            c_view_next = c_view + 1;
            for (k=0; k<g->view.caches.n_caches-i; k++) {
                *c_view = *c_view_next;
                c_view++;
                c_view_next++;
            }
            i--;
            g->view.caches.n_caches--;
            changed = TRUE;
        }
    }
    if ( changed ) g->view.ChangeNumber++;
}

void
free_service_groups()
{
wccp2_service_group_t     *g, *n;

    g = service_groups;
    while(g) {
        n = g->next;
        free(g);
        g = n;
    }
    service_groups=NULL;
}
