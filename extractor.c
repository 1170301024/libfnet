#include    <stdlib.h>  
#include    <stdio.h>
#include    <unistd.h>
#include    <string.h>
#include    <pthread.h>
#include    <time.h>
#include    <string.h>

#include    "debug.h"
#include    "include/joy/joy_api.h"
#include    "include/joy/joy_api_private.h"
#include    "include/safe_c_stub/safe_lib.h"
#include    "include/extractor.h"
#include    "include/const.h"
#include    "include/error.h"
#include    "include/nflog.h"

static struct intrface ifl[IFL_MAX];
int no_ifs;
int snaplen = 65535;


#if (DEBUG_MEASURE_TIME == 1)
float process_time; 

#endif
int num_packets;

static int 
find_interface_in_list(char *name) {
    int i;

    for (i = 0; i < IFL_MAX; ++i) {
        if (strcmp((char*)ifl[i].name, name) == 0) {
            return i;
        }
    }
   return -1;
}

/**
 * \fn void print_interfaces (FILE *f, int num_ifs)
 * \param f file to print to
 * \param num_ifs number of interfaces available
 * \return none
 */
void 
print_interfaces(FILE *f_info, int num_ifs) {
{
    int i;

    fprintf(f_info, "\nInterfaces\n");
    fprintf(f_info, "==========\n");
    for (i = 0; i < num_ifs; ++i) {
        fprintf(f_info, "Interface: %s\n", ifl[i].name);
        if (ifl[i].ip_addr4[0] != 0) {
            fprintf(f_info, "\tIPv4 Address: %s\n", ifl[i].ip_addr4);
        }
        if (ifl[i].ip_addr6[0] != 0) {
            fprintf(f_info, "\tIPv6 Address: %s\n", ifl[i].ip_addr6);
        }
        if (ifl[i].mac_addr[0] != 0) {
            fprintf(f_info, "\tMAC Address: %c%c:%c%c:%c%c:%c%c:%c%c:%c%c\n",
                    ifl[i].mac_addr[0], ifl[i].mac_addr[1],
                    ifl[i].mac_addr[2], ifl[i].mac_addr[3],
                    ifl[i].mac_addr[4], ifl[i].mac_addr[5],
                    ifl[i].mac_addr[6], ifl[i].mac_addr[7],
                    ifl[i].mac_addr[8], ifl[i].mac_addr[9],
                    ifl[i].mac_addr[10], ifl[i].mac_addr[11]);
            }
        }
    }
}

static unsigned int 
interface_list_get(void) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i;
    unsigned int num_ifs = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list on the local machine */
    //if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return num_ifs;
    }
    memset(&ifl, 0x00, sizeof(ifl));

    /* store off the interface list */
    for (d = alldevs; d; d = d->next) {
        char ip_string[INET6_ADDRSTRLEN];
        pcap_addr_t *dev_addr = NULL; //interface address that used by pcap_findalldevs()

        /* check if the device is suitable for live capture */
        for (dev_addr = d->addresses; dev_addr != NULL; dev_addr = dev_addr->next) {
            /* skip the loopback interfaces */
            
            if (strcmp(d->name,"lo0") == 0) {
                continue;
            }
            /* Linux */
            if (strcmp(d->name,"lo") == 0) {
                continue;
            }
            if (dev_addr->addr && (dev_addr->addr->sa_family == AF_INET ||
				   dev_addr->addr->sa_family == AF_INET6)
		&& dev_addr->netmask) {
                i = find_interface_in_list(d->name);
                if (i > -1) {
                    /* seen this interface before */
                    memset(ip_string, 0x00, INET6_ADDRSTRLEN);
                    if (dev_addr->addr->sa_family == AF_INET6) {
                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)dev_addr->addr)->sin6_addr, ip_string, INET6_ADDRSTRLEN);
                        snprintf((char*)ifl[i].ip_addr6, INET6_ADDRSTRLEN, "%s", (unsigned char*)ip_string);
                    } else {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)dev_addr->addr)->sin_addr, ip_string, INET_ADDRSTRLEN);
                        snprintf((char*)ifl[i].ip_addr4, INET_ADDRSTRLEN, "%s", (unsigned char*)ip_string);
                    }
                    //get_mac_address((char*)ifl[i].name,ifl[i].mac_addr);
                } else {
                    /* first time seeing this interface add to list */
                    snprintf((char*)ifl[num_ifs].name, INTFACENAMESIZE, "%s", d->name);
                    memset(ip_string, 0x00, INET6_ADDRSTRLEN);
                    if (dev_addr->addr->sa_family == AF_INET6) {
                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)dev_addr->addr)->sin6_addr, ip_string, INET6_ADDRSTRLEN);
                        snprintf((char*)ifl[num_ifs].ip_addr6, INET6_ADDRSTRLEN, "%s", (unsigned char*)ip_string);
                    } else {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)dev_addr->addr)->sin_addr, ip_string, INET_ADDRSTRLEN);
                        snprintf((char*)ifl[num_ifs].ip_addr4, INET_ADDRSTRLEN, "%s", (unsigned char*)ip_string);
                    }
                    ifl[num_ifs].active = IFF_UP;
                    //get_mac_address((char*)ifl[num_ifs].name,ifl[num_ifs].mac_addr);
                    ++num_ifs;
                }
            }
        }
    }

    if (num_ifs == 0) {
       fprintf(stderr, "No suitable interfaces found.\n\n");
    }

    pcap_freealldevs(alldevs);
    return num_ifs;
}

pcap_t * 
open_pcap_device(const char *device){
    pcap_t *pd;
    struct bpf_program fp;
    bpf_u_int32 localnet, netmask;
    char filter_exp[PCAP_ERRBUF_SIZE], errbuf[PCAP_BUF_SIZE];
    if(NULL == device){
        err_quit("the device is null", "");
    }
    printf("device %s is being opened\n", device);
    if((pd = pcap_open_live(device, snaplen, 0, snaplen, errbuf)) == NULL){
        err_msg("pcap_open_live: %s\n", errbuf);
        return NULL;
    }
    // more actions
    if(pcap_lookupnet(device, &localnet, &netmask, errbuf) < 0){
        err_quit("pcap_lookupnet: %s\n", errbuf);
    }
    memset(&fp,  0x00, sizeof(struct bpf_program));
    strncpy(filter_exp, IP_OR_VLAN, strlen(IP_OR_VLAN));
    /*if(pcap_compile(pd, &fp, filter_exp, 0, netmask) < 0){
        
        err_quit("pcap_compile: %s\n", pcap_geterr(pd));
    }
    
    if(pcap_setfilter(pd, &fp) < 0){
        err_quit("pcap_setfilter: %s\n", pcap_geterr(pd));
    }*/

    return pd;
}

pcap_t *
open_pcap_file(const char *file_name){
    pcap_t *handle = NULL;
    //bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;
    struct bpf_program fp;
    char filter_exp[PCAP_ERRBUF_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];

    /* initialize fp structure */
    memset_s(&fp, sizeof(struct bpf_program),  0x00, sizeof(struct bpf_program));
    strncpy_s(filter_exp, PCAP_ERRBUF_SIZE, IP_OR_VLAN, strnlen_s(IP_OR_VLAN, 20));

    handle = pcap_open_offline(file_name, errbuf);
    if (handle == NULL) {
        printf("Couldn't open pcap file %s: %s\n", file_name, errbuf);
        return NULL;
    }

    /* compile the filter expression */
    // if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    //     fprintf(stderr, "error: could not parse filter %s: %s\n",
    //             filter_exp, pcap_geterr(handle));
    //     return NULL;
    // }

    // /* apply the compiled filter */
    // if (pcap_setfilter(handle, &fp) == -1) {
    //     fprintf(stderr, "error: could not install filter %s: %s\n",
    //             filter_exp, pcap_geterr(handle));
    //     return NULL;
    // }
    return handle;

}

int 
init_feature_extract_service(){
    joy_init_t init_data;

    memset(&init_data, 0x00, sizeof init_data);

#ifdef ENJOY_DEBUG
    init_data.verbosity = 1;
#else
    init_data.verbosity = 4;
#endif

    init_data.max_records = 0;
    init_data.num_pkts = 8096;
    init_data.contexts = 1;
    init_data.idp = 1400;
    init_data.inact_timeout=-1;

    // turn on all bitmask value except JOY_IPFIX_EXPORT_ON
    // init_data.bitmask = JOY_ALL_ON & (~JOY_IPFIX_EXPORT_ON);
    init_data.bitmask = JOY_BIDIR_ON | JOY_ZERO_ON | JOY_TLS_ON | JOY_RETRANS_ON;
    if(joy_initialize(&init_data, NULL, NULL, NULL) != 0){
        err_quit("=>Joy initialized failed<=", "");
    }
    for(int n=0; n < init_data.contexts; n++){
        //joy_print_config(n, JOY_TERMINAL_FORMAT);
        joy_print_config(n, JOY_JSON_FORMAT);
    }

    no_ifs = interface_list_get();
    return 0;
}

FILE * flow_pipe_out;

// should i use thread? one thread for one device? or any other way?
/*
 * one context work for a device or one joy for a device?
 *   
 *
 */
static int 
feature_extract(pcap_t *handle, unsigned int ctx_idx){
    int more = 1;
  
#if (DEBUG_MEASURE_TIME == 1)   
    float x_time = 0, p_time = 0; 
    struct timeval t_start, t_end, r_time;
#endif
    if(handle == NULL){
        err_msg("argument error:null");
        return -1;
    }
    
    while(more){
        joy_ctx_data *ctx = joy_index_to_context(ctx_idx);
        ctx->output = flow_pipe_out;
        
#if (DEBUG_MEASURE_TIME == 1)
        gettimeofday(&t_start, NULL);
#endif

        

#if (DEBUG_MEASURE_TIME == 1)
        more = pcap_dispatch(handle, NO_PACKETS_IN_LOOP, nflog_libpcap_process_packet, (unsigned char *) ctx->ctx_id);
        gettimeofday(&t_end, NULL);
        joy_timer_sub(&t_end, &t_start, &r_time);
        x_time += r_time.tv_sec + r_time.tv_usec /1000000.0;
        gettimeofday(&t_start, NULL);
#else
        more = pcap_dispatch(handle, NO_PACKETS_IN_LOOP, joy_libpcap_process_packet, (unsigned char *) ctx->ctx_id);
#endif
        
        joy_print_flow_data(ctx_idx, JOY_EXPIRED_FLOWS);


#if (DEBUG_MEASURE_TIME == 1)
        gettimeofday(&t_end, NULL);
        joy_timer_sub(&t_end, &t_start, &r_time);
        p_time += r_time.tv_sec + r_time.tv_usec /1000000.0;
#endif                                                             
    }
    
    joy_print_flow_data(ctx_idx, JOY_ALL_FLOWS);
    joy_print_flocap_stats_output(ctx_idx);
    
    

#if (DEBUG_MEASURE_TIME == 1)

    /*fprintf(stderr, "result of time measurement\n==========================\npcap_dispatch:%fs\njoy_print_flow_data:%fs\njoy_libpcap_process_packet:%fs\n", x_time, p_time, process_time);
    fprintf(stderr, "number of packets: %d\n", num_packets);*/
    
    
#endif
    return 0;
}

int 
feature_extract_from_interface(const char *device){
    if(NULL == device){
        err_msg("argument error:null");
        return -1;
    }

    pcap_t * handle;
    if((handle = open_pcap_device(device)) == NULL){
        err_msg("error");
        return -1;
    }
    feature_extract(handle, 0);
    joy_shutdown();
    return 0;
}

int 
feature_extract_from_pcap(const char * f_pcap){
    if(NULL == f_pcap){
        err_msg("argument error:null");
        return -1;
    }

    pcap_t * handle;
    if((handle = open_pcap_file(f_pcap)) == NULL){
        return -1;
    }
    feature_extract(handle, 0);

    /*write a finish message to the pipe*/
    fprintf(flow_pipe_out, EXTRACTOR_PCAP_FIN_STR);
    fprintf(flow_pipe_out, "\n");
    fflush(flow_pipe_out);

    joy_shutdown();
    return 0;
}



#if (DEBUG_MEASURE_TIME == 1)
void 
test_joy_libpcap_process_packet(unsigned char *ctx_index,
                        const struct pcap_pkthdr *header,
                        const unsigned char *packet)
{
   
    struct timeval t_start, t_end, r_time;
    uint64_t index = 0;
    joy_ctx_data *ctx = NULL;

    /* check library initialization */
    

    /* make sure we have a packet to process */
    if (packet == NULL) {
        return;
    }
    num_packets++;
    /* ctx_index has the int value of the data context
     * This number is between 0 and max configured contexts
     */
    index = (uint64_t)ctx_index;

    
    gettimeofday(&t_start, NULL);

    ctx = joy_index_to_context(index);
    process_packet((unsigned char*)ctx, header, packet);

    gettimeofday(&t_end, NULL);
    joy_timer_sub(&t_end, &t_start, &r_time);
    process_time += r_time.tv_sec + r_time.tv_usec /1000000.0;
}
#endif    