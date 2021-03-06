#include    <stdlib.h>
#include    <string.h>
#include    <stdio.h>

#include    "include/fnetlib.h"
#include    "include/error.h"



/*
 * {"b":size,"dir":"<","ipt":ipt}
 */
int 
get_packet_info(const char *str, struct packet_info * pi){

    
    int size_offset = 5, dir_offset, time_offset;
    char num_str[256];
    if(fnet_atoi(&pi->size, str + size_offset) == -1){
        err_quit("error");
        return -1;
    }
    

    sprintf(num_str, "%d", pi->size);
    dir_offset = size_offset + strlen(num_str) + 8;
    if(*(str + dir_offset) == '<'){
        pi->dir = 0;
    } 
    else if(*(str + dir_offset) == '>'){
        pi->dir = 1;
    }
    else{
        err_msg("%c string parser error", *(str + dir_offset));
        return -1;
    }

    time_offset = dir_offset + 9;
    if(fnet_atoi(&pi->ms_time, str + time_offset) == -1){
        err_quit("error");
        return -1;
    }

    return 0;
}

struct packets *
parse_packets(const char * str_pkts){
    int offset = 0, num_pkt = 0, pkt_start, pkt_end, pkt_count = 0;
    char pkt_str[128];
    
    struct packets *pkts = (struct packets*)malloc(sizeof (struct packets));
    if(pkts == NULL){
        err_msg("malloc error");
        return NULL;
    }

    int i = 0;
    while(*(str_pkts + i) != '\0'){
        if(*(str_pkts + i) == '{'){
            num_pkt++;
        }
        i++;
    }

    if(num_pkt == 0){
        return NULL;
    }

    pkts->no_pkt = num_pkt;
    pkts->packets = (struct  packet_info*) malloc(sizeof (struct packet_info) * num_pkt);

    if(*str_pkts != '['){
        return NULL;
    }
more:
    offset += 1;

    if(*(str_pkts + offset) != '{')
        return NULL;

    pkt_start = offset;
    do{
        offset++;
    }while(*(str_pkts + offset) != '}');
    pkt_end = offset;
    memcpy(pkt_str, str_pkts + pkt_start, pkt_end -pkt_start + 1);
    pkt_str[pkt_end -pkt_start + 1] = '\0';

    get_packet_info(pkt_str, pkts->packets + pkt_count);
    pkt_count++;
    if(pkt_count == num_pkt){
        return pkts;
    }
    offset++;
    goto more;
}