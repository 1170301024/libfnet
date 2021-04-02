#ifndef __FNETLIB_H
#define __FNETLIB_H



struct packets{
    int no_pkt;
    struct packet_info *packets;
};
struct packet_info{
    int size;
    int dir; /*  0 for inbound. 1 for outbound*/
    int ms_time;
};

int fnet_atoi(int * ret_val, const char *s);

struct packets *parse_packets(const char * str_pkts);
#endif