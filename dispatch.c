#include    <unistd.h>
#include    <sys/socket.h>
#include    <netinet/in.h>
#include    <arpa/inet.h>
#include    <sys/param.h>
#include    <stdlib.h>
#include    <string.h>
#include    <errno.h>
#include    <stdio.h>

#include    "include/dispatch.h"
#include    "include/proto.h"
#include    "include/error.h"

extern int cmsockfd;
int flag_init_rfs;
int rfsockfd;
struct sockaddr server_addr_d;

int 
init_receive_feature_service(){
    struct sockaddr_in *sd_addr = (struct sockaddr_in*)&server_addr_d;

    rfsockfd = cmsockfd;

    memset(sd_addr, 0, sizeof (*sd_addr));
    sd_addr->sin_family = AF_INET;
    sd_addr->sin_port = htons(SERVER_FEATURE_DISTRIBUTE_PORT);
    if(inet_pton(AF_INET, SERVER_FEATURE_DISTRIBUTE_IPV4, &(sd_addr->sin_addr.s_addr)) < 0){
        err_sys("inet_pton error");
        return -1;
    }

    flag_init_rfs = 1;
    return 0;

}

int 
dispatch(){
    if(flag_init_rfs == 0){
        err_msg("Receive feature service is not initialized");
        return -1;
    }

    char ft_msg[MAX_UDP_MSG];
    int n, addr_len;
    
    for( ; ; ){
        n = recvfrom(rfsockfd, ft_msg, MAX_UDP_MSG, 0, &server_addr_d, &addr_len);
        if(n < 0){
            err_sys(recvfrom);
            continue;
        }
        printf("Receive a packet from %s:%d\n", inet_ntoa(((struct sockaddr_in*)&server_addr_d)->sin_addr), ntohs(((struct sockaddr_in*)&server_addr_d)->sin_port));

        // parse the packet as a feature packet
        short proto_len, folen;
        char focode;
        int msg_offset;

        if(ft_msg[0] != FEATURE || ft_msg[1] != GENERAL_CODE){
            err_msg("feature packet error");
            continue;
        }

        proto_len = *(short *)(ft_msg + 2);
        if(proto_len <= 4){
            err_msg("feature packet length error");
            continue;
        }
        msg_offset = 4;
        do{
            focode = *(ft_msg + msg_offset);
            folen = *(short *)(ft_msg+msg_offset + 1);
            char * val = (char *)malloc(folen + 1);
            memcpy(val, ft_msg + msg_offset + 3, folen);
            val[folen] = '\0';
            printf("code:%d,value:%d", focode, val);
            free(val);
            msg_offset += 3 + folen;
        }while(msg_offset < proto_len);
    }
}
