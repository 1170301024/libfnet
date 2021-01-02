#include    <unistd.h>
#include    <sys/socket.h>
#include    <netinet/in.h>
#include    <arpa/inet.h>
#include    <sys/param.h>
#include    <stdlib.h>
#include    <string.h>
#include    <errno.h>
#include    <stdio.h>



#include    "include/debug.h"
#include    "include/feature.h"
#include    "include/connect_manage.h"
#include    "include/proto.h"
#include    "include/error.h"
#include    <signal.h>


int no_try = 0;
int flag_init_cm = 0;
int cmsockfd;
struct sockaddr server_addr;

static void
cm_sig_alrm(int signo){
    return ;
}


int 
init_connect_manage(){
    struct sockaddr_in cmaddr, *s_addr = (struct sockaddr_in*)&server_addr;
    //int rc;
    struct sigaction act, oact;

    

    cmsockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(-1 == cmsockfd){
        err_sys("socket error");
        return -1;
    }
    memset(&cmaddr, 0, sizeof cmaddr);

    // init endpoint info
    cmaddr.sin_family = AF_INET; 
    cmaddr.sin_port = htons(USER_UDP_PROT);
    if(inet_pton(AF_INET, USER_UDP_IPV4, &(cmaddr.sin_addr.s_addr)) < 0){
        err_sys("inet_pton error");
        return -1;
    }
    
    if(-1 == bind(cmsockfd, (struct sockaddr *)&cmaddr, sizeof cmaddr)){
        err_sys("bind error");
        return -1;
    }

    // init server socket address
    s_addr->sin_family = AF_INET;
    s_addr->sin_port = htons(SERVER_UDP_PORT);
    if(inet_pton(AF_INET, SERVER_UDP_IPV4, &(s_addr->sin_addr.s_addr)) < 0){
        err_sys("inet_pton error");
        return -1;
    }

    act.sa_handler = cm_sig_alrm;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_flags |= SA_INTERRUPT;
    if(sigaction(SIGALRM, &act, &oact) < 0){
        err_msg("sigaction error");
        return -1;
    }
   
    flag_init_cm = 1;
    return 0;

} 

static int 
cm_send_recv(char * sbuf, int slen, char *rbuf, int rsize, int *rlen){

    socklen_t server_addr_len;
resend:
    no_try++;
    if(NO_MAX_TRY < no_try){
        err_msg("Three attempts failed, check network condition");
        no_try = 0;
        return -1;
    }    
    if(sendto(cmsockfd, sbuf, slen, 0, &server_addr, sizeof server_addr) == -1){
        err_sys("sendto error");
        return -1;
    }
#ifdef LIBFNET_DEBUG
    printf("sent request to server(%d)\n", no_try);
#endif
    alarm(SO_SOCKET_TIMEOUT);    
    if((*rlen = recvfrom(cmsockfd, rbuf, rsize, 0, &server_addr, &server_addr_len)) < 0){
        if(errno == EINTR){
            err_msg("socket timeout");
            goto resend;
        }
        else{
            err_sys("recvfrom error");
            return -1;
        }
    }
    alarm(0);
    no_try = 0;
    return 0;
}


int 
connect_server(){
    if(!flag_init_cm){
        err_msg("Connection management is not initialized");
        return -1;
    }

    char ctype, ccode;
    short proto_len;
    char *sbuf, rbuf[MAX_UDP_MSG];
    int n;

    ctype = CONNECT;
    ccode = GENERAL_CODE;
    proto_len = 4;

    sbuf = (char *)malloc(proto_len);
    if (sbuf == NULL){
        err_msg("malloc error");
        return -1;
    }
    sbuf[0] = ctype;
    sbuf[1] = ccode;
    *((unsigned short *)(sbuf+2)) = htons(proto_len);
    
    if(cm_send_recv(sbuf, proto_len, rbuf, MAX_UDP_MSG, &n) < 0){
        return -1;
    }

#ifdef LIBFNET_DEBUG
    printf("Received connection response from server\n");
#endif
    if(n != 4){
        err_msg("NO byte from server error");
        return -1;
    }

    if(rbuf[0] == CONNECT_RSP && rbuf[1] == CMRSP_OK){
        return 0;
    }
    err_msg("connect response error");
    return -1;

}

int 
config_server(const struct cfg_feature_set * ft_set){
    if(!flag_init_cm){
        err_msg("Connection management is not initialized");
        return -1;
    }

    if(NULL == ft_set){
        err_msg("null argument error");
        return -1;
    }
    if(ft_set->no_ft > NO_FEATURE){
        err_msg("no feature error");
        return -1;
    }
    char cfg_type, cfg_code, ft_code;
    unsigned short proto_len = 0, no_ft;
    char *sbuf, rbuf[MAX_UDP_MSG], ft_flags[(NO_FEATURE + 7) / 8];
    int n;


    memset(ft_flags, 0, sizeof ft_flags);
    cfg_type = CONFIG;
    cfg_code = GENERAL_CODE;
    no_ft = ft_set->no_ft;

    for(int i=0; i <= NO_FEATURE; i++){
        if(ft_set->f_features[i] == 1){  
            ft_code = i;
            ft_flags[ft_code/8] |= ((unsigned char )1 << (unsigned char )(ft_code % 8));  
        }
    }

    proto_len = 4 + 2 + sizeof (ft_flags);
    sbuf = (char *)malloc(proto_len);
    if(sbuf == NULL){
        err_msg("malloc error");
        return -1;
    }
    sbuf[0] = cfg_type;
    sbuf[1] = cfg_code;
    *((unsigned short *)(sbuf+2)) = htons(proto_len);
    *((unsigned short *)(sbuf+4)) = htons(no_ft);
    memcpy(sbuf+6, ft_flags, sizeof ft_flags);

    if(cm_send_recv(sbuf, proto_len, rbuf, MAX_UDP_MSG, &n) < 0){
        return -1;
    }

#ifdef LIBFNET_DEBUG
    printf("receive config response from server\n");
#endif
    if(n != 4){
        err_msg("NO byte from server error");
        return -1;
    }

    if(rbuf[0] == CONFIG_RSP && rbuf[1] == CMRSP_OK){
        return 0;
    }
    err_msg("config response error");
    return -1;
}

int 
restore_server(){
    if(!flag_init_cm){
        err_msg("Connection management is not initialized");
        return -1;
    }

    char rtype, rcode;
    short proto_len;
    char *sbuf, rbuf[MAX_UDP_MSG];
    int n;

    rtype = RESTORE;
    rcode = GENERAL_CODE;
    proto_len = 4;

    sbuf = (char *)malloc(proto_len);
    if (sbuf == NULL){
        err_msg("malloc error");
        return -1;
    }
    sbuf[0] = rtype;
    sbuf[1] = rcode;
    *((unsigned short *)(sbuf+2)) = htons(proto_len);
    
    if(cm_send_recv(sbuf, proto_len, rbuf, MAX_UDP_MSG, &n) < 0){
        return -1;
    }

#ifdef LIBFNET_DEBUG
    printf("Received restore response from server\n");
#endif
    if(n != 4){
        err_msg("NO byte from server error");
        return -1;
    }

    if(rbuf[0] == RESTORE_RSP && rbuf[1] == CMRSP_OK){
        return 0;
    }
    err_msg("restore response error");
    return -1;

}


