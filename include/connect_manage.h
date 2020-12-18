#ifndef _CONNECT_MANAGE_H_
#define _CONNECT_MANAGE_H_

#define SERVER_UDP_PORT 60720
#define SERVER_UDP_IPV4 "192.168.182.133"

#define USER_UDP_PROT 60606
#define USER_UDP_IPV4 "192.168.182.133"

#define SO_SOCKET_TIMEOUT   5
#define NO_MAX_TRY 3

int init_connect_manage();
int connect_server();
int config_server(struct cfg_feature_set * ft_set);
int restore_server();
static int cm_send_recv(char * sbuf, int slen, char *rbuf, int rsize, int *rlen);
static void cm_sig_alrm(int signo);
#endif