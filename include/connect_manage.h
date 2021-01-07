#ifndef _CONNECT_MANAGE_H_
#define _CONNECT_MANAGE_H_

#define SERVER_UDP_PORT 60720
#define SERVER_UDP_IPV4 "192.168.2.11"

#define USER_UDP_PROT 60606
#define USER_UDP_IPV4 "192.168.79.128"

#define SO_SOCKET_TIMEOUT   5
#define NO_MAX_TRY 3

int init_connect_manage(void);
int connect_server(void);
int config_server(const struct cfg_feature_set * ft_set);
int restore_server(void);
#endif