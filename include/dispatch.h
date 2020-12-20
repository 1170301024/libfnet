#ifndef _DISPATCH_H_
#define _DISPATCH_H_

#define SERVER_FEATURE_DISTRIBUTE_PORT 60721
#define SERVER_FEATURE_DISTRIBUTE_IPV4 "192.168.182.133"

int init_receive_feature_service();
int dispatch();
#endif