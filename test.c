#include    <stdio.h>

#include    "include/connect_manage.h"
#include    "include/dispatch.h"
#include    "include/error.h"
#include    "include/feature.h"
#include    "debug.h"



int 
main(void){
    init_all();
    test_fnet_connect();
    test_fnet_config();
    test_fnet_restore();
    test_fnet_dispatch();
}

void init_all(){
    init_connect_manage();
    init_receive_feature_service();
}

void
test_fnet_connect(){
    printf("testing connect to server...\n");
    if(connect_server() == 0){
        printf("connect to server successfully\n");
    }
    else{
        printf("connect to server fail\n");
    }
}

void
test_fnet_config(){
    struct cfg_feature_set cfs;
    unsigned char fs[4] = {1, 2, 5, 3};
    cfs.no_ft = 4;
    
    for(int i=0; i<10; i++){
        cfs.f_features[i] = fs[i];
    }

    printf("testing configure to server...\n");
    if(config_server(&cfs) == 0){
        printf("configure to server successfully\n");
    }
    else{
        printf("configure to server fail\n");
    }
}

void
test_fnet_restore(){
    printf("testing resotre to server...\n");
    if(restore_server() == 0){
        printf("restore to server successfully\n");
    }
    else{
        printf("restore to server fail\n");
    }
}

void 
test_fnet_dispatch(){
    printf("testing dispatch...\n");
    if(dispatch() <  0){
        printf("dispatch operation failed\n");
    }
}