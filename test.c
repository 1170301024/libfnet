#include    <stdio.h>

#include    "include/connect_manage.h"
#include    "include/error.h"
#include    "include/feature.h"
#include    "debug.h"



int 
main(void){
    init_all();
    test_fnet_connect();
    test_fnet_config();
    test_fnet_restore();
}

void init_all(){
    init_connect_manage();
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
    unsigned char fs[10] = {1, 2, 5, 41, 36, 25, 12, 11, 22, 3};
    cfs.no_ft = 10;
    
    for(int i=0; i<10; i++){
        cfs.features[i] = fs[i];
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