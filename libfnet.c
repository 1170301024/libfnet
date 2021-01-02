#include    "include/libfnet.h"
#include    "include/connect_manage.h"
#include    "include/dispatch.h"
#include    "include/feature.h"
#include    "include/error.h"

extern int flag_init_cm;
extern int flag_init_rfs;
int 
fnet_connect(){
    if(!flag_init_cm){
        if(init_connect_manage() < 0){
            err_msg("Connect server failed");
            return -1;
        }
    }

    return connect_server();
}

int
fnet_config(const struct cfg_feature_set * ft_set){
    if(!flag_init_cm){
        if(init_connect_manage() < 0){
            err_msg("Configure server failed");
            return -1;
        }
    }
    return config_server(ft_set);
}

int 
fnet_start(){
    return fnet_restore();
}

// int 
// fnet_pause(){
//     if(!flag_init_cm){
//         if(init_connect_manage() < 0){
//             err_msg("Pause server failed");
//             return -1;
//         }
//     }
//     return pause_server();
// }

int 
fnet_restore(){
    if(!flag_init_cm){
        if(init_connect_manage() < 0){
            err_msg("Restore server failed");
            return -1;
        }
    }
    return restore_server();
}

int 
fnet_dispatch(int loop, feature_handler fhdl, unsigned char *fhdl_args){
    if(!flag_init_rfs){
        if(init_receive_feature_service() < 0){
            err_msg("receive feature service initialization failed");
            return -1;
        }
    }
        
    return dispatch(fhdl, fhdl_args);
}





//songyunzu shi xiaozhu 