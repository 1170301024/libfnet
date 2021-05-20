#include    <pthread.h>
#include    <unistd.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <fcntl.h>

#include    "include/libfnet.h"
#include    "include/connect_manage.h"
#include    "include/dispatch.h"
#include    "include/feature.h"
#include    "include/error.h"
#include    "include/flow.h"
#include    "include/extractor.h"
#include    "include/fnetthread.h"

extern FILE * flow_pipe_in;
extern FILE * flow_pipe_out;
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

int 
fnet_process_pcap(const char * pcap_file, feature_handler fhdl, unsigned char *fhdl_argv){

    if(pcap_file == NULL){
        return -1;
    }
    if(fhdl == NULL){
        return -1;
    }

    int fxpid;
    int fxd_pipe[2];

    // create a pipe
    if(pipe(fxd_pipe) == -1){
        err_quit("pipe error");
    }
    if((fxpid = fork()) == 0){
        // close the descriptor for reading
        close(fxd_pipe[0]);
        flow_pipe_out = fdopen(fxd_pipe[1], "w"); 
        if(init_feature_extract_service() == 0){
            feature_extract_from_pcap(pcap_file);
            exit(0);
        }
        sleep(1);

        exit(-1);
    }
    // sleep 1s for waiting feature extraction service to finish initialization
    sleep(1); 
    // close the descriptor for writing
    close(fxd_pipe[1]);
    flow_pipe_in = fdopen(fxd_pipe[0], "r");
    flow_distribute(fhdl, fhdl_argv);
   
    return 0;
}




//songyunzu shi xiaozhu 