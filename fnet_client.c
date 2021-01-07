#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>
#include    <stdbool.h>
#include    <getopt.h>

#include    "include/libfnet.h"
#include    "include/config.h"
#include    "include/error.h"

configuration_t glb_config;
       
static int usage (char *s){
    printf("usage: %s <command> [OPTIONS] file1 [file2 ...]\n", s);
    
    printf("\nThese are common fnet commands\n"
           "   connect              Connect to the  server\n"
           "   config               Configure the required feature set to the server\n"
           "   start                Start distributing the features of traffic flow\n"
           "   pause                Pause distributing features of traffic flow\n"
           "   restore              Restore distrubution service\n");
    printf("\nwhere OPTIONS are as follows:\n");
    printf("\nGeneral options\n"
           "   output=F             write output the file F(otherwise stdout is used)\n"
           "   --xconfig F          read feature configuration from file(F)");
    printf("\nData feature options\n"
           "   ip=1                 include ip feature information\n"
           "   tcp=1                include tcp feature information\n"
           "   ppi=1                include per packet information feature\n"
           "   fingerprints=1       include fingerprints feature\n"
           "   wht=1                include WHT protocol feature\n"
           "   dns=1                include DNS protocol feature\n"
           "   ssh=1                include SSH protocol feature\n"
           "   tls=1                include TLS protocol feature\n"
           "   dhcp=1               include DHCP protocol feature\n"
           "   dhcpv6=1             include DHCPv6 protocol feature\n"
           "   http=1               include HTTP protocol feature\n"
           "   ike=1                include Internel Key Exchange protocol feature\n"
           "   payload=1            include payload for each flow\n"
           "   exe=1                include information about host process associated with flow\n"
           "   idp=N                report N bytes of the initial data packet of each flow\n"
           "   debug=1              include debug information\n"
           "   expire_type=1        include expire_type feature\n");
    printf("\nRETURN VALUE                 0 if no errors; nonzero otherwise\n");
    return 0;
}


FILE * json_output_file;

static void 
handler(const unsigned char *arg, struct feature_set *fts){
    // advoid unused parameter error
    if(arg != NULL){
        err_msg("argument error");
    }

    fprintf(json_output_file, "{");
    int first_f = 1;
    for(int i=1; i<=NO_FEATURE; i++){
        if(fts->f_feature[i]){
            if(first_f){
                first_f = 0;
                fprintf(json_output_file, "\"%s\":%s", feature_name(fts->features[i]->ft_code), fts->features[i]->ft_val);
            }
            else{
                fprintf(json_output_file, ",\"%s\":%s", feature_name(fts->features[i]->ft_code), fts->features[i]->ft_val);
            }
            
        }    
    }
    fprintf(json_output_file, "}\n");
    fflush(json_output_file);
    return;
}
int
connect_command(void){
    if(fnet_connect() < 0){
        err_quit("connect to server failed");
    }
    return 0;


}  

void 
default_cfs(struct cfg_feature_set *cfs){
    for(int i=1; i<=12; i++){
        cfs->f_features[i] = 1;  
    }
    cfs->no_ft = 12;
}
int 
config_command(void){
    struct cfg_feature_set cfs;
    
    memset(&cfs, 0x00, sizeof cfs);

    default_cfs(&cfs);

    if(glb_config.ip){
        cfs.f_features[IP] = 1;
        cfs.no_ft++;
    }
    if(glb_config.tcp){
        cfs.f_features[TCP] = 1;
        cfs.no_ft++;
    }
    if(glb_config.ppi){
        cfs.f_features[PPI] = 1;
        cfs.no_ft++;
    }
    if(glb_config.wht){
        cfs.f_features[WHT] = 1;
        cfs.no_ft++;
    }
    if(glb_config.dns){
        cfs.f_features[DNS] = 1;
        cfs.no_ft++;
    }
    if(glb_config.ssh){
        cfs.f_features[SSH] = 1;
        cfs.no_ft++;
    }
    if(glb_config.tls){
        cfs.f_features[TLS] = 1;
        cfs.no_ft++;
    }
    if(glb_config.dhcp){
        cfs.f_features[DHCP] = 1;
        cfs.no_ft++;
    }
    if(glb_config.dhcpv6){
        cfs.f_features[DHCPV6] = 1;
        cfs.no_ft++;
    }
    if(glb_config.http){
        cfs.f_features[HTTP] = 1;
        cfs.no_ft++;
    }
    if(glb_config.payload){
        cfs.f_features[PAYLOAD] = 1;
        cfs.no_ft++;
    }
    if(glb_config.idp){
        cfs.f_features[IDP_IN] = 1;
        cfs.f_features[IDP_LEN_IN] = 1;
        cfs.f_features[IDP_OUT] = 1;
        cfs.f_features[IDP_LEN_OUT] = 1;
        cfs.no_ft += 4;
    }
    if(glb_config.expire_type){
        cfs.f_features[EXPIRE_TYPE] = 1;
        cfs.no_ft++;
    }

    if(fnet_config(&cfs) < 0){
        err_quit("configure to server failed");
        return -1;
    }
    return 0;


 
}

int 
restore_command(void){
    
    if(fnet_restore() < 0){
        err_quit("restore service failed");
    }
    return 0;
}

int
pause_command(void){
    return 0;
}

int 
all_action(void){
    if(connect_command() < 0){
        return -1;
    }
    else if(config_command() < 0){
        return -1;
    }
    else if(restore_command() < 0){
        return -1;
    }
    while(1){
        if(fnet_dispatch(0, handler, NULL) < 0){
            break;
        } 
    }
    return 0;

}
static const char * action_command[] = {"connect", "config", "restore", "pause"};
static int num_action_cmds = 4;

int main(int argc, char **argv){
    char c;
    int num_cmds = 0;
    int done_with_options = 0;
    int opt_count = 0, i;
    int action = -1;
    //char *config_file;
    char ** i_argv = argv;
    int i_argc = argc;


    // if(argc == 1){
    //     return usage(argv[0]);
    // }
    puts("3");
    if(argc > 1){
        for(i=0; i<num_action_cmds; i++){
            if(strcmp(argv[1], action_command[i]) == 0){
                action = i;
                break;
            }
        }
    }
    puts("2");
    /* Sanity check argument syntax */
    for (i=1; i<argc; i++) {
        if (strchr(argv[i], '=')) {
            if (done_with_options) {
                  err_msg("option (%s) found after filename (%s)", argv[i], argv[i-1]);
                  exit(-1);
            }
        } else {
            done_with_options = 1;
        }
    }

    if(action != -1){
        argv++;
        argc--;
    }
    puts("1");
    num_cmds = config_set_from_argv(&glb_config, argv, argc);
    argv += num_cmds;
    argc -= num_cmds;
     /* Process command line options */
    while (1) {
        int option_index = 0;
        struct option long_options[] = {
            {"help",  no_argument,         0, 'h' },
            {"xconfig", required_argument, 0, 'x' },
            {0,         0,                 0,  0  }
        };

        c = getopt_long(argc, argv, "hx:", long_options, &option_index);

        if (c == -1) break;

        switch (c) {
            case 'x':
                // config_file = optarg;
                opt_count++;
                break;
            case 'h':
            default:
                return usage(argv[0]);
        }
        opt_count++;
    }
    

    // if (initial_setup(config_file)) exit(0);
    if(glb_config.filename != NULL){
         if(NULL == (json_output_file = fopen(glb_config.filename, "w"))){
             fprintf(stderr, "cannot open file %s", glb_config.filename);
             exit(-1);
         }
    }
    else{
        json_output_file = stdout;
    }

    switch(action){
        case 0:
            connect_command();
            break;

        case 1:
            config_command();
            break;

        case 2:
            restore_command();
            break;

        case 3:
            pause_command();
            break;

        default:
            all_action();

    }
}


