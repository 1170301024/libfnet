#include    <stdio.h>
#include    <string.h>
#include    <stdlib.h>

#include    "include/fnetlib.h"
#include    "include/libfnet.h"
#include    "include/error.h"
#include    "include/feature.h"

static FILE * csv_file;

void lab_task_share_handle(const unsigned char* arg, struct feature_set * fts){
    struct packets * pkts = parse_packets(fts->features[PACKETS]->ft_val);
    fprintf(csv_file, "%s,%s,%s,%s,%s", fts->features[SA]->ft_val,
                                    fts->features[SP]->ft_val,
                                    fts->features[DA]->ft_val,
                                    fts->features[DP]->ft_val,
                                    fts->features[PR]->ft_val);
    fprintf(csv_file, ",\"[");
    int valid_f = 0;
    for(int i=0; i < pkts->no_pkt; i++){  
        if(!valid_f){
            if(pkts->packets[i].dir == 0){
                fprintf(csv_file, "%d" , pkts->packets[i].size);
            }
            else{
                fprintf(csv_file, "-%d", pkts->packets[i].size);
            }
            valid_f = 1;
            continue;
        }
        if(pkts->packets[i].dir == 0){
            fprintf(csv_file, ", %d", pkts->packets[i].size);
        }
        else{
            fprintf(csv_file, ", -%d", pkts->packets[i].size);
        }
        
    }
    if(valid_f){
        fprintf(csv_file, "]\"\n");
    }
    fflush(csv_file);;

}

int 
main(int args, char * argv[]){
    char * pcap_file;

    if (args != 3){
        err_quit("lab_task arguments error");
    }
    if(NULL == (csv_file = fopen(argv[2], "w+"))){
        err_quit("Canont open file %s", argv[1]);
    }
    pcap_file = argv[1];


    fputs("src ip,dst ip,src port,dst port,protocol,packets\n", csv_file);
    fflush(csv_file);
    fnet_process_pcap(pcap_file, lab_task_share_handle, NULL);

}