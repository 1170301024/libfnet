#include    <stdio.h>
#include    <string.h>
#include    <stdlib.h>
#include    <time.h>

#include    "include/connect_manage.h"
#include    "include/dispatch.h"
#include    "include/error.h"
#include    "include/feature.h"
#include    "debug.h"

#define start_string "#start"
#define end_string "#end"



struct packets{
    int no_pkt;
    struct packet_info *packets;
};
struct packet_info{
    int size;
    int dir; /*  0 for inbound. 1 for outbound*/
    int ms_time;
};

struct action{
    time_t start_time;
    time_t end_time;
    char action[128];
    struct action *next;
};

struct action *action_list;
/*
 * {"b":size,"dir":"<","ipt":ipt}
 */
int 
get_packet_size_dir_time(const char *str, struct packet_info * pi){

    int size_offset = 5, dir_offset, time_offset;
    char num_str[256];
    if((pi->size = atoi(str + size_offset)) == 0){
        return -1;
    }
    
    sprintf(num_str, "%d\0", pi->size);
    dir_offset = size_offset + strlen(num_str) + 8;
    if(*(str + dir_offset) == '<'){
        pi->dir = 0;
    } 
    else if(*(str + dir_offset) == '>'){
        pi->dir = 1;
    }
    else{
        err_msg("%c string parser error", *(str + dir_offset));
        return -1;
    }

    time_offset = dir_offset + 9;
    if((pi->ms_time = atoi(str + time_offset)) == 0){
        return -1;
    }
    return 0;
}

struct packets *
parser_packets(const char * str_pkts){
    int offset = 0, num_pkt = 0, pkt_start, pkt_end, pkt_count = 0;
    char pkt_str[128];
    
    struct packets *pkts = (struct packets*)malloc(sizeof (struct packets));
    if(pkts == NULL){
        err_msg("malloc error");
        return NULL;
    }

    int i = 0;
    while(*(str_pkts + i) != '\0'){
        if(*(str_pkts + i) == '{'){
            num_pkt++;
        }
        i++;
    }
    if(num_pkt == 0){
        return NULL;
    }

    pkts->no_pkt = num_pkt;
    pkts->packets = (struct  packet_info*) malloc(sizeof (struct packet_info) * num_pkt);

    if(*str_pkts != '['){
        return NULL;
    }
more:
    offset += 1;

    if(*(str_pkts + offset) != '{')
        return NULL;

    pkt_start = offset;
    do{
        offset++;
    }while(*(str_pkts + offset) != '}');
    pkt_end = offset;
    memcpy(pkt_str, str_pkts + pkt_start, pkt_end -pkt_start + 1);
    pkt_str[pkt_end -pkt_start + 1] = '\0';

    get_packet_size_dir_time(pkt_str, pkts->packets + pkt_count);
    pkt_count++;
    if(pkt_count == num_pkt){
        return pkts;
    }
    offset++;
    goto more;


    
}
FILE * file;


// 
time_t last_handler_time = -1;
int csv_file_count =1;

int flow_count;

char * data_file = "test";

void handler(const unsigned char* arg, struct feature_set * fts){
    if(last_handler_time == -1 || time(NULL) - last_handler_time > 1){
        char file_path[256];
        last_handler_time = time(NULL);
        sprintf(file_path, "../%s_feature/%d.csv", data_file, csv_file_count);
        if((file = fopen(file_path, "w+")) == NULL){
            err_quit("canno't open file");
        }
        sprintf(file_path, "../%s/%d/logs/%d.log", data_file, csv_file_count, csv_file_count);
        puts(file_path);
        read_logfile(file_path);
        csv_file_count++;
    // for(struct action *a = action_list; a!= NULL; a=a->next){
    //     printf("action:%s, start_time:%ld, end_time:%ld\n", a->action, a->start_time, a->end_time);
    // }

        fprintf(file, "flow_number,action,packets_length_total,filename,protocol,sip,dip,sport,dport\n");
    }
    char start_timebuf[256], end_timebuf[256];
    time_t ms_start_flow, ms_end_flow;
    if(fts->f_feature[TIME_START] && fts->f_feature[TIME_END]){
        double start_time = atof(fts->features[TIME_START]->ft_val);
        double end_time = atof(fts->features[TIME_END]->ft_val);

        ms_start_flow = (time_t)(start_time * 1000); 
        ms_start_flow = (time_t)(end_time * 1000);
        const time_t st = (int) start_time, et = (int) end_time;
        strftime(start_timebuf, 256, "%Y-%m-%d_%H:%M:%S\0", localtime(&st));
        strftime(end_timebuf, 256, "%Y-%m-%d_%H:%M:%S\0", localtime(&et));
        
        
    }
    
    
    struct packets * pkts = parser_packets(fts->features[PACKETS]->ft_val);
    if(pkts == NULL){
        err_msg("error");
        return;
    }
    
    for(struct action *a = action_list; a!= NULL; a=a->next){
        //printf("action:%s, start_time:%ld, end_time:%ld\n", a->action, a->start_time, a->end_time);
        int it = 0;
        int vaild_f = 0;
        for(int i=0; i < pkts->no_pkt; i++){
            it += pkts->packets[i].ms_time;
            time_t pkt_time = ms_start_flow + it;
            if(pkt_time > a->start_time && pkt_time < a->end_time){
                if(!vaild_f){
                    fprintf(file, "%d,%s,\"[", flow_count, a->action);
                    if(pkts->packets[i].dir == 0){
                        fprintf(file, "%d" , pkts->packets[i].size);
                    }
                    else{
                        fprintf(file, "-%d", pkts->packets[i].size);
                    }
                    vaild_f = 1;
                    continue;
                }
                if(pkts->packets[i].dir == 0){
                    fprintf(file, ", %d", pkts->packets[i].size);
                }
                else{
                    fprintf(file, ", -%d", pkts->packets[i].size);
                }
                
            }
        }
        if(vaild_f){
            fprintf(file, "]\"");
            fprintf(file, ",%d.pcap", csv_file_count-1);
            // test
            //fprintf(file, ",%s,%s,", start_timebuf, end_timebuf);
            //fprintf(file, "%l,%l,", a->start_time, a->end_time);

            // end test
            fprintf(file, ",%s,%s,%s,%s,%s\n", fts->features[PR]->ft_val, 
                                    fts->features[SA]->ft_val,
                                    fts->features[DA]->ft_val,
                                    fts->features[SP]->ft_val,
                                    fts->features[DP]->ft_val);
            
            if(strcmp(fts->features[PR]->ft_val, "6")){
                fflush(file);
                getchar();
            }
        }   
        
    }
    
    flow_count++;
    fflush(file);
}

int
read_logfile(char *file_path){
    FILE * file = NULL;
    char line[256];
    struct tm tm;
    int action_flag = 0, time_f = 0;
    struct action * cur_action;

    action_list = NULL;
    if((file = fopen(file_path, "r")) == NULL){
        err_quit("cannot open logfile");
    }
    do{
        fgets(line, 256, file);
        line[strlen(line)-1] = '\0';
        if(strcmp(end_string, line) == 0){
            break;
        }
        puts(line);
        if(action_flag == 0 && strcmp(start_string, line) == 0){
            
            action_flag = 1;
            time_f = 0;
            continue;
        }
        
        else if(action_flag == 0){
            continue;
        }
        if(strlen(line) <= 1){
            continue;
        }
        // read start time of action || read end time of action
        if(time_f == 0 || time_f == 2){
            int _flag = 0, i=0;
            time_t time, m_time;
            do{
                if(_flag != 1 && *(line+i) == '_'){
                    *(line+i) = ' ';
                    _flag = 1;
                }
                else if(_flag == 1 && *(line+i) == '_'){
                    *(line+i) = '\0';
                    m_time = atoi(line+i+1);
                    puts(line);
                    strptime(line, "%Y-%m-%d %H:%M:%S", &tm);
                    printf("mktime:%ld\n", mktime(&tm));
                    _flag = 2;
                }
                i++;
            }while(_flag < 2);
            if(time_f == 0){
                if(action_list == NULL){
                    cur_action = (struct action*)malloc(sizeof (struct action));
                    if(cur_action == NULL){
                        err_quit("malloc error");
                    }
                    action_list = cur_action;
                }
                else{
                    cur_action->next = (struct action*)malloc(sizeof (struct action));
                    cur_action = cur_action->next;
                }
                cur_action->start_time = mktime(&tm) * 1000 + (int)(m_time / 1000000);
                time_f = 1;
            }
            else{
                cur_action->end_time = mktime(&tm) * 1000 + (int)(m_time / 1000000);
                time_f = 0;
                
            }
            continue;
        }
        // read action
        if(time_f == 1){
            strcpy(cur_action->action, line);
            time_f = 2;
        }
    }while(strcmp(end_string, line) != 0);
   
    
}

int 
main(void){
    if(init_connect_manage() < 0){
        err_quit("connection initialized failed");
    }
    if(connect_server() < 0){
        err_quit("connect to server failed");
    }
    
    struct cfg_feature_set cfs;
    memset(&cfs, 0x00, sizeof cfs);

    unsigned char fs[] = {SA, DA, PR, SP, DP, TIME_START, TIME_END, 
                PACKETS};
    cfs.no_ft = sizeof fs;

    for(int i=0; i<cfs.no_ft; i++){
        cfs.f_features[fs[i]] = 1;
    }

    if(config_server(&cfs) < 0){
        err_quit("configure to server failed");
    }

    if(restore_server() < 0){
        err_quit("restore service failed");
    }

    init_receive_feature_service();

    // if((file = fopen("./lab_task.csv", "w+")) == NULL){
    //     err_quit("cann't open file");
    // }
    // read_logfile();
    // // for(struct action *a = action_list; a!= NULL; a=a->next){
    // //     printf("action:%s, start_time:%ld, end_time:%ld\n", a->action, a->start_time, a->end_time);
    // // }

    // fprintf(file, "flow_number,action,packets_length_total\n");
    dispatch(handler, NULL);
}

