#include    <stdio.h>
#include    <string.h>
#include    <stdlib.h>
#define __USE_XOPEN     // for use strptime function
#include    <time.h>
#undef __USE_XOPEN
#include    "include/connect_manage.h"
#include    "include/dispatch.h"
#include    "include/error.h"
#include    "include/feature.h"
#include    "include/fnetlib.h"
#include    "debug.h"



// for packets feature in a flow record
struct packets{
    int no_pkt;
    struct packet_info *packets;
};

// denote each packet in a flow record
struct packet_info{
    int size;
    int dir; /*  0 for inbound. 1 for outbound*/
    int ms_time;
};

// denote each action in logfile
struct action{
    time_t start_time;
    time_t end_time;
    char action[128];
    struct action *next;
};

struct action *action_list;

/*
 * {"b":pkt_len,"dir":"<","ipt":ipt}
 * {"rep":65536-pkt_len,"dir":"<", "ipt":ipt}
 */
static int 
get_packet_info(const char *str, struct packet_info * pi){

    int size_offset = 5, dir_offset, time_offset;
    char num_str[256];
    if(fnet_atoi(&pi->size, str + size_offset) == -1){
        size_offset += 2;
        // handle rep
        if(fnet_atoi(&pi->size, str + size_offset) == -1){
            err_quit("in function get_packet_info: cannot parse packet string: %s", str);  
        }
       
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
        err_quit("in function get_packet_info: cannot parse packet string: %s", str);  
    }

    time_offset = dir_offset + 9;
    if(fnet_atoi(&pi->ms_time, str + time_offset) == -1){
        err_quit("in function get_packet_info: cannot parse packet string: %s", str);  
    }
    return 0;
}

/*
 * parse packet feature with following format
 */
struct packets *
parse_packets(const char * str_pkts){
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

    get_packet_info(pkt_str, pkts->packets + pkt_count);
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

char * data_file = "TWdata200_2";


void 
lab_task_data_traffic_handler(const unsigned char* arg, struct feature_set * fts){

    // we regard the stream whose receiving time is less than 1s as the stream in the same pcap file 
    if(last_handler_time == -1 || time(NULL) - last_handler_time > 1){
        char file_path[256];
        last_handler_time = time(NULL);

        sprintf(file_path, "../%s_feature/%d.csv", data_file, csv_file_count);
        if((file = fopen(file_path, "w+")) == NULL){
            err_quit("cannot open file");
        }
        fprintf(file, "flow_number,action,packets_length_total,filename,protocol,sip,dip,sport,dport\n");

        sprintf(file_path, "../%s/%d/logs/%d.log", data_file, csv_file_count, csv_file_count);
        puts(file_path);
        read_logfile(file_path);

        csv_file_count++;
        flow_count = 1;
        
    }
    char start_timebuf[256], end_timebuf[256];
    time_t ms_start_flow, ms_end_flow;

    if(fts->f_feature[TIME_START] && fts->f_feature[TIME_END]){
        double start_time = atof(fts->features[TIME_START]->ft_val);
        double end_time = atof(fts->features[TIME_END]->ft_val);

        ms_start_flow = (time_t)(start_time * 1000); 
        ms_end_flow = (time_t)(end_time * 1000);
        const time_t st = (int) start_time, et = (int) end_time;
        strftime(start_timebuf, 256, "%Y-%m-%d_%H:%M:%S\0", localtime(&st));
        strftime(end_timebuf, 256, "%Y-%m-%d_%H:%M:%S\0", localtime(&et));
        
        
    } else{
        return;
    }
    
    // parse packets feature
    struct packets * pkts = parse_packets(fts->features[PACKETS]->ft_val);
    if(pkts == NULL){
        err_msg("error");
        return;
    }
    
    for(struct action *a = action_list; a!= NULL; a=a->next){
        //printf("action:%s, start_time:%ld, end_time:%ld\n", a->action, a->start_time, a->end_time);
        int it = 0;
        int valid_f = 0;
        for(int i=0; i < pkts->no_pkt; i++){
            it += pkts->packets[i].ms_time;
            time_t pkt_time = ms_start_flow + it;
            if(pkt_time > a->start_time && pkt_time < a->end_time){
                if(!valid_f){
                    fprintf(file, "%d,%s,\"[", flow_count, a->action);
                    if(pkts->packets[i].dir == 0){
                        fprintf(file, "%d" , pkts->packets[i].size);
                    }
                    else{
                        fprintf(file, "-%d", pkts->packets[i].size);
                    }
                    valid_f = 1;
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
        if(valid_f){
            fprintf(file, "]\"");
            fprintf(file, ",%d.pcap", csv_file_count-1);
            fprintf(file, ",%s,%s,%s,%s,%s\n", fts->features[PR]->ft_val, 
                                    fts->features[SA]->ft_val,
                                    fts->features[DA]->ft_val,
                                    fts->features[SP]->ft_val,
                                    fts->features[DP]->ft_val);
        }   
        
    }
    
    flow_count++;
    fflush(file);
}

#define LOGFILE_MAX_LINE 256
#define LOGFILE_START_STRING    "#start"
#define LOGFILE_END_STRING  "#end"
/*
 * format of logfile
 *  #start
 * 
 *  start time of action
 *  action
 *  end time of action
 * 
 *  [repeat]....
 * 
 *  #end
 * 
 */
int
read_logfile(char *file_path){
    FILE * file = NULL;
    char line[LOGFILE_MAX_LINE];
    struct tm tm;
    int action_flag = 0, time_f = 0;
    struct action * cur_action;

    action_list = NULL;
    if((file = fopen(file_path, "r")) == NULL){
        err_quit("cannot open logfile");
    }
    do{
        // handle illegal logfile
        if(feof(file)){
            if(action_flag){
                err_quit("In function read_logfile: %s do not have string %s", file_path, LOGFILE_END_STRING);
            }
            else{
                err_quit("In function read_logfile: %s do not have string %s", file_path, LOGFILE_START_STRING);
            }
        }
        fgets(line, 256, file);
        line[strlen(line)-1] = '\0';
        if(strcmp(LOGFILE_END_STRING, line) == 0){
            break;
        }
        puts(line);
        if(action_flag == 0 && strcmp(LOGFILE_START_STRING, line) == 0){
            action_flag = 1;
            time_f = 0;
            continue;
        }
        
        else if(action_flag == 0){
            continue;
        }
        // empty line(no letter) may have a blank
        if(strlen(line) <= 1){ 
            continue;
        }

        // read start time of action || read end time of action
        if(time_f == 0 || time_f == 2){
            time_t time;
            int  m_time;
            char * ms_str;

            memset(&tm, 0, sizeof(struct tm)); // **no initialization will make the reture value of function mktime be -1**
            ms_str = strptime(line, "%Y-%m-%d_%H:%M:%S", &tm);
            if(ms_str == NULL){
                err_quit("In function read_logfile: cannot parse time string %s", line);
            }
            if(fnet_atoi(&m_time, ms_str + 1) == -1){ // skip '_' character
                err_quit("In function read_logfile: cannot parse time string %s", line);
            }
            // check return value of function mktime 
            if((time = mktime(&tm)) == -1){
                err_quit("In function read_logfile: value of mktime returns is -1");
            }
            printf("value of mktime returns:%ld\nmillsecond:%d\n", time, m_time);
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
                cur_action->start_time = time * 1000 + (int)(m_time / 1000000);
                time_f = 1;
            }
            else{
                cur_action->end_time = time * 1000 + (int)(m_time / 1000000);
                time_f = 0;
                
            }
            continue;
        }
        // read action
        if(time_f == 1){
            strcpy(cur_action->action, line);
            time_f = 2;
        }
    }while(1);
}


int 
main(int argc, char * argv[]){
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
    dispatch(lab_task_data_traffic_handler, NULL);
}

