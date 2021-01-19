#include    <stdio.h>
#include    <string.h>
#include    <stdlib.h>
#include    <time.h>

#include    "include/connect_manage.h"
#include    "include/dispatch.h"
#include    "include/error.h"
#include    "include/feature.h"
#include    "include/fnetlib.h"
#include    "debug.h"



struct debug{
    int tcp_retrans;
};

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
    char start_time_str[128];
    char ent_time_str[128];
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
    if(fnet_atoi(&pi->size, str + size_offset) == -1){
        err_quit("error");
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
    if(fnet_atoi(&pi->ms_time, str + time_offset) == -1){
        err_quit("error");
        return -1;
    }

    return 0;
}

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

    get_packet_size_dir_time(pkt_str, pkts->packets + pkt_count);
    pkt_count++;
    if(pkt_count == num_pkt){
        return pkts;
    }
    offset++;
    goto more;


    
}
FILE * file, *json_output_file;


struct debug *
parse_debug(const char * str_debug){
    if (str_debug == NULL){
        return NULL;
    }
    int tcp_retrans_offset = 2, retrans_val_offset = 15;
    int retrans_val;
    struct debug * debug;
    if(strncmp("tcp_retrans", str_debug + tcp_retrans_offset, 11) != 0){
        err_quit("In function parse_debug: cannot parse debug feature string: %s", str_debug);
    }

    if(fnet_atoi(&retrans_val, str_debug + retrans_val_offset) == -1){
        err_quit("In function parse_debug: cannot parse debug feature string: %s", str_debug);
    }
    debug = (struct debug*)malloc(sizeof (struct debug));
    debug->tcp_retrans = retrans_val;
    return debug;

}
FILE * csv_file;
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

// 
time_t last_handler_time = -1;
int csv_file_count =1;

int flow_count;

char * data_file = "TWdata200_2";
int num_packet = 0;
int num_pkt_in_out = 0;
int num_retrans = 0;

void handler(const unsigned char* arg, struct feature_set * fts){


    // if it's the first time to call handler, open a csv file and parse the corresponding log file
    if(last_handler_time == -1 || time(NULL) - last_handler_time > 1){
        char file_path[256];
        last_handler_time = time(NULL);
        sprintf(file_path, "../%s_feature/%d.csv", data_file, csv_file_count);
        if((file = fopen(file_path, "w+")) == NULL){
            err_quit("cannot open file");
        }
        sprintf(file_path, "../%s/%d/logs/%d.log", data_file, csv_file_count, csv_file_count);
        puts(file_path);
        read_logfile(file_path);

 // open json output file
        sprintf(file_path, "../%s_feature/%d.txt", data_file, csv_file_count);
        if((json_output_file = fopen(file_path, "w+")) == NULL){
            err_quit("cannot open file");
        }


// end 
        csv_file_count++;
        flow_count = 1;
    // for(struct action *a = action_list; a!= NULL; a=a->next){
    //     printf("action:%s, start_time:%ld, end_time:%ld\n", a->action, a->start_time, a->end_time);
    // }

        fprintf(file, "flow_number,action,action_start_time,action_end_time,flow_start_time,flow_end_time,packets_capture_time,file\n");
    }
    char start_timebuf[256], end_timebuf[256];
    time_t ms_start_flow, ms_end_flow;

/* output information of flow*/
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
// end*/
    if(fts->f_feature[TIME_START] && fts->f_feature[TIME_END]){
        double start_time = atof(fts->features[TIME_START]->ft_val);
        double end_time = atof(fts->features[TIME_END]->ft_val);

        ms_start_flow = (time_t)(start_time * 1000); 
        ms_end_flow = (time_t)(end_time * 1000);
        const time_t st = ms_start_flow / 1000, et = ms_end_flow /1000 ;
        strftime(start_timebuf, 256, "%Y-%m-%d_%H:%M:%S\0", localtime(&st));
        strftime(end_timebuf, 256, "%Y-%m-%d_%H:%M:%S\0", localtime(&et));   
    }
    
    struct packets * pkts = parse_packets(fts->features[PACKETS]->ft_val);
    /*struct debug * debug = parse_debug(fts->features[DEBUG]->ft_val);
    if(debug != NULL) num_retrans += debug->tcp_retrans;
    // test
   /* int num1;
    if(fnet_atoi(&num1, fts->features[NUM_PKTS_IN]->ft_val) == -1){
        err_quit("eror");
    }
    num_pkt_in_out += num1;
    if(fnet_atoi(&num1, fts->features[NUM_PKTS_OUT]->ft_val) == -1){
        err_quit("eror");
    }
    num_pkt_in_out += num1;
    //end*/
    for(int i =0; i<pkts->no_pkt; i++){
        //fprintf(stderr, "%d ", pkts->packets[i].size);
        num_packet++;
    }/*
    fprintf(stderr, "\n");*/
    fprintf(stderr, "number of packets: %d\n", num_packet);
    fprintf(stderr, "number of flows %d\n", flow_count);
    
    /*printf("num_retrans:%d\n", num_retrans);*/
   
    
    if(pkts == NULL){
        err_msg("error");
        return;
    }
    
    int match_action_f = 0;
    for(struct action *a = action_list; a != NULL; a=a->next){
                
        int it = 0;  // interval time
        int valid_f = 0;    
        for(int i=0; i < pkts->no_pkt; i++){
            
            it += pkts->packets[i].ms_time;
            time_t pkt_time = ms_start_flow + it;
            if(pkt_time > a->start_time && pkt_time < a->end_time){
                match_action_f = 1;
                if(!valid_f){
                    fprintf(file, "%d,%s", flow_count, a->action);
                    fprintf(file, ",%s,%s,%s_%d,%s_%d,\"[", a->start_time_str, a->ent_time_str, start_timebuf, ms_start_flow%1000 , end_timebuf, ms_end_flow%1000);
                    //fprintf(file, ",%ld,%ld,%ld,%ld,\"[", a->start_time, a->end_time, ms_start_flow, ms_end_flow);

                    if(pkts->packets[i].dir == 0){
                        fprintf(file, "%d(%d)" , pkts->packets[i].size, it);
                    }
                    else{
                        fprintf(file, "-%d(%d)", pkts->packets[i].size, it);
                    }
                    valid_f = 1;
                    continue;
                }
                if(pkts->packets[i].dir == 0){
                    fprintf(file, ", %d(%d)", pkts->packets[i].size, it);
                }
                else{
                    fprintf(file, ", -%d(%d)", pkts->packets[i].size, it);
                }

                
            }
        }
        if(valid_f){
            fprintf(file, "]\"");
            fprintf(file, ",%d.pcap\n", csv_file_count-1);
            

            
            /*fprintf(file, ",%s,%s,%s,%s,%s\n", fts->features[PR]->ft_val, 
                                    fts->features[SA]->ft_val,
                                    fts->features[DA]->ft_val,
                                    fts->features[SP]->ft_val,
                                    fts->features[DP]->ft_val);
            */
            if(strcmp(fts->features[PR]->ft_val, "6")){
                fflush(file);
                getchar();
            }
        }   
        
        
    }
    if(!match_action_f){
        fprintf(file, "%d,null", flow_count);
        fprintf(file, ",null,null,%s_%d,%s_%d,\"[", start_timebuf, ms_start_flow%1000 , end_timebuf, ms_end_flow%1000);
        int it = 0;
        for(int i=0; i < pkts->no_pkt; i++){
            it += pkts->packets[i].ms_time;
            time_t pkt_time = ms_start_flow + it;
            if(pkts->packets[i].dir == 0){
                fprintf(file, ",%d(%d)" , pkts->packets[i].size, it);
            }
            else{
                fprintf(file, ",-%d(%d)", pkts->packets[i].size, it);
            }
        }
        fprintf(file, "]\"");
        fprintf(file, ",%d.pcap\n", csv_file_count-1);

    }
    flow_count++;
    fflush(file);
}

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
#define LOGFILE_MAX_LINE 256

#define LOGFILE_START_STRING    "#start"
#define LOGFILE_END_STRING  "#end"
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
                    strptime(line, "%Y-%m-%d %H:%M:%S", &tm);
                    //printf("mktime:%ld\n", mktime(&tm));
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
                memcpy(cur_action->start_time_str, line, strlen(line) + 1); // copy action time str include null character
                time_f = 1;
            }
            else{
                cur_action->end_time = mktime(&tm) * 1000 + (int)(m_time / 1000000);
                memcpy(cur_action->ent_time_str, line, strlen(line) + 1); 
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
main(int args, char *argv[]){
    if (args != 2){
        err_quit("lab_task arguments error");
    }
    if(NULL == (csv_file = fopen(argv[1], "w+"))){
        err_quit("Canont open file %s", argv[1]);
    }

    fprintf(csv_file, "src ip,dst ip,src port,dst port,protocol,packets\n");

    if(init_connect_manage() < 0){
        err_quit("connection initialized failed");
    }
    if(connect_server() < 0){
        err_quit("connect to server failed");
    }
    
    struct cfg_feature_set cfs;
    memset(&cfs, 0x00, sizeof cfs);

    unsigned char fs[] = {SA, DA, PR, SP, DP, PACKETS};
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

   

    dispatch(lab_task_share_handle, NULL);
    return 0;
    /*char *pkt_str = "[{\"b\":46,\"dir\":\">\",\"ipt\":0},{\"b\":0,\"dir\":\"<\",\"ipt\":0},{\"b\":0,\"dir\":\">\",\"ipt\":2307},{\"b\":38,\"dir\":\"<\",\"ipt\":0},{\"b\":0,\"dir\":\">\",\"ipt\":0},{\"b\":554,\"dir\":\"<\",\"ipt\":0},{\"b\":0,\"dir\":\"<\",\"ipt\":188},{\"b\":0,\"dir\":\">\",\"ipt\":0},{\"b\":0,\"dir\":\"<\",\"ipt\":1019},{\"b\":0,\"dir\":\">\",\"ipt\":2976},{\"b\":38,\"dir\":\"<\",\"ipt\":0},{\"b\":0,\"dir\":\">\",\"ipt\":0},{\"b\":0,\"dir\":\"<\",\"ipt\":0},{\"b\":0,\"dir\":\">\",\"ipt\":1023},{\"b\":38,\"dir\":\"<\",\"ipt\":0},{\"b\":0,\"dir\":\">\",\"ipt\":0},{\"b\":0,\"dir\":\"<\",\"ipt\":0},{\"b\":0,\"dir\":\">\",\"ipt\":1089},{\"b\":0,\"dir\":\"<\",\"ipt\":0},{\"b\":47,\"dir\":\">\",\"ipt\":3278},{\"b\":0,\"dir\":\"<\",\"ipt\":0}]";
    struct packets * pkts = parser_packets(pkt_str);
    
    if(pkts == NULL){
        err_quit("error");
    }
    for(int i =0; i<pkts->no_pkt; i++){
        fprintf(stdout, "%d ", pkts->packets[i].ms_time);
    }*/
}

