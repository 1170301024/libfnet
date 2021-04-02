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
#include    "include/libfnet.h"
#include    "include/lablib.h"
#include    "include/parse_log.h"
#include    "include/tls.h"

struct action_tls_map{
    struct action * action;
    int no_req_tls;
    int no_res_tls;
    struct {
        int tls_seq;
        int tls_len;
    } tls_req[128], tls_res[128];
    struct action_tls_map * next;
};
struct action * read_logfile(char * file_path);
/*
// denote each action in logfile
struct action{
    time_t start_time;
    time_t end_time;
    char action[128];
    struct action *next;
};

struct action *action_list;*/

FILE * file;
/*
// 
time_t last_handler_time = -1;
int csv_file_count =1;

int flow_count;

char * data_file = "TWdata200_2";
*/
/*
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
/*int
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
        }
    }while(1);
}*/


static FILE * csv_file;

void lab_task_share_handle(const unsigned char* arg, struct feature_set * fts){

    /*
     * Estimate the TCP application protocol
     * Optimization: stop after first 2 packets that have non-zero payload
     */
    
    if (fts->f_feature[TLS] == 0)   return ;

    struct tls_srlt * srlt;

    int * tcp_len_arr;
    int * tls_len_arr;

    struct packets * pkts = parse_packets(fts->features[PACKETS]->ft_val);

    if(pkts == NULL) return ;
    tcp_len_arr = (int *) calloc(pkts->no_pkt, sizeof (int));
    int valid_f = 0;
    /*fprintf(csv_file, "%s,%s,%s,%s,%s", fts->features[SA]->ft_val,
                                    fts->features[SP]->ft_val,
                                    fts->features[DA]->ft_val,
                                    fts->features[DP]->ft_val,
                                    fts->features[PR]->ft_val);
    fprintf(csv_file, ",\"[");
    
    for(int i=0; i < pkts->no_pkt; i++){  
        if(!valid_f){
            if(pkts->packets[i].dir == 0){
                fprintf(csv_file, "%d" , pkts->packets[i].size);
                
            }
            else{
                fprintf(csv_file, "-%d", pkts->packets[i].size);
                
            }
            valid_f = 1;
            tcp_len_arr[i] = (pkts->packets[i].dir==0 ? 1 : -1) * pkts->packets[i].size;
            continue;
        }
        if(pkts->packets[i].dir == 0){
            fprintf(csv_file, ",%d", pkts->packets[i].size);
        }
        else{
            fprintf(csv_file, ",-%d", pkts->packets[i].size);

        }
        tcp_len_arr[i] = (pkts->packets[i].dir==0 ? 1 : -1) * pkts->packets[i].size;
    }
    fprintf(csv_file, "]\",\"[");*/
    fprintf(csv_file, "\"[");
    valid_f = 0;
    //puts(fts->features[TLS]->ft_val);
    srlt = parse_tls_srlt(fts->features[TLS]->ft_val);
    tls_len_arr = (int *)calloc(srlt->no_items, sizeof (int));
    for(int i=0; i < srlt->no_items; i++){  
        if(!valid_f){
            if(srlt->items[i].dir == 0){
                fprintf(csv_file, "%d" , srlt->items[i].b);
            }
            else{
                fprintf(csv_file, "-%d", srlt->items[i].b);

            }
            valid_f = 1;
            tls_len_arr[i] = (!srlt->items[i].dir ? 1 : -1) * srlt->items[i].b;
            continue;
        }
        if(srlt->items[i].dir == 0){
            fprintf(csv_file, ",%d", srlt->items[i].b);
        }
        else{
            fprintf(csv_file, ",-%d", srlt->items[i].b);

        }
        tls_len_arr[i] = (!srlt->items[i].dir ? 1 : -1) * srlt->items[i].b;
    }
    fprintf(csv_file, "]\"\n");
    fflush(csv_file);
    tcp2tls_seq_dict(tcp_len_arr, pkts->no_pkt, tls_len_arr, srlt->no_items);
    /*for(int i = 0;i<pkts->no_pkt; i++){
        printf("%d, ", tcp_len_arr[i]);
    }
    puts("\n");
    for (int i =0; i<srlt->no_items; i++){
        printf("%d, ", tls_len_arr[i]);
    }*/


}

void lab_task_tls_tcp_handle(const unsigned char* arg, struct feature_set * fts){
    if (fts->f_feature[TLS] == 0)   return ;

    char filename[256];
    FILE * csv_file_fp;

    int * tcp_len_arr;
    int * tls_len_arr;
    struct packets * pkts;
    struct tls_srlt * srlt;
    struct packetR_tcp2tls * r_result;

    // parser packets feature
    pkts = parse_packets(fts->features[PACKETS]->ft_val);
    if(pkts == NULL) return ;
        tcp_len_arr = (int *) calloc(pkts->no_pkt, sizeof (int));

    // get tcp packet length
    for(int i=0; i < pkts->no_pkt; i++){  
        tcp_len_arr[i] = (!pkts->packets[i].dir ? 1 : -1) * pkts->packets[i].size;
    }
    
    // parse tls srlt feature
    srlt = parse_tls_srlt(fts->features[TLS]->ft_val);
    // puts(fts->features[TLS]->ft_val);
    tls_len_arr = (int *)calloc(srlt->no_items, sizeof (int));

    // get tls packet length
    for(int i=0; i < srlt->no_items; i++){  
        tls_len_arr[i] = (!srlt->items[i].dir ? 1 : -1) * srlt->items[i].b;
    }
    
    r_result = tcp2tls_seq_dict(tcp_len_arr, pkts->no_pkt, tls_len_arr, srlt->no_items);
    sprintf(filename, "./csv_result/%s_%s_%s_%s", fts->features[SA]->ft_val,
                                    fts->features[SP]->ft_val,
                                    fts->features[DA]->ft_val,
                                    fts->features[DP]->ft_val);
    if(NULL == (csv_file_fp = fopen(filename, "w+"))){
        err_quit("Canont open file %s", filename);
    }
    int i = 1;
    for(struct dict_item_tcp2tls *item = r_result->dict_item; item!= NULL; item = item->next){
        fprintf(csv_file_fp, "%d,%d,[", item->tcp_no + 1, tcp_len_arr[item->tcp_no]);
        for(int c=0; c<item->num_tls_no; c++){
            //fprintf(csv_file_fp, "%d,", i++);
           
            fprintf(csv_file_fp, "(%d,%d),", item->tls_no[c] + 1, tls_len_arr[item->tls_no[c]]);
        }
        fprintf(csv_file_fp, "]\n");
    }
    
    fflush(csv_file_fp);
}

char * logfile;
char * result_file_up;
char * result_file_down;
void lab_task_tls_tcp_handle2(const unsigned char* arg, struct feature_set * fts){
    if (fts->f_feature[TLS] == 0)   return ;

    int * tcp_len_arr;
    int * tls_len_arr;
    struct packets * pkts;
    struct tls_srlt * srlt;
    struct packetR_tcp2tls * r_result;

    // parser packets feature
    pkts = parse_packets(fts->features[PACKETS]->ft_val);
    if(pkts == NULL) return ;
        tcp_len_arr = (int *) calloc(pkts->no_pkt, sizeof (int));

    // get tcp packet length
    for(int i=0; i < pkts->no_pkt; i++){  
        tcp_len_arr[i] = (!pkts->packets[i].dir ? 1 : -1) * pkts->packets[i].size;
    }
    
    // parse tls srlt feature
    srlt = parse_tls_srlt(fts->features[TLS]->ft_val);
    // puts(fts->features[TLS]->ft_val);
    tls_len_arr = (int *)calloc(srlt->no_items, sizeof (int));

    // get tls packet length
    for(int i=0; i < srlt->no_items; i++){  
        tls_len_arr[i] = (!srlt->items[i].dir ? 1 : -1) * srlt->items[i].b;
    }
    
    r_result = tcp2tls_seq_dict(tcp_len_arr, pkts->no_pkt, tls_len_arr, srlt->no_items);
    struct action * actions = read_logfile(logfile);
    struct action_tls_map * map = NULL;
    struct action_tls_map *cur_lct_map, * prev_map;
    int t[128];
    int l[128];
    int cnt = 0;
    for (struct action * a = actions; a != NULL; a=a->next){
        cur_lct_map = (struct action_tls_map *) calloc(1, sizeof (struct action_tls_map));
        cur_lct_map->action = a;
        cnt = 0;
       
        for(int i =0; i<a->no_req; i++){
            for(struct dict_item_tcp2tls *item = r_result->dict_item; item!= NULL; item = item->next){
                if(a->request_pkt_seq[i] == (item->tcp_no+1)){
                    for(int c=0; c<item->num_tls_no; c++){
                        for (int m=0; m<cnt; m++){
                            if(t[m] == item->tls_no[c]){
                                goto next_item1;
                            }
                        }
                        t[cnt] = item->tls_no[c];
                        l[cnt] = tls_len_arr[item->tls_no[c]];
                        cnt++;
                    next_item1:
                        ;
                    }
                }
            }
        }
        for(int m=0; m<cnt; m++){
            cur_lct_map->tls_req[cur_lct_map->no_req_tls].tls_seq = t[m];
            cur_lct_map->tls_req[cur_lct_map->no_req_tls].tls_len = l[m];
            cur_lct_map->no_req_tls++;
            
        }
        cnt = 0;
        for(int i =0; i<a->no_res; i++){
            for(struct dict_item_tcp2tls *item = r_result->dict_item; item!= NULL; item = item->next){
                if(a->response_pkt_seq[i] == (item->tcp_no+1)){
                    for(int c=0; c<item->num_tls_no; c++){
                        for (int m=0; m<cnt; m++){
                            if(t[m] == item->tls_no[c]){
                                goto next_item;
                            }
                        }
                        t[cnt] = item->tls_no[c];
                        l[cnt] = tls_len_arr[item->tls_no[c]];
                        cnt++;
                    next_item:
                        ;
                    }
                }   
            }             
        }
        for(int m=0; m<cnt; m++){
            cur_lct_map->tls_res[cur_lct_map->no_res_tls].tls_seq = t[m];
            cur_lct_map->tls_res[cur_lct_map->no_res_tls].tls_len = l[m];
            cur_lct_map->no_res_tls++;
            
        }
        if (map == NULL){
            map = cur_lct_map;
        }
        else{
            prev_map->next = cur_lct_map;
        }
        prev_map = cur_lct_map;
    }
    FILE * up_fp, *down_fp;
    if((up_fp = fopen(result_file_up, "w")) == NULL){
        err_quit("cannot open logfile");
    }
    if((down_fp = fopen(result_file_down, "w")) == NULL){
        err_quit("cannot open logfile");
    }
    fprintf(up_fp, "tls seq, tls len, action\n");
    fprintf(down_fp, "tls seq, tls len, action\n");
    int flag_o_up, flag_o_down;
    for(int n=0; n<srlt->no_items; n++){   
        flag_o_up = flag_o_down = 0; // represent not find
        for(struct action_tls_map * atm = map; atm != NULL; atm = atm->next){
            for(int i=0; !flag_o_up &&  i<atm->no_req_tls;i++){
                if(n == atm->tls_req[i].tls_seq){
                    flag_o_up = 1; // find
                    fprintf(up_fp, "%d,%d,%s\n", n+1, abs(atm->tls_req[i].tls_len), atm->action->name);
                }    
            }
            for(int i=0; !flag_o_down && i<atm->no_res_tls;i++){
                if(n+1 == atm->tls_res[i].tls_seq){
                    flag_o_down = 1;
                    fprintf(down_fp, "%d,%d,%s\n", n+1, abs(atm->tls_res[i].tls_len), atm->action->name);
                }
                
            }
            if(flag_o_up || flag_o_down){
                break;
            }
        }
        if(!flag_o_up){
            fprintf(up_fp, "%d, %d\n", n+1, abs(tls_len_arr[n]));
        }
        if(!flag_o_down){
            fprintf(down_fp, "%d, %d\n", n+1, abs(tls_len_arr[n]));
        }
        
    }
    
    
}
int 
main(int args, char * argv[]){
    char * pcap_file;

    // if (args != 3){
    //     err_quit("lab_task arguments error");
    // }
    if(args != 5){
        err_quit("lab_task arguments error");
    }
    pcap_file = argv[1];
    logfile = argv[2];
    result_file_up = argv[3];
    result_file_down = argv[4];

    // if((file = fopen("./lab_task.csv", "w+")) == NULL){
    //     err_quit("cann't open file");
    // }
    // read_logfile();
    // // for(struct action *a = action_list; a!= NULL; a=a->next){
    // //     printf("action:%s, start_time:%ld, end_time:%ld\n", a->action, a->start_time, a->end_time);
    // // }

    // fprintf(file, "flow_number,action,packets_length_total\n");
    // dispatch(lab_task_data_traffic_handler, NULL);

    /*fputs("src ip,dst ip,src port,dst port,protocol,tcp, tls \n", csv_file);
    fflush(csv_file);*/
    //fnet_process_pcap(pcap_file, lab_task_share_handle, NULL);
    fnet_process_pcap(pcap_file, lab_task_tls_tcp_handle2, NULL);
    
    

}