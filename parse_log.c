#include    <stdlib.h>
#include    <string.h>
#include    <regex.h>
#include    <stdio.h>
#include    "fnetlib.h"
#include    "include/error.h"
#include    "include/parse_log.h"



static struct action *
parse_logfile_line(char * line){
    regex_t reg;
    regmatch_t pmatch[5];
    int cflags = REG_EXTENDED;
    struct action * action;
    char temp_str[128];
    int start_lct, status;
    char * action_line_pattern = "^\\{\"action\": \"(.*)\", \"stream_id\": \"(.*)\", \"request\": \\[(.*)], \"response\": \\[(.*)]}";
    regcomp(&reg, action_line_pattern, cflags);
    status = regexec(&reg, line, 5, pmatch, 0);
    if (status == REG_NOMATCH){
        err_quit("No Match\n");
        return NULL;
    }else{
        action = (struct action *)calloc(1, sizeof (struct action));   
        if(action == NULL){
            err_quit("calloc error frome parser_logfile_line");
        }
        memcpy(action->name, line+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so);
        memset(temp_str, 0x00, sizeof temp_str);
        memcpy(temp_str, line+pmatch[2].rm_so, pmatch[2].rm_eo-pmatch[2].rm_so);
        fnet_atoi(&(action->http_id), temp_str);
        memset(temp_str, 0x00, sizeof temp_str);
        memcpy(temp_str, line+pmatch[3].rm_so, pmatch[3].rm_eo-pmatch[3].rm_so);
        start_lct = -1;
        for(int i=0; i<strlen(temp_str); i++){
            if(temp_str[i] == '\"' && start_lct == -1){
                start_lct = i + 1;
                continue;
            }
            else if(temp_str[i] == '\"'){
                temp_str[i] == '\0';
                fnet_atoi(&(action->request_pkt_seq[action->no_req]), temp_str + start_lct);
                action->no_req++;
                start_lct = -1;
            }
            if(action->no_req > sizeof action->request_pkt_seq){
                err_quit("too many requset packets error in parser_logfile_line");
            }
        }
       
        memset(temp_str, 0x00, sizeof temp_str);
        
        memcpy(temp_str, line+pmatch[4].rm_so, pmatch[4].rm_eo-pmatch[4].rm_so);
        start_lct = -1;
        for(int i=0; i<strlen(temp_str); i++){
            if(temp_str[i] == '\"' && start_lct == -1){
                start_lct = i + 1;
                continue;
            }
            else if(temp_str[i] == '\"'){
                temp_str[i] == '\0';
                fnet_atoi(&(action->response_pkt_seq[action->no_res]), temp_str + start_lct);
                action->no_res++;
                start_lct = -1;
            }
            if(action->no_res > sizeof action->response_pkt_seq){
                err_quit("too many response packets error in parser_logfile_line");
            }
        }
    }
    return action;

}
/*
 * parse the file that each line with the format like 
 * {"action": "点赞", "stream_id": "175", "request": ["1057"], "response": ["1110"]}
 */
struct action *
read_logfile(char * file_path){
    FILE * file = NULL;
    char line[LOGFILE_MAX_LINE];
    
    struct action * action_list = NULL;
    struct action * cur_action, * prev_action;

    if((file = fopen(file_path, "r")) == NULL){
        err_quit("cannot open logfile");
    }

    while(NULL != fgets(line, 256, file)){
        cur_action = parse_logfile_line(line);
        if (action_list == NULL){
            action_list = cur_action;
        }
        else{
            prev_action->next = cur_action;
        }
        prev_action = cur_action;
    }
    return action_list;
}
