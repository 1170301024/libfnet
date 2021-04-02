#ifndef _PARSE_LOG_H_
#define _PARSE_LOG_H_
#define LOGFILE_MAX_LINE 256

/*
 * denote the action string with the format like{"action": "点赞", "stream_id": "175", "request": ["1057"], "response": ["1110"]}
 */
struct action{
    char name[128];
    int http_id;
    int no_req;
    int no_res;
    int request_pkt_seq[256];
    int response_pkt_seq[256];
    struct action * next;
};
struct action *read_logfile(char * file_path);
#endif