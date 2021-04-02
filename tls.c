#include    <stdlib.h>
#include    <string.h>
#include    <regex.h>

#include    "include/tls.h"
#include    "include/error.h"
#include    "include/fnetlib.h"

/* This function have memory leaks*/

struct tls_srlt *
parse_tls_srlt(const char * str_tls){
    int offset = 0, i = 0;
    int num_items = 0;
    int item_start, item_end;
    int item_count = 0;
    char *str_srlt;
    char item_str[128];
    int status;
    regex_t reg;
    regmatch_t pmatch[5];
    int cflags = REG_EXTENDED;

    char * srlt_pattern = "^\\{.*\"srlt\":(\\[.*])}$";
    char * item_pattern = "^\\{\"b\":([0-9]+),\"dir\":\"([><])\",\"ipt\":([0-9]+),\"tp\":([0-9]+).*}$";
    regcomp(&reg, srlt_pattern, cflags);
    status = regexec(&reg, str_tls, 2, pmatch, 0);
    if (status == REG_NOMATCH){
        err_quit("No Match\n");
        return NULL;
    }else{
        str_srlt = (char *)calloc(pmatch[1].rm_eo-pmatch[1].rm_so + 1, sizeof (char));   
        memcpy(str_srlt, str_tls+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so);
    }
    struct tls_srlt * srlt = (struct tls_srlt*)calloc(1, sizeof (struct tls_srlt));
    if(srlt == NULL){
        err_msg("calloc error");
        return NULL;
    }
    
    // count the items in srlt object
    while(*(str_srlt + i) != '\0'){
        if(*(str_srlt + i) == '{'){
            num_items++;
        }
        i++;
    }

    srlt->no_items = num_items;
    if(num_items == 0){    
        srlt->items = NULL;
        return srlt;
    }

    srlt->items = (struct tls_srlt_item *)calloc(num_items, sizeof (struct tls_srlt_item));
    if(srlt->items == NULL){
        err_msg("calloc error");
        return NULL;
    }
    if(*str_srlt != '[') return NULL;
    regcomp(&reg, item_pattern, cflags);

more:
    offset += 1;
    // if not match "{...}""
    if(*(str_srlt + offset) != '{') return NULL;

    item_start = offset;
    do{
        offset++;
    }while(*(str_srlt + offset) != '}');
    item_end = offset;
    memcpy(item_str, str_srlt + item_start, item_end -item_start + 1);
    item_str[item_end - item_start + 1] = '\0';
    status = regexec(&reg, item_str, 5, pmatch, 0);
    if (status == REG_NOMATCH){
        err_quit("regexec error :No Match");
    }else{  // THE CODE CAN BE BETTER
        char sub_ptrn_str[32];
        memcpy(sub_ptrn_str, item_str+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so); 
        sub_ptrn_str[pmatch[1].rm_eo-pmatch[1].rm_so] = '\0';
        if(fnet_atoi(&(srlt->items[item_count].b), sub_ptrn_str) == -1){
            err_quit("fnet_atoi error");
            return NULL;
        }

        if(pmatch[2].rm_eo-pmatch[2].rm_so == 1){
            char c_dir = *(item_str+pmatch[2].rm_so);
            if(c_dir == '<')
                srlt->items[item_count].dir = 0;
            else if(c_dir == '>')
                srlt->items[item_count].dir = 1;
            else{
                err_quit("match error");
                return NULL;
            } 

        }
        memcpy(sub_ptrn_str, item_str+pmatch[3].rm_so, pmatch[3].rm_eo-pmatch[3].rm_so); 
        sub_ptrn_str[pmatch[1].rm_eo-pmatch[1].rm_so] = '\0';
        if(fnet_atoi(&(srlt->items[item_count].ipt), sub_ptrn_str) == -1){
            err_quit("fnet_atoi error");
            return NULL;
        }

        memcpy(sub_ptrn_str, item_str+pmatch[4].rm_so, pmatch[4].rm_eo-pmatch[4].rm_so); 
        sub_ptrn_str[pmatch[1].rm_eo-pmatch[1].rm_so] = '\0';
        if(fnet_atoi(&(srlt->items[item_count].tp), sub_ptrn_str) == -1){
            err_quit("fnet_atoi error");
            return NULL;
        }        
    }
    
    item_count++;
    if(item_count == num_items){
        regfree(&reg);
        return srlt;
    }
    offset++;
    goto more;
    

}