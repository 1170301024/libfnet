#include <stdlib.h>
#include <string.h>

#include "include/lablib.h"

struct packetR_tcp2tls *
tcp2tls_seq_dict(int * tcp_len_arr, int tcp_arr_size, int * tls_len_arr, int tls_arr_size){
    int in_unmatched_tls_length = 0;
    int in_unmatched_tcp_length = 0;
    int out_unmatched_tls_length = 0;
    int out_unmatched_tcp_length = 0;
    int in_tls_loc =0;
    int out_tls_loc = 0;

    int count = 0;
    int tls_in_tcp[1380];
    struct packetR_tcp2tls * result;
    struct dict_item_tcp2tls * cur_dict_item = NULL;

    result = (struct packetR_tcp2tls *)calloc(1, sizeof (struct packetR_tcp2tls));
    
    // process tcp and tls length array
    

    for(int i=0; i < tcp_arr_size; i++){
        int *u_tcp_len, *u_tls_len, *tls_loc;
        int dir;
        count = 0;
        // if(tcp_len_arr[i] == 0)   
        //     continue;
        
        // else 
        if(tcp_len_arr[i] > 0){
            u_tcp_len = &in_unmatched_tcp_length;
            u_tls_len = &in_unmatched_tls_length;
            tls_loc = &in_tls_loc;
            dir = 1;
        }
        else{
            u_tcp_len = &out_unmatched_tcp_length;
            u_tls_len = &out_unmatched_tls_length;
            tls_loc = &out_tls_loc;
            dir = -1;
        }
        *u_tcp_len = dir==1 ? tcp_len_arr[i] : -tcp_len_arr[i];
        
        if(result->no_item == 0){
            result->dict_item = (struct dict_item_tcp2tls *)calloc(1, sizeof (struct dict_item_tcp2tls));
            cur_dict_item = result->dict_item;
        }
        else{
            cur_dict_item->next = (struct dict_item_tcp2tls *)calloc(1, sizeof (struct dict_item_tcp2tls));
            cur_dict_item = cur_dict_item->next;
        }
        result->no_item++;

        if(*u_tls_len >= *u_tcp_len){
            *u_tls_len -= *u_tcp_len;
            *u_tcp_len = 0;
            tls_in_tcp[count++] = (*tls_loc) - 1;
            cur_dict_item->tcp_no = i;
            cur_dict_item->tls_no = (int *)calloc(count, sizeof (int));
            cur_dict_item->num_tls_no = count;
            for(int n=0; n<count;n++){
                cur_dict_item->tls_no[n] = tls_in_tcp[n];
            }
            continue;
        }
        else if(*u_tls_len > 0){
            *u_tcp_len -= *u_tls_len; 
            *u_tls_len = 0;
            tls_in_tcp[count++] = (*tls_loc) - 1;
            
        }
        //printf("%d, %d, %d\n", *u_tcp_len, *u_tls_len, i);
        for(int j=*tls_loc; j<tls_arr_size;  j++){
            // revert to tcp len
            (*tls_loc)++;
            if(dir * tls_len_arr[j] < 0){
                continue;
            }

            tls_in_tcp[count++] = j;
            int tls2tcp_len = dir * tls_len_arr[j] + 5;

            
            //printf("%d, %d, %d, %d, %d\n", *u_tcp_len, *u_tls_len, tls2tcp_len, i, j);
            if(tls2tcp_len >= *u_tcp_len){
                *u_tls_len = tls2tcp_len - *u_tcp_len;
                *u_tcp_len = 0;

                cur_dict_item->tcp_no = i;
                cur_dict_item->tls_no = (int *)calloc(count, sizeof (int));
                cur_dict_item->num_tls_no = count;
                for(int n=0; n<count;n++){
                    cur_dict_item->tls_no[n] = tls_in_tcp[n];
                }
                break;
            }
            else{
                *u_tcp_len -= tls2tcp_len;
                *u_tls_len = 0;
                
                continue;
            }
            
            
        }
        if(*u_tcp_len == 0){
            continue;
        }
        else{
            printf("error");
            printf("tls_loc:%d, tls_array_len:%d", *tls_loc, tls_arr_size);
            break;
        }
    }

    /*for(struct dict_item_tcp2tls *item = result->dict_item; item!= NULL; item = item->next){
        printf("%d(%d):[", item->tcp_no + 1, tcp_len_arr[item->tcp_no]);
        for(int c=0; c<item->num_tls_no; c++){
            printf("%d(%d) ", item->tls_no[c], tls_len_arr[item->tls_no[c]]);
        }
        puts("]\n");
    }*/
    return result;
}

static void 
free_dict_item_tcp2tls(struct dict_item_tcp2tls *item){
    free(item->tls_no);
    if(item->next != NULL) {
        free_dict_item_tcp2tls(item->next);
    }
    free(item);
    return ;
}
    
// free struct packetR_tcp2tls
void free_packetR_tcp2tls(struct packetR_tcp2tls * d){
    free_dict_item_tcp2tls(d->dict_item);
    free(d);
    return ;
}