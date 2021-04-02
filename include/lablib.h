#ifndef _LABLIB_H_
#define _LABLIB_H_

/*
 * the role of the struct is a dictionary that key is the tcp packet number,
 * and the value of key is a list of tls packet number which payload of the tls packet
 * included in the tcp payload. 
 */

struct dict_item_tcp2tls{
    int tcp_no; // denote index from 0
    int * tls_no; // denote index from 0
    int num_tls_no;
    struct dict_item_tcp2tls * next;
};
struct packetR_tcp2tls{
    int no_item;
    struct dict_item_tcp2tls * dict_item;
};

struct packetR_tcp2tls * tcp2tls_seq_dict(int * tcp_len_arr, int tcp_arr_size, int * tls_len_arr, int tls_arr_size);
void free_packetR_tcp2tls(struct packetR_tcp2tls * d);


#endif