#ifndef _TLS_H_
#define _TLS_H_

#define TLS_C_VERSION   1
#define TLS_S_VERSION   2
#define TLS_C_KEY_LENGTH    3
#define TLS_SRLT    10


struct tls_srlt_item{
    int b;  // length of tls packet in bytes
    int dir;
    int ipt;
    int tp;
    // TO-DO hs_types and hs_lens
};
struct tls_srlt{
    int no_items;
    struct tls_srlt_item * items;
};


struct tls_srlt * parse_tls_srlt(const char * str_tls);
#endif