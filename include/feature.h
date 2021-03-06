#ifndef _FEATURE_H_
#define _FEATURE_H_

/*
  all feature codes in flow record 
*/
#define SA      1
#define DA      2
#define PR      3
#define SP      4
#define DP      5
#define BYTES_OUT       6
#define NUM_PKTS_OUT        7
#define BYTES_IN        8
#define NUM_PKTS_IN         9
#define TIME_START      10
#define TIME_END        11
#define PACKETS     12
#define BYTE_DIST      13
#define BYTE_DIST_MEAN     14
#define BYTE_DIST_STD      15
#define ENTROPY     16
#define TOTAL_ENTROPY       17
#define P_MALWARE       18
#define IP      19
#define TCP     20
#define OSEQ        21
#define OACK        22
#define ISEQ        23
#define IACK        24
#define PPI     25
#define FRINTERPRINTS       26
#define WHT     27
#define DNS     28
#define SSH     29
#define TLS     30
#define DHCP        31
#define DHCPV6      32
#define HTTP        33
#define IKE     34
#define PAYLOAD     35
#define EXE     36
#define HD      37
#define PROBABLE_OS     38
#define IDP_OUT     39
#define IDP_LEN_OUT     40
#define IDP_IN      41
#define IDP_LEN_IN      42
#define DEBUG       43
#define EXPIRE_TYPE     44

#define NO_FEATURE 44



struct cfg_feature_set{
    int no_ft;
    unsigned char f_features[NO_FEATURE + 1]; 
};


struct feature_{
    unsigned char ft_code;
    unsigned short ft_len; // length of feature string
    char * ft_val;  // feature string;
};

struct feature_set{
    int no_ft;
    unsigned char f_feature[NO_FEATURE + 1];
    struct feature_ *features[NO_FEATURE + 1];
};

#define empty_feature_set(fsp)   do{      \
                                    for(int i=0; i<=NO_FEATURE; i++){ \
                                        fsp->f_feature[i] = 0; \
                                        fsp->features[i] = NULL; \
                                    }   \
                                    fsp->no_ft = 0;   \
                                }while(0);

const char *feature_name(int feature_code);
#endif
