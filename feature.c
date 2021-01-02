#include    <stdlib.h>

#include    "include/feature.h"


static char * features[NO_FEATURE+1] = {
    [0]= NULL, [1]="sa", [2]="da", [3]="pr",
    [4]="sp", [5]="dp", [6]="bytes_out", [7]="num_pkts_out", 
    [8]="bytes_in", [9]="num_pkts_in", [10]="time_start", [11]="time_end",
    [12]="packets", [13]="byte_dist", [14]="byte_dist_mean", [15]="byte_dist_std",
    [16]="entropy", [17]="total_entropy", [18]="p_malware", [19]="ip", 
    [20]="tcp", [21]="oseq", [22]="oack", [23]="iseq",
    [24]="iack", [25]="ppi", [26]="fingerprints", [27]="wht",
    [28]="dns", [29]="ssh", [30]="tls", [31]="dhcp",
    [32]="dhcpv6", [33]="http", [34]="ike", [35]="payload",
    [36]="exe", [37]="hd", [38]="probable_os", [39]="idp_out",
    [40]="idp_len_out", [41]="idp_in", [42]="idp_len_in", [43]="debug",
    [44]="expire_type"
};


const char *
feature_name(int feature_code){
    if(feature_code < 1 || feature_code > 44){
        return NULL;
    }
    return features[feature_code];
}