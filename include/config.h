#ifndef _CONFIG_H_
#define _CONFIG_H_

#include    <stdbool.h>
#include    "map.h"
/** maximum line length */
#define LINEMAX 512

#define NULL_KEYWORD "none"
#define NULL_KEYWORD_LEN 4

#define parse_check_feature_bool(f) if (match(command, #f)) { \
    parse_check(parse_bool(&config->report_##f, arg, num));   \
     }

#define config_all_features_bool(feature_list)  MAP(parser_check_feature_bool, feature_list)

#define set_feature(f) (cfg.f = glb.f);

#define set_all_features(feature_list) MAP(set_feature, feature_list)
typedef struct configuration{
    bool ip;
    bool tcp;
    bool ppi;
    bool wht;
    bool dns;
    bool ssh;
    bool tls;
    bool dhcp;
    bool dhcpv6;
    bool http;
    bool ike;
    bool payload;
    bool idp;
    bool expire_type;

    char *outputdir;
    char *filename;
    char *logfile;
}configuration_t;

int config_set_from_argv (configuration_t *config, char *argv[], int argc);

#endif