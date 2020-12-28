#ifndef _CONFIG_H_
#define _CONFIG_H_

/** maximum line length */
#define LINEMAX 512

#define NULL_KEYWORD "none"
#define NULL_KEYWORD_LEN 4

typedef struct configuration{
    bool ip;
    bool tcp;
    bool dns;
    

    char *outputdir;
    char *filename;
    char *logfile;
}configuration_t;
#endif