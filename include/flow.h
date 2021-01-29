#ifndef _FLOW_H
#define _FLOW_H

#define NONEMPTY 0
#define EMPYT 1
#define RESERVED 2

#define empty_feature(x) (x.flags = EMPTY)

struct feature_mask{
    unsigned int fm_low;
    unsigned int fm_mid;
    unsigned int fm_high;
};
/*
 * before invoking the micro you should check the code of the feature so that the value of it is not
 * beyond NO_FEATURE
 */
#define get_fm(f, c) (((int *)(&f))[c/32] & (1 << (c % 32u)))

#define mask_fm(f, c) (((int *)(&f))[c/32] |= (1 << (c % 32u)))

#define delete_fm(f, c) (((int *)(&f))[c/32] ^= (1 << c % 32u))

#define empty_fm(f) f.fm_low = 0; f.fm_mid = 0; f.fm_high = 0

struct feature{
  int flags;
  int code;
  char * name;
  char * value;
  short val_len;  
};

struct flow_record{
  /* number of features in a flow record*/
  int no_feature;

  struct feature_mask fm;
  
  struct feature features[NO_FEATURE+1];


};

typedef void (*feature_handler)(const unsigned char *, struct feature_set*);

void init_flow_record(struct flow_record *record);

void free_flow_record(struct flow_record *record);

int json_string2flow_record(struct flow_record *flow_record, char *str);

void 
flow_distribute(feature_handler handler);

void flow_record2json_string(struct flow_record *flow_record, char **str);

int feature_code(char *feature);

const char * feature_name(int code);

#endif


