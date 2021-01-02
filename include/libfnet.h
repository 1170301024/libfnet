#ifndef _LIBFNET_H_
#define _LIBFNET_H_

#include    "feature.h"
#include    "dispatch.h"

int fnet_connect(void);

int fnet_config(const struct cfg_feature_set * ft_set);

int fnet_start(void);

int fnet_pause(void);

int fnet_restore(void);

int fnet_dispatch(int loop, feature_handler, unsigned char *hdl_args);

#endif