#ifndef _LIBFNET_H_
#define _LIBFNET_H_

#include    "feature.h"

int fnet_connect();

int fnet_config(const struct cfg_feature_set * ft_set);

int fnet_start();

int fnet_pause();

int fnet_restore();

int fnet_dispatch(int loop, feature_handler, unsigned char hdl_args);

#endif