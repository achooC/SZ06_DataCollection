#ifndef _UBUS_H_
#define _UBUS_H_

#include <libubus.h>
#include <pthread.h>
#include "sz06_info.h"

extern const char date_time_format[];

extern struct ubus_context *ctx;

extern pthread_mutex_t mutex_ubus;

void ubus_init();

extern const struct blobmsg_policy rule_attrs[__RULE_ATTR_MAX] ;

extern const struct blobmsg_policy rule_cond_attrs[__RULE_ATTR_COND_MAX] ;

extern const struct blobmsg_policy rule_act_attrs[__RULE_ATTR_ACT_MAX];

extern const struct blobmsg_policy group_attrs[__GROUP_ATTR_MAX];

extern const struct blobmsg_policy scene_attrs[__SCENE_ATTR_MAX];
extern const struct blobmsg_policy real_time[__ZHA_REAL_TIME_MAX];
extern const struct blobmsg_policy cloud_debug[__ZHA_DEBUG_MAX];
extern const struct blobmsg_policy cloud_addr_changed[__CLOUD_ADDR_MAX];
extern const struct blobmsg_policy sha256[__SHA256_MAX];
extern const struct blobmsg_policy zha_gateway_attrs[__ZHA_GATEWAY_ATTR_MAX];

extern const struct blobmsg_policy sz06_id[__SZ06_MAX];

#endif

