/*************************************************************************

    > File Name: zha_strategy.h
    > Author: lunan
    > Mail: 6616@shuncom.com 
    > Created Time: 2015�?5�?0�?星期�?16�?2�?5�? ************************************************************************/

#ifndef _SZ06_INFO_H_
#define _SZ06_INFO_H_


#include <stdio.h>
#include <libubus.h>
#include <libubox/utils.h>

typedef struct device_info_s{
	unsigned char id[21];
	unsigned char addr[9];
	int status;//0--ok;1--add;2--delete;3--waitersp;4--get dtype;5--infochange
	unsigned int ep;
	unsigned int did;
	unsigned int pid;
	struct device_info_s *next;
}sz_device_info;


enum {
	ZHA_PERMITJOIN_TIME_ATTR_SET,
	__ZHA_NWKMGR_ATTR_MAX,
};

enum {
	ZHA_GATEWAY_ATTR_ID,
	ZHA_GATEWAY_ATTR_NWKADDR,
	ZHA_GATEWAY_ATTR_CLUSTERID,
	ZHA_GATEWAY_ATTR_ATTRID,
	ZHA_GATEWAY_ATTR_ENDPOINT_ID,
	ZHA_GATEWAY_ATTR_PROFILE_ID,
	ZHA_GATEWAY_ATTR_DEVICE_ID,
	ZHA_GATEWAY_ATTR_ON,
	ZHA_GATEWAY_ATTR_BRI,
	ZHA_GATEWAY_ATTR_HUE,
	ZHA_GATEWAY_ATTR_SAT,
	ZHA_GATEWAY_ATTR_COLORTEMP,
	ZHA_GATEWAY_ATTR_WORKMODE,
	ZHA_GATEWAY_ATTR_CMDNUM,
	ZHA_GATEWAY_ATTR_NAME,
	ZHA_GATEWAY_ATTR_STATUS,
	ZHA_GATEWAY_ATTR_ZONEID,
	ZHA_GATEWAY_ATTR_RAWDATA,
	ZHA_GATEWAY_ATTR_INFAREDCODE,
	ZHA_GATEWAY_ATTR_INFAREDLEARN,
	ZHA_GATEWAY_ATTR_INFAREDCONTROL,
	ZHA_GATEWAY_ATTR_WHITELIST,
	ZHA_GATEWAY_ATTR_CHANNEL,
	ZHA_GATEWAY_ATTR_CTRL,	
	ZHA_GATEWAY_ATTR_FAN,
	ZHA_GATEWAY_ATTR_PERCENTAGE,
	ZHA_HVAC_THERMOSTAT_MODE,
	ZHA_HVAC_THERMOSTAT_VALUE,
	ZHA_HVAC_TARGET_TEMP,
	ZHA_HVAC_POWER_MODE,
	ZHA_GATEWAY_ATTR_CHILD_LOCK,
	ZHA_GATEWAY_ATTR_WORK_MODE,
#if 0
	ZHA_GATEWAY_ATTR_FEEDID,
	ZHA_GATEWAY_ATTR_ACCESSKEY,
	ZHA_GATEWAY_ATTR_SERVER,
#endif
	__ZHA_GATEWAY_ATTR_MAX,
};

enum {
	GROUP_ATTR_ID,
	GROUP_ATTR_NAME,
	GROUP_ATTR_VISIBLE,
	GROUP_ATTR_DEVICE,
	GROUP_ATTR_PROFILEID,
	GROUP_ATTR_ON,
	GROUP_ATTR_BRI,
	GROUP_ATTR_HUE,
	GROUP_ATTR_SAT,
	GROUP_ATTR_COLORTEMP,
	GROUP_ATTR_FAN,
	GROUP_THERMOSTAT_MODE,
	GROUP_THERMOSTAT_VALUE,
	GROUP_TARGET_TEMP,
	GROUP_POWER_MODE,
	__GROUP_ATTR_MAX,
};

enum {
	SCENE_ATTR_ID,
	SCENE_ATTR_GROUP_ID,
	SCENE_ATTR_ICON_ID,
	SCENE_ATTR_NAME,
	SCENE_ATTR_DEVICE,
	__SCENE_ATTR_MAX,
};


enum {
	RULE_ATTR_ID,
	RULE_ATTR_NAME,
	RULE_ATTR_STATE,
	RULE_ATTR_CREATETIME,
	RULE_ATTR_LAST_TRIGGERED,
	RULE_ATTR_TRIGGERED_COUNT,
	RULE_ATTR_CONDITION_EXPRESSION,
	RULE_ATTR_CONDITIONS,
	RULE_ATTR_ACTIONS,
	__RULE_ATTR_MAX,
};

enum {
	RULE_ATTR_COND_INDEX,
	RULE_ATTR_COND_REPEAT_TIMES,
	RULE_ATTR_COND_TYPE,
	RULE_ATTR_COND_ACT_TIME,
	RULE_ATTR_COND_ID,
	RULE_ATTR_COND_EP,
	RULE_ATTR_COND_CMD,
	RULE_ATTR_COND_OP,
	RULE_ATTR_COND_VALUE,
	__RULE_ATTR_COND_MAX,
};


enum {
	RULE_ATTR_ACT_INDEX,
	RULE_ATTR_ACT_DELAY_TIMEOUT,
	RULE_ATTR_ACT_TARGET_TYPE,
	RULE_ATTR_ACT_IEEEADDR,
	RULE_ATTR_ACT_GROUP_ID,
	RULE_ATTR_ACT_SCENE_ID,
	RULE_ATTR_ACT_ENDPOINT_ID,
	RULE_ATTR_ACT_CMD,
	RULE_ATTR_ACT_VALUE,
	__RULE_ATTR_ACT_MAX,
};

enum {
	GW_ATTR_SERVER_IP,
	GW_ATTR_SERVER_PORT,
	GW_ATTR_SAFEKEY,
	GW_ATTR_DEVTYPE,
	__GW_ATTR_MAX,
};

enum {
	ZHA_REAL_TIME,
	__ZHA_REAL_TIME_MAX,
};

enum {
	ZHA_DEBUG,
	__ZHA_DEBUG_MAX,
};

enum {
	CLOUD_ADDR,
	__CLOUD_ADDR_MAX,
};

enum {
	SHA256_TIME,
	SHA256_ID,
	SHA256_MAC,
	__SHA256_MAX,
};

enum {
	SZ06_ID,
	__SZ06_MAX,
};


pthread_mutex_t     zha_list_mutex;

//extern coordInfo_t coordInfo;


extern int	zha_get_coord_info(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int zha_get_ver(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

extern int get_SZ06ID(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

extern int add_SZ06ID(struct ubus_context *ctx, struct ubus_object *obj,
								struct ubus_request_data *req, const char *method,
								struct blob_attr *msg);


#if 0
extern int	zha_coordChangeChannel(struct ubus_context *ctx, struct ubus_object *obj, 
				struct ubus_request_data *req, const char *method, 
				struct blob_attr *msg);


extern int	zha_coordResetFactNew(struct ubus_context *ctx, struct ubus_object *obj, 
				struct ubus_request_data *req, const char *method, 
				struct blob_attr *msg);
#endif
extern int	zha_write_idlist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int	zha_delete_idlist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int	zha_get_idlist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);
#if 0
extern int zha_list(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);
#endif

#if 0
extern uint8_t ubus_is_busy;

extern int	zha_list(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern const struct blobmsg_policy zha_nwkmgr_attrs[__ZHA_NWKMGR_ATTR_MAX];

extern const struct blobmsg_policy zha_gateway_attrs[__ZHA_GATEWAY_ATTR_MAX];

extern Zstatus_t zha_list_backinfo(deviceInfo_t *device_info, uint16_t num);

extern int	zha_scan(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int	zha_cloud_report(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);


extern int	zha_coordResetFactNew(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);


extern int	zha_permitjoin(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int	zha_get_coord_info(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);


extern int	zha_leave_req(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int	zha_getAttr(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);



extern int	zha_set(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

int	zha_get_node_info(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);


extern int	zha_write_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int	zha_delete_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int	zha_get_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int	zha_enable_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int zha_group_create(struct ubus_context *ctx, struct ubus_object *obj, 
			struct ubus_request_data *req, const char *method, 
			struct blob_attr *msg);

extern int zha_group_set(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int zha_group_change(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int zha_group_list(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

extern int zha_group_delete(struct ubus_context *ctx, struct ubus_object *obj, 
			struct ubus_request_data *req, const char *method, 
			struct blob_attr *msg);


/* scene */
extern int zha_scene_create(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg);


extern int zha_scene_list(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg);

extern int zha_scene_set(struct ubus_context *ctx, struct ubus_object *obj,
  		struct ubus_request_data *req, const char *method,
  		struct blob_attr *msg);


extern int zha_scene_store(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg);


extern int zha_scene_recall(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg);

extern int zha_scene_delete(struct ubus_context *ctx, struct ubus_object *obj, 
			struct ubus_request_data *req, const char *method, 
			struct blob_attr *msg);


//rule
extern int zha_rule_create(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

extern int zha_rule_change(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

int zha_rule_enable(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

int zha_rule_get_info(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);


extern int zha_rule_list(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

extern int zha_rule_delete(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

extern int	zha_coordChangeChannel(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int	zha_clean_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int	test1(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);
extern int	zha_disable_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

extern int	zha_time_set(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

int zha_set_coord_heart_interval(unsigned short interval);

int	zha_coord_heart_Interval(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

int zha_set_min_heart_interval(unsigned short interval);

int	zha_min_heart_interval(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

int zha_set_max_heart_interval(unsigned short interval);

int	zha_max_heart_interval(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);

int zha_get_heart(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);		

int zha_get_ver(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

int zha_get_cloud_state(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

int zha_debug(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);		

int zha_cloud_addr_changed(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

int zha_get_cloud_addr(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

int zha_sha_256(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

void disable_whitelist_timer_callback(struct uloop_timeout *t);
#endif


#if 0
extern int	test2(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg);
#endif



#endif

