/*************************************************************************
  > File Name: ubus.c
  > Author: lunan
  > Mail: 6616@shuncom.com 
  > Created Time: 2015�?5�?0�?星期�?15�?3�?2�? ************************************************************************/

#include<stdio.h>
#include <libubus.h>
#include <libubox/utils.h>
#include <libubox/blobmsg_json.h>
#include <pthread.h>
#include "ubus.h"
#include "sz06_info.h"
#include "sql_fun.h"
//#include "user_api.h"

struct ubus_context *ctx;

pthread_mutex_t mutex_ubus;

const struct blobmsg_policy zha_nwkmgr_attrs[__ZHA_NWKMGR_ATTR_MAX] = {
	[ZHA_PERMITJOIN_TIME_ATTR_SET] = { "time",BLOBMSG_TYPE_INT32},
};

const struct blobmsg_policy zha_gateway_attrs[__ZHA_GATEWAY_ATTR_MAX] = {
	[ZHA_GATEWAY_ATTR_ID] = { "id",BLOBMSG_TYPE_STRING},
	[ZHA_GATEWAY_ATTR_ENDPOINT_ID] = { "ep",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_NWKADDR] = { "nwkaddr",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_CLUSTERID] = { "clusterid",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_ATTRID] = { "attrid",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_PROFILE_ID] = { "pid",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_DEVICE_ID] = { "did",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_ON] = { "on",BLOBMSG_TYPE_BOOL},
	[ZHA_GATEWAY_ATTR_BRI] = { "bri",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_HUE] = { "hue",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_SAT] = { "sat",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_COLORTEMP] = { "ctp",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_WORKMODE] = { "workmode",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_CMDNUM] = { "cmdnum",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_NAME] = { "name",BLOBMSG_TYPE_STRING},
	[ZHA_GATEWAY_ATTR_STATUS] = { "status",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_ZONEID] = { "zid",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_RAWDATA] = { "rwd",BLOBMSG_TYPE_STRING},
	[ZHA_GATEWAY_ATTR_INFAREDCODE] = { "incd",BLOBMSG_TYPE_STRING},
	[ZHA_GATEWAY_ATTR_INFAREDLEARN] = { "inle",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_INFAREDCONTROL] = { "inct",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_WHITELIST] = { "idlist",BLOBMSG_TYPE_ARRAY},	
	[ZHA_GATEWAY_ATTR_CHANNEL] = { "channel",BLOBMSG_TYPE_INT32},

	[ZHA_GATEWAY_ATTR_CTRL] = { "ctrl",BLOBMSG_TYPE_INT32},	
	[ZHA_GATEWAY_ATTR_FAN] = { "fan",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_PERCENTAGE] = { "pt",BLOBMSG_TYPE_INT32},
	[ZHA_HVAC_THERMOSTAT_MODE] = {"mode",BLOBMSG_TYPE_INT32},
	[ZHA_HVAC_THERMOSTAT_VALUE] = {"amount",BLOBMSG_TYPE_INT32},
	[ZHA_HVAC_TARGET_TEMP] = {"tgtemp",BLOBMSG_TYPE_INT32},
	[ZHA_HVAC_POWER_MODE] = {"powermode",BLOBMSG_TYPE_INT32},
	[ZHA_GATEWAY_ATTR_CHILD_LOCK] = { "childlock",BLOBMSG_TYPE_BOOL},
	[ZHA_GATEWAY_ATTR_WORK_MODE] = { "workmode",BLOBMSG_TYPE_INT32},
};

const struct blobmsg_policy group_attrs[__GROUP_ATTR_MAX] = {
	[GROUP_ATTR_ID] = { "id", BLOBMSG_TYPE_INT32},
	[GROUP_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING},
	[GROUP_ATTR_VISIBLE] = {"visible", BLOBMSG_TYPE_INT32},
	[GROUP_ATTR_DEVICE] = { "device", BLOBMSG_TYPE_ARRAY},
	[GROUP_ATTR_PROFILEID] = { "pid", BLOBMSG_TYPE_INT32},
	[GROUP_ATTR_ON]  = { "on",  BLOBMSG_TYPE_BOOL},
	[GROUP_ATTR_BRI] = { "bri", BLOBMSG_TYPE_INT32},
	[GROUP_ATTR_HUE] = { "hue", BLOBMSG_TYPE_INT32},
	[GROUP_ATTR_SAT] = { "sat", BLOBMSG_TYPE_INT32},
	[GROUP_ATTR_COLORTEMP] = { "ctp", BLOBMSG_TYPE_INT32},
	[GROUP_ATTR_FAN] = { "fan",BLOBMSG_TYPE_INT32},
	[GROUP_THERMOSTAT_MODE] = {"mode",BLOBMSG_TYPE_INT32},
	[GROUP_THERMOSTAT_VALUE] = {"amount",BLOBMSG_TYPE_INT32},
	[GROUP_TARGET_TEMP] = {"tgtemp",BLOBMSG_TYPE_INT32},
	[GROUP_POWER_MODE] = {"powermode",BLOBMSG_TYPE_INT32},
};

const struct blobmsg_policy scene_attrs[__SCENE_ATTR_MAX] = {
	[SCENE_ATTR_ID] = { "id", BLOBMSG_TYPE_INT32},
	[SCENE_ATTR_GROUP_ID] = { "gid", BLOBMSG_TYPE_INT32},
	[SCENE_ATTR_ICON_ID] = { "icon", BLOBMSG_TYPE_INT32},
	[SCENE_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING},
	[SCENE_ATTR_DEVICE] = { "device", BLOBMSG_TYPE_ARRAY},
};


/* date-time format */
const char date_time_format[] = "%Y-%m-%dT%H:%M:%S";

const struct blobmsg_policy rule_attrs[__RULE_ATTR_MAX] = {
	[RULE_ATTR_ID] = { "id",BLOBMSG_TYPE_INT32},
	[RULE_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING},
	[RULE_ATTR_STATE] = { "state", BLOBMSG_TYPE_INT32},
	/* 2015-09-24T15:02:56 */
	[RULE_ATTR_CREATETIME] = { "ct", BLOBMSG_TYPE_STRING},
	[RULE_ATTR_LAST_TRIGGERED] = { "ltrig", BLOBMSG_TYPE_STRING},
	[RULE_ATTR_TRIGGERED_COUNT] = { "ctrig", BLOBMSG_TYPE_INT32},
	[RULE_ATTR_CONDITION_EXPRESSION] = { "exp", BLOBMSG_TYPE_STRING},
	[RULE_ATTR_CONDITIONS] = { "cond", BLOBMSG_TYPE_ARRAY},
	[RULE_ATTR_ACTIONS] = { "act", BLOBMSG_TYPE_ARRAY},
};

const struct blobmsg_policy rule_cond_attrs[__RULE_ATTR_COND_MAX] = {
	[RULE_ATTR_COND_INDEX] = { "idx", BLOBMSG_TYPE_INT32},
	[RULE_ATTR_COND_REPEAT_TIMES] = { "trig", BLOBMSG_TYPE_INT32},
	[RULE_ATTR_COND_TYPE] = { "type", BLOBMSG_TYPE_INT32},
	/* 2015-09-24T15:02:56 */
	[RULE_ATTR_COND_ACT_TIME] = { "time", BLOBMSG_TYPE_STRING},
	[RULE_ATTR_COND_ID] = { "id", BLOBMSG_TYPE_STRING},
	[RULE_ATTR_COND_EP] = { "ep", BLOBMSG_TYPE_INT32},
	[RULE_ATTR_COND_CMD] = { "cmd", BLOBMSG_TYPE_STRING},
	[RULE_ATTR_COND_OP] = { "op", BLOBMSG_TYPE_STRING},
	[RULE_ATTR_COND_VALUE] = { "val", BLOBMSG_TYPE_STRING},
};


const struct blobmsg_policy rule_act_attrs[__RULE_ATTR_ACT_MAX] = {
	[RULE_ATTR_ACT_INDEX] = { "idx", BLOBMSG_TYPE_INT32},
	[RULE_ATTR_ACT_DELAY_TIMEOUT] = { "delay", BLOBMSG_TYPE_INT32},
	[RULE_ATTR_ACT_TARGET_TYPE] = { "type", BLOBMSG_TYPE_INT32},
	[RULE_ATTR_ACT_IEEEADDR] = { "id", BLOBMSG_TYPE_STRING},
	[RULE_ATTR_ACT_GROUP_ID] = { "gid", BLOBMSG_TYPE_INT32},
	[RULE_ATTR_ACT_SCENE_ID] = { "sid", BLOBMSG_TYPE_INT32},
	[RULE_ATTR_ACT_ENDPOINT_ID] = { "ep", BLOBMSG_TYPE_INT32},
	[RULE_ATTR_ACT_CMD] = { "cmd", BLOBMSG_TYPE_STRING},
	[RULE_ATTR_ACT_VALUE] = { "val", BLOBMSG_TYPE_STRING},
};

const struct blobmsg_policy real_time[__ZHA_REAL_TIME_MAX] = {
	[ZHA_REAL_TIME] = { "time",BLOBMSG_TYPE_STRING},
};

const struct blobmsg_policy cloud_debug[__ZHA_DEBUG_MAX] = {
	[ZHA_DEBUG] = { "debug_level",BLOBMSG_TYPE_INT32},
};

const struct blobmsg_policy cloud_addr_changed[__CLOUD_ADDR_MAX] = {
	[CLOUD_ADDR] = { "cloud_addr_changed",BLOBMSG_TYPE_INT32},
};

const struct blobmsg_policy sha256[__SHA256_MAX] = {
	[SHA256_TIME] = { "time",BLOBMSG_TYPE_INT32},
	[SHA256_ID] = { "time",BLOBMSG_TYPE_STRING},
	[SHA256_MAC] = { "time",BLOBMSG_TYPE_STRING},
};

const struct blobmsg_policy sz06_id[__SZ06_MAX] ={
	[SZ06_ID] = {"id", BLOBMSG_TYPE_STRING},
};

static const struct ubus_method SZ06_methods[] = {
//		UBUS_METHOD_NOARG("get_coordinfo",zha_get_coord_info),
        UBUS_METHOD_NOARG("get_SZ06ID", get_SZ06ID),
        UBUS_METHOD("add_SZ06ID", add_SZ06ID, sz06_id),
        UBUS_METHOD("write_idlist", zha_write_idlist, zha_gateway_attrs),
        UBUS_METHOD_NOARG("get_idlist", zha_get_idlist),
        UBUS_METHOD("delete_idlist", zha_delete_idlist, zha_gateway_attrs),
	
#if 0
		UBUS_METHOD_NOARG("reset_factnew",zha_coordResetFactNew),
		UBUS_METHOD_NOARG("get_whitelist", zha_get_whitelist),
		UBUS_METHOD("write_whitelist", zha_write_whitelist, zha_gateway_attrs),
		UBUS_METHOD("delete_whitelist", zha_delete_whitelist, zha_gateway_attrs),
		UBUS_METHOD("set_coordchannel",zha_coordChangeChannel, zha_gateway_attrs),		
		UBUS_METHOD_NOARG("get_ver", zha_get_ver),
		UBUS_METHOD_NOARG("list", zha_list),
#endif
#if 0
	UBUS_METHOD_NOARG("list", zha_list),
	UBUS_METHOD_NOARG("scan", zha_scan),
	UBUS_METHOD_NOARG("cloud_report", zha_cloud_report),
	UBUS_METHOD_NOARG("reset_factnew",zha_coordResetFactNew),
	UBUS_METHOD("set_coordchannel",zha_coordChangeChannel, zha_gateway_attrs),
	UBUS_METHOD("permit_join",zha_permitjoin, zha_nwkmgr_attrs),
	UBUS_METHOD("get_attr",zha_getAttr, zha_gateway_attrs),
	UBUS_METHOD("leave_req", zha_leave_req, zha_gateway_attrs),
	UBUS_METHOD("set", zha_set, zha_gateway_attrs),
	UBUS_METHOD("get_node_info", zha_get_node_info, zha_gateway_attrs),
	UBUS_METHOD_NOARG("get_coordinfo",zha_get_coord_info),
	UBUS_METHOD("write_whitelist", zha_write_whitelist, zha_gateway_attrs),
	UBUS_METHOD("delete_whitelist", zha_delete_whitelist, zha_gateway_attrs),
	UBUS_METHOD_NOARG("get_whitelist", zha_get_whitelist),
	UBUS_METHOD_NOARG("clean_whitelist", zha_clean_whitelist),
	UBUS_METHOD("enable_whitelist",zha_enable_whitelist, zha_gateway_attrs),
	UBUS_METHOD("group_create", zha_group_create, group_attrs),
	UBUS_METHOD_NOARG("group_list", zha_group_list),
	UBUS_METHOD("group_change", zha_group_change, group_attrs),
	UBUS_METHOD("group_set", zha_group_set, group_attrs),
	UBUS_METHOD("group_del", zha_group_delete, group_attrs),
	
	UBUS_METHOD_NOARG("scene_list", zha_scene_list),
	UBUS_METHOD("scene_create", zha_scene_create, scene_attrs),
	UBUS_METHOD("scene_store", zha_scene_store, scene_attrs),
	UBUS_METHOD("scene_recall", zha_scene_recall, scene_attrs),
	UBUS_METHOD("scene_set", zha_scene_set, scene_attrs),
	UBUS_METHOD("scene_del", zha_scene_delete, scene_attrs),
	UBUS_METHOD("rule_create", zha_rule_create, rule_attrs),
	UBUS_METHOD("rule_change", zha_rule_change, rule_attrs),
	UBUS_METHOD("rule_enable", zha_rule_enable, rule_attrs),
	UBUS_METHOD("rule_get_info", zha_rule_get_info, rule_attrs),
	UBUS_METHOD_NOARG("rule_list", zha_rule_list),
	UBUS_METHOD("rule_del", zha_rule_delete, rule_attrs),
	UBUS_METHOD("disable_whitelist",zha_disable_whitelist, zha_nwkmgr_attrs),
	UBUS_METHOD("time_set",zha_time_set,real_time),
	UBUS_METHOD("coord_heart",zha_coord_heart_Interval, zha_nwkmgr_attrs),
	UBUS_METHOD("min_heart",zha_min_heart_interval, zha_nwkmgr_attrs),
	UBUS_METHOD("max_heart",zha_max_heart_interval, zha_nwkmgr_attrs),
	UBUS_METHOD_NOARG("get_heart", zha_get_heart),
	UBUS_METHOD_NOARG("get_ver", zha_get_ver),
	UBUS_METHOD_NOARG("get_cloud_state", zha_get_cloud_state),
	UBUS_METHOD("debug_level",zha_debug,cloud_debug),
	UBUS_METHOD("cloud_addr_changed",zha_cloud_addr_changed,cloud_addr_changed),
	UBUS_METHOD_NOARG("get_cloud_addr",zha_get_cloud_addr),
	UBUS_METHOD_NOARG("sha256",zha_sha_256)
#endif
};


struct ubus_object_type SZ06_object_type =
UBUS_OBJECT_TYPE("SZ06_ID", SZ06_methods);

struct ubus_object SZ06_object = {
	.name = "SZ06_ID",
	.type = &SZ06_object_type,
	.methods = SZ06_methods,
	.n_methods = ARRAY_SIZE(SZ06_methods),
};



void ubus_init()
{
	int ret;
	const char *ubus_socket = NULL;

	pthread_mutex_init(&mutex_ubus,NULL);
    printf("**********ubus_init******************\n");
	ctx = ubus_connect(ubus_socket);
	if(!ctx)
	{
		fprintf(stderr, "Failed to connect to ubus\n");
	}

	ret = ubus_add_object(ctx, &SZ06_object);
	if(ret)
		fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));

	ubus_add_uloop(ctx);

}

