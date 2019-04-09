#ifndef _MQTT_H_
#define _MQTT_H_

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <mosquitto.h>
#include "cJSON.h"
#include <pthread.h>
#include "sz_connect_drive.h"

extern void mqtt_client_init(void);


#define CCIOT_CLOUD_APP_NAME			"cciot_cloud"
#define CCIOT_LOCAL_APP_NAME			"cciot_local"
#define CCIOT_CLIENT_APP_NAME			CCIOT_CLOUD_APP_NAME
#define SZ_IOT_APP_NAME					"sz_iot"
#define CCIOT_APP_PORT					"ff"

#define APPLICATION_NAME_ITSELF			"SZ06_Data"
#define THROUGH_DATA_APPLICATION		"szTT_device5_0"


#define CLIENT_HEART_DEVICE_COUNT			10
#define CLIENT_HEART_INTERVAL				60


#define SZ_CLOUD_WATCH_DOG_LOCK			pthread_mutex_lock(&sz_srne_watch_dog_lock)
#define SZ_CLOUD_WATCH_DOG_UNLOCK			pthread_mutex_unlock(&sz_srne_watch_dog_lock)

#define SZ_MAX_TOPIC_LEN   (32)


extern int serial;
extern cloud_info_s sz_mqtt;
extern int sz_srne_watch_dog_counter;
extern pthread_mutex_t sz_srne_watch_dog_lock;

extern char szIotTopic[SZ_MAX_TOPIC_LEN];
extern char szZigBee5_0Topic[SZ_MAX_TOPIC_LEN];
extern int myPort;

int sz_get_mqtt_pwd(char* pwd);

int sz_srne_feed_watch_dog(int time);

int sz_mqtt_get_mac_addr(cloud_info_s *p) ;

int sz_srne_check_watch_dog(void);

void sz_mosqtt_connect_cb(struct mosquitto *mosq, void *obj, int result);

void sz_mosqtt_disconnect_cb(struct mosquitto *mosq, void *obj, int result);

void sz_mosqtt_message_cb(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message);

int sz_mosqtt_heartbeat_cb(cloud_info_s* p);

void sz_mqtt_bus(int sub_topic_count,unsigned char **subscribe_topic,unsigned char *publish_topic);



#ifdef __cplusplus
}
#endif

#endif
