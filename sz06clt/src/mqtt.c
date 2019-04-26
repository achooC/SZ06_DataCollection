#include "mqtt.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <mosquitto.h>
#include "cJSON.h"
#include <pthread.h>
//#include "local_type.h"

#include "sz_time.h"
#include "sz_connect_drive.h"
#include "sz_printf.h"
#include "sz_malloc.h"
#include "recmqtt.h"

struct mosquitto *mosq;
char mqtt_host[10] = "0.0.0.0";
int mqtt_port = 51883;
int keepalive = 60;

int serial = 0;
pthread_mutex_t sz_srne_watch_dog_lock;
cloud_info_s sz_mqtt = {0};
int sz_srne_watch_dog_counter = 20;


char szIotTopic[SZ_MAX_TOPIC_LEN] = {0};
char szZigBee5_0Topic[SZ_MAX_TOPIC_LEN] = {0};
int  myPort = 0;

void mqtt_client_init(void)
{
	while(1){
	   sleep(1);
	   if(MOSQ_ERR_SUCCESS != mosquitto_lib_init()){
	      err_debug("mosquitto_lib_init failure!");
		  continue;
	   }
	   else{
	   	  debug("mosquitto_lib_init success!");
		  break;
	   }
	}

}

int sz_srne_check_watch_dog(void)
{
	SZ_CLOUD_WATCH_DOG_LOCK;
	sz_srne_watch_dog_counter = sz_srne_watch_dog_counter - 1;

	if(sz_srne_watch_dog_counter <= 0)
	{
		war_debug("WATCHDOG[%d]",sz_srne_watch_dog_counter);
		
		char cmd[200] = {0};
		time_t timep; 

		system("logread | grep cciot_cloud2 > /tmp/sz_srne_check_watch_dog.log");
		time (&timep); 
		sprintf(cmd,"echo \"%s\n\" >> /tmp/sz_srne_watch_dog.txt",ctime(&timep));
		system(cmd);
		exit(0);
	}
	else
	{
		war_debug("WATCHDOG[%d]",sz_srne_watch_dog_counter);
	}
	SZ_CLOUD_WATCH_DOG_UNLOCK;

	return SUCCESS;
}


int sz_srne_feed_watch_dog(int time)
{
	SZ_CLOUD_WATCH_DOG_LOCK;
	sz_srne_watch_dog_counter = time + 5;
	SZ_CLOUD_WATCH_DOG_UNLOCK;

	return SUCCESS;
}


void sz_mosqtt_connect_cb(struct mosquitto *mosq, void *obj, int result)
{
	debug("sz_mosqtt_connect_cb enter");
	return ;
}

void sz_mosqtt_disconnect_cb(struct mosquitto *mosq, void *obj, int result)
{
	debug("sz_mosqtt_disconnect_cb enter");
	return ;
}

void sz_mosqtt_message_cb(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	print_time_curr();
	debug("topic[%s] payloadlen[%d]",message->topic,message->payloadlen);

	sz_mq_package_handle(message->topic,message->payloadlen,message->payload);
		
	return ;
}

int sz_mosqtt_heartbeat_cb(cloud_info_s* p)
{
	debug("sz_mosqtt_heartbeat_cb enter");
	return SUCCESS;
}



/****************************************
** func   name : sz_get_mqtt_pwd
** output para : pwd-->the mqtt password
** Note        : sizeof(pwd) >=33
*****************************************/
int sz_get_mqtt_pwd(char* pwd)
{
	int pwd_read_len = 0;
	const char *cmd = "uci get shuncom.root.passwd";
	FILE *fp=NULL;
	
	fp = popen(cmd,"r");
	if(fp == NULL)
	{
		err_debug("popen error");
		exit(1);
	}
	else
	{
		pwd_read_len = fread(pwd, 32, 1, fp);
		if(pwd_read_len <= 0)
		{
			err_debug("pwd_read_len[%d] error",pwd_read_len);
			pclose(fp);
			exit(1);
		}
		pwd[32]='\0';
	}

	pclose(fp);

	return 0;
}

int sz_mqtt_get_mac_addr(cloud_info_s *p)  
{
	gw_info_t *gw_info = &p->gw_info;
	char *cmd="uci get network.wan.macaddr";		
	FILE *fp=NULL;		 
	char mac[18]={0};
	
	fp = popen(cmd,"r");	   
	if(fp == NULL)
	{				 
		printf("[%s] popen error\n",__FUNCTION__);				  
		return FAILURE; 	   
	}		

	if(fread(mac,17, 1, fp) != 1) 
	{
		debug("read flash data[%s] Error!\r\n",mac);
		fclose(fp);
		return FAILURE;
	}

	if(0 == memcmp(mac,"78:45:61:53:6a:4b",strlen("78:45:61:53:6a:4b")))
	{
		debug("mac[%s]",mac);
		fclose(fp);
		return FAILURE;
	}
	
	memcpy(gw_info->mac,mac,17);
	sprintf(gw_info->ieee,"00ff%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", \
	mac[0],mac[1],mac[0],mac[1],\
	mac[0],mac[1],\
	mac[3],mac[4],\
	mac[6],mac[7],\
	mac[9],mac[10],\
	mac[12],mac[13],\
	mac[15],mac[16]);
	
	gw_info->mac_flag = 1;
	gw_info->ieee_flag = 1;

	debug("mac[%s] ieee[%s] ",gw_info->mac,gw_info->ieee);
		 
	pclose(fp); 	  
	return SUCCESS;
}


void sz_mqtt_bus(int sub_topic_count,unsigned char **subscribe_topic,unsigned char *publish_topic)
{
	int i = 0;

	if(sub_topic_count <= 0)
	{
		err_debug("sub_topic_count[%d] error",sub_topic_count);
		exit(1);
	}

	if(subscribe_topic == NULL)
	{
		err_debug("subscribe_topic is NULL");
		exit(1);
	}
	
	if(0 != pthread_mutex_init(&sz_srne_watch_dog_lock,NULL))
	{
		err_debug("--------------------> sz_srne_watch_dog_lock init error");
		exit(1);
	}
	
	memset((char *)&sz_mqtt,0,sizeof(cloud_info_s));

	sz_mqtt.connect_type = 1;// 0 -- tcp;1 -- mqtt;
	
	strcpy(sz_mqtt.server_info.server_addr,"0.0.0.0");
	sz_mqtt.server_info.port = 51883;

	//sz_mqtt.key[32];// encryption key
	sz_mqtt.version = 0;//0--json no header;1--json header;2--header;4--compress
	sz_mqtt.verify = 0;//is verify
	sz_mqtt.encryption = 0;//1--need verify;0--didn`t need
	sz_mqtt.heart_count = 0;
	sz_mqtt.watch_dog_time = 20;
	sz_mqtt.step = CLIENT_STEP_SOCKET_INIT;
	sz_mqtt.status = CONNECT_STEP_GETED_SERVERINFO;
	sz_mqtt.reqheart = DEFAULT_CONNECT_WITH_DEVICE;
	sz_mqtt.devcount = CLIENT_HEART_DEVICE_COUNT;
	sz_mqtt.getserverct = 0;
	sz_mqtt.gwregisted = 0;

	sz_mqtt.cloud_client.mqtt_client.mosq = NULL;
	sz_mqtt.cloud_client.mqtt_client.heart_interval = CLIENT_HEART_INTERVAL;
	sz_mqtt.cloud_client.mqtt_client.login_need = 1;
	sz_mqtt.cloud_client.mqtt_client.reconnect_interval = 10;	
	strcpy(sz_mqtt.cloud_client.mqtt_client.name,"mqttAdmin");
	sz_get_mqtt_pwd(sz_mqtt.cloud_client.mqtt_client.password);

	sub_topic_count = (sub_topic_count >= MQTT_SUBSCRIBE_TOPIC_MAX_COUNT?MQTT_SUBSCRIBE_TOPIC_MAX_COUNT:sub_topic_count);
	sz_mqtt.cloud_client.mqtt_client.sub_topic_count = sub_topic_count;	
	for(i = 0;i < sub_topic_count;i++)
		memcpy(sz_mqtt.cloud_client.mqtt_client.sub_topic[i],subscribe_topic[i], \
			strlen(subscribe_topic[i]) >= MQTT_SUBSCRIBE_TOPIC_MAX_LEN?(MQTT_SUBSCRIBE_TOPIC_MAX_LEN - 1):strlen(subscribe_topic[i]));

	if(publish_topic == NULL)
		strcpy(sz_mqtt.cloud_client.mqtt_client.pub_topic,sz_mqtt.cloud_client.mqtt_client.sub_topic[0]);
	else
		memcpy(sz_mqtt.cloud_client.mqtt_client.pub_topic,publish_topic, \
			strlen(publish_topic) >= MQTT_PUBLISH_TOPCI_MAX_LEN?(MQTT_PUBLISH_TOPCI_MAX_LEN - 1):strlen(publish_topic));

	sz_mqtt.cloud_callback.mqtt_callback.connect_callback = sz_mosqtt_connect_cb;
	sz_mqtt.cloud_callback.mqtt_callback.disconnect_callback = sz_mosqtt_disconnect_cb;
	sz_mqtt.cloud_callback.mqtt_callback.mosqtt_message_callback = sz_mosqtt_message_cb;
	sz_mqtt.cloud_callback.mqtt_callback.mosqtt_heartbeat_callback = sz_mosqtt_heartbeat_cb;
	sz_mqtt.cloud_callback.mqtt_callback.feed_watch_dog = sz_srne_feed_watch_dog;	
	
	sz_mqtt_get_mac_addr(&sz_mqtt);
	
	sz_mqtt.recv_buf = (unsigned char *)sz_malloc(MAX_RECV_SIZE);
	if(NULL == sz_mqtt.recv_buf)
	{
		err_debug("sz_malloc recv buff error");
		exit(1);
	}
	sz_mqtt.recv_len = 0;	

	cloud_init(&sz_mqtt);

	return ;
}

