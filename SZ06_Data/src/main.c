/**************************************
*
*
*
**************************************/

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>


#include "sz_printf.h"
#include "cJSON.h"
#include "sz_time.h"
#include "sz_connect_drive.h"
#include "hal_types.h"
#include "mqtt.h"
#include "ubus.h"
#include "sql_fun.h"

int main(int argc , char *argv[])
{
	int8 i;
	time_cb_info_t watch_dog_time_cb;
	int8 subscribe_topic_count = 0;
	unsigned char *subscribe_topic[MQTT_SUBSCRIBE_TOPIC_MAX_COUNT] = {NULL};

	printf("#########SZ06 Data Acquisition#########");

	if(argc < 2 ){
		err_debug("argc[%d] is wrong", argc);
		return FAILURE;
	}
	
	else{
		debug("argc %d", argc);
		for(i = 1; i < argc; i++){
			debug("argv[%d] = %d", i, argv[i]);
		}
	}

    strcpy(szIotTopic,argv[1]);
    strcpy(szZigBee5_0Topic,argv[2]);
	myPort = argv[3];

	mqtt_client_init();
	sz_time_init();
	uloop_init();
	ubus_init();
	sz06_collectDataInit();
	sz_init_db();

	for(i = 1;i < argc;i++)
	{
		subscribe_topic_count = subscribe_topic_count + 1;
		subscribe_topic[i - 1] = argv[i];
		debug("topic%d[%s]",i - 1,argv[i]);
	}

	sz_mqtt_bus(subscribe_topic_count,subscribe_topic,NULL);

	heartbeat_thread_init(); 

	uloop_run();

//	watch_dog_time_cb.fun_time_cb = sz_srne_check_watch_dog;
//	watch_dog_time_cb.interval = 1;
	
//	sz_time_thread(&watch_dog_time_cb);
}
