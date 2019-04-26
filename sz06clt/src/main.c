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
#include "recmqtt.h"

int geteth0MacStr(unsigned char *t_macaddr)
{
    unsigned char *cmd = "uci get network.wan.macaddr";
    FILE *fp = NULL;
    unsigned char buf[20] = {0};
    fp = popen(cmd,"r");
    if(fp == NULL)
    {
        printf("[%s] popen error\n",__FUNCTION__);
        return -1;
    }
    fread(buf, 20, 1, fp);
    buf[19] = '\0';
    buf[strlen(buf)-1] = '\0';
    strcpy(t_macaddr,buf);
    pclose(fp);
    return 0;
}

int macStr2hexstr(unsigned char *str,unsigned char *nstr)
{
    strncpy(nstr,str,2);
    strncpy(nstr+2,str+3,2);
    strncpy(nstr+4,str+6,2);
    strncpy(nstr+6,str+9,2);
    strncpy(nstr+8,str+12,2);
    strncpy(nstr+10,str+15,2);
    nstr[12] = '\0';
    return 0;
}

void geteth0Mac(void)
{
    unsigned char t_macaddr[17] = {0};
    unsigned char hexStr[13] = {0};
    int i;

    geteth0MacStr(t_macaddr);
    macStr2hexstr(t_macaddr,hexStr);
    hexStr2bytes(hexStr,macaddr,6);

    printf("[%s] MAC : ",__FUNCTION__);
    for(i = 0; i < 6; i++)
    {
        printf("%02x ",macaddr[i]);
    }
    for(i = 0; i < 4; i++)
    {
        sprintf(mac_8bit,"%s%02x",mac_8bit,macaddr[i+2]);
    }
    printf("\n");
    printf("\033[31m mac_8bit is [%s]\033\[0m \n", mac_8bit);
}


int rawdata_application_id_cal(int rawdata_application_port)
{
    debug("rawdata_application_port:[%d]",rawdata_application_port);
    char t_macaddr[17] = {0};
    char hexStr[13] = {0};
    geteth0MacStr(t_macaddr);
    macStr2hexstr(t_macaddr,hexStr);

    snprintf(rawdata_application_id,21,"04%02x00%s%02x",rawdata_application_port,hexStr,5);
    debug("rawdata_application_id:[%s]",rawdata_application_id);

    //strcpy(rawdata_application_id,"0402002c6a6f00551005");
}


int main(int argc , char *argv[])
{	
	geteth0Mac();
	int8 i;
	time_cb_info_t watch_dog_time_cb;
	int8 subscribe_topic_count = 0;
	unsigned char *subscribe_topic[MQTT_SUBSCRIBE_TOPIC_MAX_COUNT] = {NULL};
	unsigned char *cmd[100] = {NULL};
	
	printf("#########SZ06 Data Collection#########");
	sprintf(cmd,"uci set appinfo.version.sz06clt='%s'","sz06clt-V1.0");
  	system((const char *)cmd);
  	system("uci commit appinfo");

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

    strcpy(szIotTopic,argv[3]);
    strcpy(szZigBee5_0Topic,argv[1]);
	myPort = argv[2];

	rawdata_application_id_cal(atoi(argv[2]));
    rawdata_application_port = atoi(argv[2]);
	

	mqtt_client_init();
	sz_time_init();
	uloop_init();
	ubus_init();
	sz06_collectDataInit();
	sz_init_db();

/*	for(i = 1;i < argc;i++)
	{
		subscribe_topic_count = subscribe_topic_count + 1;
		subscribe_topic[i - 1] = argv[i];
		debug("topic%d[%s]",i - 1,argv[i]);
	}*/

	debug("myPort %d", myPort);

	subscribe_topic_count = subscribe_topic_count + 1;
    subscribe_topic[0] = argv[1];
    debug("topic%d[%s]",0,argv[1]);

    subscribe_topic_count = subscribe_topic_count + 1;
    subscribe_topic[1] = argv[3];
    debug("topic%d[%s]",1,argv[3]);

	sz_mqtt_bus(subscribe_topic_count,subscribe_topic,NULL);

//	heartbeat_thread_init(); 
	checkOl_thread_init();

	uloop_run();

//	watch_dog_time_cb.fun_time_cb = sz_srne_check_watch_dog;
//	watch_dog_time_cb.interval = 1;
	
//	sz_time_thread(&watch_dog_time_cb);
}
