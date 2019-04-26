#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>
#include <sys/time.h>
#include <math.h>
#include <ctype.h>

#include "cJSON.h"
#include "sz_connect_drive.h"
#include "recmqtt.h"
#include "mqtt.h"
#include "sz_printf.h"
#include "sql_fun.h"
#include "sz_malloc.h"
#include "sz_time.h"
#include "hal_types.h"

int sz_rebuild_st(unsigned int ep,unsigned short did,unsigned short pid,char *rawdata);
int sz_mq_package_handle(unsigned char* topic,int len,unsigned char* payload);
int parse_raw_data(cJSON *payload);
int register_device(unsigned char *id);
void sz06_collectDataInit(void);
int sz06_insetDevice(collect_data data);
int sz06_delete_device(unsigned char *id);
int sz06_update_olflag(unsigned char *id,int olflag);
int sz06_update_elelev(unsigned char *id,int elelev, int ep);
int sz06_update_digidal(unsigned char *id,int digidal, int ep);
int sz06_update_eleout(unsigned char *id,int eleout, int ep);
int sz06_update_anal420(unsigned char *id,double anal420, int ep);
int sz06_update_volt3_3(unsigned char *id,double volt3_3, int ep);
int sz06_update_volt5_0(unsigned char *id,double volt5_0, int ep);
int sz06_update_dstemp(unsigned char *id,double dstemp, int ep);
int sz06_update_pttemp(unsigned char *id,double pttemp, int ep);
int sz06_update_colltemp(unsigned char *id,double colltemp, int ep);
int sz06_update_collhumi(unsigned char *id,double collhumi, int ep);

void heartbeat_thread_init(void);
void *thread_heartbeat1(void *p);
void sz06_heartbeat_handler(void);
void *thread_checkOl(void *p);

char rawdata_application_id[21] = {0};
int rawdata_application_port = 0;
unsigned char mac_8bit[10] = {0};
unsigned char macaddr[6] = {0};


collect_data sz06_collectDataHead;

pthread_mutex_t device_manage_lock;

int olflag = 3;

int add = 1;
int sub = 0;
int dataUpdate = 0;

int hexStr2bytes(const char *hexStr,unsigned char *buf,int bufLen)
{
    int i;
    int len;

    if(NULL==hexStr)
    {
        len=0;
    }
    else
    {
        len=(int)strlen(hexStr)/2;

        if(bufLen<len)
        {
            len=bufLen;
        }
    }
    memset(buf,0,bufLen);

    for(i=0;i<len;i++)
    {
        char ch1,ch2;
        int val;

        ch1=hexStr[i*2];
        ch2=hexStr[i*2+1];
        if(ch1>='0'&&ch1<='9')
        {
            val=(ch1-'0')*16;
        }
        else if(ch1>='a'&&ch1<='f')
        {
            val=((ch1-'a')+10)*16;
        }
        else if(ch1>='A'&&ch1<='F')
        {
            val=((ch1-'A')+10)*16;
        }
        else
        {
            return -1;
        }

        if(ch2>='0'&&ch2<='9')
        {
            val+=ch2-'0';
        }
        else if(ch2>='a'&&ch2<='f')
        {
            val+=(ch2-'a')+10;
        }
        else if(ch2>='A'&&ch2<='F')
        {
            val+=(ch2-'A')+10;
        }
        else
        {
            return -1;
        }

        buf[i]=val&0xff;
    }

    return 0;
}


int sz_mq_package_handle(unsigned char* topic,int len,unsigned char* payload)
{
	if((0 == len) || !topic || !payload){
		err_debug("len[%d] topic or payload is NULL",len);
		return FAILURE;
	}
	
	int i = 0;
	unsigned char myId[21];
	char myRawData[17];
	cJSON *root = cJSON_Parse(payload);

	if(root == NULL){
		err_debug("root is NULL");
		return FAILURE;
	}

	cJSON * p_application = cJSON_GetObjectItem(root,"application");
	cJSON * p_port = cJSON_GetObjectItem(root,"port");
	cJSON * p_destination = cJSON_GetObjectItem(root,"destination");
	cJSON * p_payload = cJSON_GetObjectItem(root,"payload");

	
	if(!p_application || !p_port || !p_destination || !p_payload){
		err_debug("application/port/destination/payload is NULL");
		cJSON_Delete(root);
		root = NULL;
		return FAILURE;
	}

	if((strlen(p_application->valuestring) == strlen(APPLICATION_NAME_ITSELF)) && \
		(0 == memcmp(APPLICATION_NAME_ITSELF,p_application->valuestring,strlen(APPLICATION_NAME_ITSELF))))
	{
		debug("application is [%s], message recv from myself",p_application->valuestring);
		cJSON_Delete(root);
		root = NULL;
		return FAILURE;
	}

	if((strlen(p_application->valuestring) == strlen(THROUGH_DATA_APPLICATION)) && \
		(0 == memcmp(THROUGH_DATA_APPLICATION,p_application->valuestring,strlen(THROUGH_DATA_APPLICATION)))) 
	{
		debug("application is [%s]",p_application->valuestring);
		
		mr_debug("mq recv topic[%s] len[%d]",topic,len);
		if(len < 200000)
        {
			mr_debug("mq recv payload[%s]",payload);
		}
		debug("application[%s] port[%s] destination[%s]",p_application->valuestring,p_port->valuestring,p_destination->valuestring);

		cJSON *code = cJSON_GetObjectItem(p_payload, "code");

/*		if(code->valueint == 102)
		{
			cJSON *rawdata = cJSON_GetObjectItem(p_payload, "rawData");
			sz06_update_olflag(rawdata->valuestring, add);
		}
		else*/
        	parse_raw_data(p_payload);
	}

	if(((strlen(p_application->valuestring) == strlen(CCIOT_CLOUD_APP_NAME)) && \
		(0 == memcmp(CCIOT_CLOUD_APP_NAME,p_application->valuestring,strlen(CCIOT_CLOUD_APP_NAME)))) || \
		((strlen(p_application->valuestring) == strlen(CCIOT_LOCAL_APP_NAME)) && \
		(0 == memcmp(CCIOT_LOCAL_APP_NAME,p_application->valuestring,strlen(CCIOT_LOCAL_APP_NAME)))))
	{
		debug("application is [%s]",p_application->valuestring);

		mr_debug("mq recv topic[%s] len[%d]",topic,len);
		if(len < 200000)
        {
			mr_debug("mq recv payload[%s]",payload);
		}
		debug("application[%s] port[%s] destination[%s]",p_application->valuestring,p_port->valuestring,p_destination->valuestring);

		cJSON * code = cJSON_GetObjectItem(p_payload,"code");
		
		if(!code)
	    {
	        err_debug("code is NULL");
	        return FAILURE;
	    }
		if(code->valueint == 1005)
        	sz_105_device_register_rsp(p_payload);
		else if(code->valueint == 1003)
		{
			cJSON *id = cJSON_GetObjectItem(p_payload, "id");
			cJSON *serial = cJSON_GetObjectItem(p_payload, "serial");
			if(!id || !serial ){
				err_debug("id/serial is NULL");
				cJSON_Delete(root);
				root = NULL;
				return FAILURE;
			}
			sz_103_delete_device_rsp(id->valuestring, serial->valueint);
			sz_104_delete_device_report(id->valuestring);
		}

		else if(code->valueint == 1010)
		{
			cJSON *devclass = cJSON_GetObjectItem(p_payload, "devclass");
			cJSON *devinfos = cJSON_GetObjectItem(p_payload, "devinfos");
			cJSON *devSerial = cJSON_GetObjectItem(p_payload, "serial");

			if(!devclass || !devinfos || !devSerial){
				err_debug("devclass/devinfos/devSerial is NULL");
				cJSON_Delete(root);
				root = NULL;
				return FAILURE;
			}
			
			int arraySize =  cJSON_GetArraySize(devinfos);
			if(!arraySize)
    		{
       		 	err_debug("arraySize is 0");
				cJSON_Delete(root);
				root = NULL;
       		 	return FAILURE;
    		}

			cJSON *ids = cJSON_CreateArray();
		    if(!ids)
		    {
		        err_debug("ids is NULL");
		        cJSON_Delete(root);
		        root = NULL;
		        return ;
		    }
					
			for(i = 0; i < arraySize; i++)
			{
				cJSON *devInfos = cJSON_GetArrayItem(devinfos, i);
				cJSON *devaddr = cJSON_GetObjectItem(devInfos, "devaddr");
				cJSON *devtype = cJSON_GetObjectItem(devInfos, "devtype");

				cJSON *item = cJSON_CreateObject();
			    char *id[21];
				sz_device_info tmp_device;
				char sql[500] = {0};
				char *zErrMsg = NULL;
				int rc, epCount, returnValue = 0;

				int string_len = strlen(devaddr->valuestring);
				unsigned char devaddr_hex[string_len/2];
    			hexStr2bytes(devaddr->valuestring,devaddr_hex,string_len/2);
				
				sprintf(id, "03%02x02000000%02x%02x%02x%02x", rawdata_application_port, devaddr_hex[0], devaddr_hex[1], devaddr_hex[2], devaddr_hex[3]);
				sprintf(tmp_device.addr, "%02x%02x%02x%02x",  devaddr_hex[0], devaddr_hex[1], devaddr_hex[2], devaddr_hex[3]);
//				strncpy(tmp_device.id, id, 20);
//				debug("%s   %s", id, tmp_device.id);
//				strncpy(tmp_device.addr, id+6, 9);
				register_device(id);
				for(epCount = 1; epCount < 6; epCount++)
						{
//							debug("add");
							collect_data device;
					    	strncpy(device.id, (unsigned char *)id, 21);
							strncpy(device.addr, devaddr->valuestring,9);
//							debug("%s   %s", device.id, device.addr);
							device.ep = epCount;
							device.olflag = 3;
							device.elelev = 2;
							device.digidal = 2;
							device.eleout = 2;
							device.anal420 = 2;
							device.volt3_3 = 5;
							device.volt5_0 = 6;
							device.dstemp = 0.000001;
							device.pttemp = 0.000001;
							device.colltemp = 0.000001;
							device.collhumi = 0.000001;
							device.next = NULL;
							returnValue = sz06_insetDevice(device);
						}
						if(returnValue == 2)
						{
							debug("device was added!");
							return UBUS_STATUS_OK;
						}
						tmp_device.did = 1;
						tmp_device.ep = 1;
//						strcpy(device->dsp, dsp);
						sprintf(sql,"INSERT INTO device_tb(date,ieee,addr,rawdata,ep,did,status) \
							VALUES(date('now'),'%s','%s','%s',%d,%d,%d);",id,tmp_device.addr,"1112451b6599000103010103020403030403",1,1,0);
						printf("sql:[%s]",sql);
						rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
						
						if (rc != SQLITE_OK)
						{
								err_debug("SQL error: %s\n", zErrMsg);
								sqlite3_free(zErrMsg);
								return 1;
						}
						sz_recover_device_info();
			    cJSON_AddStringToObject(item,"id", id);
			    cJSON_AddNumberToObject(item,"devtype", devtype->valueint); 
 			    cJSON_AddItemToArray(ids,item);

			}
			sz_110_add_device_rsp(ids, devclass->valueint, devSerial->valueint);
			
			
		}
		else if(code->valueint == 1002)
		{	
			cJSON *id = cJSON_GetObjectItem(p_payload, "id");
			cJSON *ep = cJSON_GetObjectItem(p_payload, "ep");
			cJSON *control = cJSON_GetObjectItem(p_payload, "control");
			cJSON *sz06ctrl = cJSON_GetObjectItem(control, "sz06ctrl");
			cJSON *read = cJSON_GetObjectItem(control, "read");
			if(!id || !ep || !control || (!sz06ctrl && !read)){
				err_debug("id/ep/control/(sz06ctrl read) is NULL");
				cJSON_Delete(root);
				root = NULL;
				return FAILURE;
			}
			if(sz06ctrl)
			{
				strcpy(myId, id->valuestring);
				strcpy(myRawData, sz06ctrl->valuestring);
				sz_102_device_control_rsp(id->valuestring, ep->valueint,sz06ctrl->valuestring);
				sz_control_device(myId, ep->valueint, myRawData);
			}
			else if(read)
			{
				strncpy(myId, id->valuestring, 21);
				strcpy(myRawData, read->valuestring);
				sz_102_device_read_rsp(myId, ep->valueint,myRawData);
				sz_read_device(myId, ep->valueint, myRawData);				
			}
			
		}
		else if(code->valueint == 1001)
		{
			cJSON *result =  cJSON_GetObjectItem(p_payload, "result");

			if(!result)
			{
				debug("result id NULL");
				sz06_heartbeat_handler();
			}
		}
	}
/*	unsigned char *sendData = NULL;

	sendData = cJSON_PrintUnformatted(root);
	
    if(!sendData){
        cJSON_Delete(root);
        root = NULL;
        err_debug("cjson print error");
        return FAILURE;
    }

	unsigned int sendLen = strlen(sendData);
	int ret = sz_mq_send_data_by_topic(szIotTopic, sendLen, sendData);

    cJSON_Delete(root);
    root = NULL;
    sz_free((void *)sendData);
    sendData = NULL;*/

    cJSON_Delete(root);
    root = NULL;


    return SUCCESS;
	
}

int sz_read_device(unsigned char *id, unsigned int ep, char *rawdata)
{
	unsigned char *send_data = NULL;
	unsigned char addr[9];
	unsigned char myRawData[50];
	unsigned char ieee[9];
	int ret;
	strncpy(ieee, id+12, 9);
	debug("ieee  %s", ieee);
	if(memcmp(ieee, "ffffffff", 8) == 0)
	{
		debug("Broadcast query data");
//		collect_data *tmp_device = sz06_collectDataHead.next;
//		while(tmp_device != NULL)
//		{
//			if(tmp_device->ep == ep)
//			{
				cJSON *root = cJSON_CreateObject();
			    if(!root)
			    {
			        err_debug("create root error");
			        return FAILURE;
			    }

			//	debug("control [%s]", myControl->child->valuestring);
				cJSON *payload = cJSON_CreateObject();
				if(!payload)
				{
					err_debug("create payload error");
					cJSON_Delete(root);
					root = NULL;
					return FAILURE;
				} 
			    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
			    cJSON_AddStringToObject(root,"port",myPort);
			    cJSON_AddStringToObject(root,"destination",THROUGH_DATA_APPLICATION);


				cJSON_AddItemToObject(root,"payload",payload);
				cJSON_AddNumberToObject(payload, "code", 1002);
				cJSON_AddStringToObject(payload, "id", rawdata_application_id);
				cJSON_AddNumberToObject(payload, "ep", ep);
				cJSON_AddNumberToObject(payload,"serial",serial++);
			    cJSON_AddNumberToObject(payload,"did",1);
			    cJSON_AddNumberToObject(payload,"pid",65286);
				cJSON *control = cJSON_CreateObject();
				if(!control)
				{
					err_debug("create control error");
					cJSON_Delete(payload);
					payload =NULL;
					cJSON_Delete(root);
					root = NULL;
					return FAILURE;
				}

//				strncpy(addr,tmp_device->addr,9);

				unsigned int rawdataLen = strlen(rawdata);
				rawdataLen = 6+rawdataLen/2;
				debug("rawdatalen = %d", rawdataLen);
				sprintf(myRawData, "%X07FFFFFFFF%s", 0x10, rawdata);
				cJSON_AddItemToObject(payload,"control",control);
				cJSON_AddStringToObject(control, "rawData", myRawData);
				
			    send_data = cJSON_PrintUnformatted(root);
			    if(!send_data)
			    {
			        cJSON_Delete(root);
			        root = NULL;
			        err_debug("cjson print error");
			        return FAILURE;
			    }

				unsigned int send_len = strlen(send_data);
			    ret = sz_mq_send_data_by_topic(szZigBee5_0Topic, send_len, send_data);

			    cJSON_Delete(root);
			    root = NULL;
			    sz_free((void *)send_data);
			    send_data = NULL;
//			}
//			tmp_device = tmp_device->next;
//		}
	}
	else
	{
		debug("Unicast query data");
		cJSON *root = cJSON_CreateObject();
	    if(!root)
	    {
	        err_debug("create root error");
	        return FAILURE;
	    }

	//	debug("control [%s]", myControl->child->valuestring);
		cJSON *payload = cJSON_CreateObject();
		if(!payload)
		{
			err_debug("create payload error");
			cJSON_Delete(root);
			root = NULL;
			return FAILURE;
		} 
	    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
	    cJSON_AddStringToObject(root,"port",myPort);
	    cJSON_AddStringToObject(root,"destination",THROUGH_DATA_APPLICATION);


		cJSON_AddItemToObject(root,"payload",payload);
		cJSON_AddNumberToObject(payload, "code", 1002);
		cJSON_AddStringToObject(payload, "id", rawdata_application_id);
		cJSON_AddNumberToObject(payload, "ep", ep);
		cJSON_AddNumberToObject(payload,"serial",serial++);
	    cJSON_AddNumberToObject(payload,"did",1);
	    cJSON_AddNumberToObject(payload,"pid",65286);
		cJSON *control = cJSON_CreateObject();
		if(!control)
		{
			err_debug("create control error");
			cJSON_Delete(payload);
			payload =NULL;
			cJSON_Delete(root);
			root = NULL;
			return FAILURE;
		}
/*		collect_data *tmp_device = sz06_collectDataHead.next;
		while(tmp_device != NULL)
		{
			if(memcmp(id,tmp_device->id,20) == 0 && (ep == tmp_device->ep))
			{
				strncpy(addr,tmp_device->addr,9);
			}
			tmp_device = tmp_device->next;
		}*/
		unsigned int rawdataLen = strlen(rawdata);
		rawdataLen = 6+rawdataLen/2;
		debug("rawdatalen = %d", rawdataLen);
		sprintf(myRawData, "%X07%s%s", 0x10, ieee, rawdata);
		cJSON_AddItemToObject(payload,"control",control);
		cJSON_AddStringToObject(control, "rawData", myRawData);
		
	    send_data = cJSON_PrintUnformatted(root);
	    if(!send_data)
	    {
	        cJSON_Delete(root);
	        root = NULL;
	        err_debug("cjson print error");
	        return FAILURE;
	    }

		unsigned int send_len = strlen(send_data);
	    ret = sz_mq_send_data_by_topic(szZigBee5_0Topic, send_len, send_data);

	    cJSON_Delete(root);
	    root = NULL;
	    sz_free((void *)send_data);
	    send_data = NULL;
	}

    return ret;	
	
	return SUCCESS;
}


int sz_control_device(unsigned char *id, unsigned int ep, char *rawdata)
{
//	unsigned char *send_data = NULL;
	unsigned char addr[9];
	unsigned char myRawData[50];
	unsigned char ieee[9];
	int ret;

	strncpy(ieee, id+12, 9);
	debug("ieee[%s]", ieee);
/*	cJSON *root = cJSON_CreateObject();
    if(!root)
    {
        err_debug("create root error");
        return FAILURE;
    }
//	debug("control [%s]", myControl->child->valuestring);
	cJSON *payload = cJSON_CreateObject();
	if(!payload)
	{
		err_debug("create payload error");
		cJSON_Delete(root);
		root = NULL;
		return FAILURE;
	} 
    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
    cJSON_AddStringToObject(root,"port",myPort);
    cJSON_AddStringToObject(root,"destination",THROUGH_DATA_APPLICATION);

	cJSON_AddItemToObject(root,"payload",payload);
	cJSON_AddNumberToObject(payload, "code", 1002);*/
//	if(memcmp(ieee, "ffffffff", 8) == 0)
//	{
//		collect_data *tmp_device = sz06_collectDataHead.next;
//		while(tmp_device != NULL)
//		{
//			if(tmp_device->ep == ep)
//			{
				unsigned char *send_data = NULL;
				cJSON *root = cJSON_CreateObject();
			    if(!root)
			    {
			        err_debug("create root error");
			        return FAILURE;
			    }
				
			//	debug("111");
			//	debug("control [%s]", myControl->child->valuestring);
				cJSON *payload = cJSON_CreateObject();
				
				if(!payload)
				{
					err_debug("create payload error");
					cJSON_Delete(root);
					root = NULL;
					return FAILURE;
				} 
				
			    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
			    cJSON_AddStringToObject(root,"port",myPort);
			    cJSON_AddStringToObject(root,"destination",THROUGH_DATA_APPLICATION);

				cJSON_AddItemToObject(root,"payload",payload);
				cJSON_AddNumberToObject(payload, "code", 1002);
				cJSON_AddStringToObject(payload, "id", rawdata_application_id);
				cJSON_AddNumberToObject(payload, "ep", ep);
				cJSON_AddNumberToObject(payload,"serial",serial++);
				cJSON_AddNumberToObject(payload,"did",1);
				cJSON_AddNumberToObject(payload,"pid",65286);
				cJSON *control = cJSON_CreateObject();
				if(!control)
				{
					err_debug("create control error");
					cJSON_Delete(payload);
					payload =NULL;
					cJSON_Delete(root);
					root = NULL;
					return FAILURE;
				}

//				strncpy(addr,tmp_device->addr,9);
//				debug("%s", addr);
				
				unsigned int rawdataLen = strlen(rawdata);
				rawdataLen = 6+rawdataLen/2;
				debug("rawdatalen = %d", rawdataLen);
				sprintf(myRawData, "%X%02X%s%s", 0x15, rawdataLen, ieee, rawdata);
				cJSON_AddItemToObject(payload,"control",control);
				cJSON_AddStringToObject(control, "rawData", myRawData);
					
				send_data = cJSON_PrintUnformatted(root);
				if(!send_data)
				{
					cJSON_Delete(root);
					root = NULL;
					err_debug("cjson print error");
					return FAILURE;
				}
				
				unsigned int send_len = strlen(send_data);
				ret = sz_mq_send_data_by_topic(szZigBee5_0Topic, send_len, send_data);
				
				cJSON_Delete(root);
				root = NULL;
				sz_free((void *)send_data);
				send_data = NULL;

//			}
//			tmp_device = tmp_device->next;
//		}
//	}
/*	else
	{
		unsigned char *send_data = NULL;
		cJSON *root = cJSON_CreateObject();
	    if(!root)
	    {
	        err_debug("create root error");
	        return FAILURE;
	    }
	//	debug("control [%s]", myControl->child->valuestring);
		cJSON *payload = cJSON_CreateObject();
		if(!payload)
		{
			err_debug("create payload error");
			cJSON_Delete(root);
			root = NULL;
			return FAILURE;
		} 
	    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
	    cJSON_AddStringToObject(root,"port",myPort);
	    cJSON_AddStringToObject(root,"destination",THROUGH_DATA_APPLICATION);

		cJSON_AddItemToObject(root,"payload",payload);
		cJSON_AddNumberToObject(payload, "code", 1002);		
		cJSON_AddStringToObject(payload, "id", id);
		cJSON_AddNumberToObject(payload, "ep", ep);
		cJSON_AddNumberToObject(payload,"serial",serial++);
		cJSON_AddNumberToObject(payload,"did",1);
		cJSON_AddNumberToObject(payload,"pid",65286);
		cJSON *control = cJSON_CreateObject();
		if(!control)
		{
			err_debug("create control error");
			cJSON_Delete(payload);
			payload =NULL;
			cJSON_Delete(root);
			root = NULL;
			return FAILURE;
		}
		collect_data *tmp_device = sz06_collectDataHead.next;
		while(tmp_device != NULL)
		{	
			if(memcmp(id,tmp_device->id,20) == 0 && (ep == tmp_device->ep))
			{
				strncpy(addr,tmp_device->addr,9);
				debug("%s", addr);
			}
			tmp_device = tmp_device->next;
		}
		unsigned int rawdataLen = strlen(rawdata);
		rawdataLen = 6+rawdataLen/2;
		debug("rawdatalen = %d", rawdataLen);
		sprintf(myRawData, "%X%02X%s%s", 0x15, rawdataLen, ieee, rawdata);
		cJSON_AddItemToObject(payload,"control",control);
		cJSON_AddStringToObject(control, "rawData", myRawData);
			
		send_data = cJSON_PrintUnformatted(root);
		if(!send_data)
		{
			cJSON_Delete(root);
			root = NULL;
			err_debug("cjson print error");
			return FAILURE;
		}
		
		unsigned int send_len = strlen(send_data);
	    ret = sz_mq_send_data_by_topic(szZigBee5_0Topic, send_len, send_data);
		
		cJSON_Delete(root);
		root = NULL;
		sz_free((void *)send_data);
		send_data = NULL;

	}*/
/*	cJSON_AddStringToObject(payload, "id", id);
	cJSON_AddNumberToObject(payload, "ep", ep);
	cJSON_AddNumberToObject(payload,"serial",serial++);
    cJSON_AddNumberToObject(payload,"did",1);
    cJSON_AddNumberToObject(payload,"pid",65286);
	cJSON *control = cJSON_CreateObject();
	if(!control)
	{
		err_debug("create control error");
		cJSON_Delete(payload);
		payload =NULL;
		cJSON_Delete(root);
		root = NULL;
		return FAILURE;
	}
	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{	
		if(memcmp(id,tmp_device->id,20) == 0 && (ep == tmp_device->ep))
		{
			strncpy(addr,tmp_device->addr,9);
			debug("%s", addr);
		}
		tmp_device = tmp_device->next;
	}
	unsigned int rawdataLen = strlen(rawdata);
	rawdataLen = 6+rawdataLen/2;
	debug("rawdatalen = %d", rawdataLen);
	sprintf(myRawData, "%X%02X%s%s", 0x15, rawdataLen, addr, rawdata);
	cJSON_AddItemToObject(payload,"control",control);
	cJSON_AddStringToObject(control, "rawData", myRawData);
	
    send_data = cJSON_PrintUnformatted(root);
    if(!send_data)
    {
        cJSON_Delete(root);
        root = NULL;
        err_debug("cjson print error");
        return FAILURE;
    }

	unsigned int send_len = strlen(send_data);
    int ret = sz_mq_send_data_by_topic(szZigBee5_0Topic, send_len, send_data);

    cJSON_Delete(root);
    root = NULL;
    sz_free((void *)send_data);
    send_data = NULL;*/
    return ret;	
	
	return SUCCESS;
}

int sz_102_device_read_rsp(unsigned char *id, unsigned int ep, char *rawdata)
{
	unsigned char *send_data = NULL;

    cJSON *root = cJSON_CreateObject();
    if(!root)
    {
        err_debug("create root error");
        return FAILURE;
    }

//	debug("control [%s]", myControl->child->valuestring);
	cJSON *payload = cJSON_CreateObject();
	if(!payload)
	{
		err_debug("create payload error");
		cJSON_Delete(root);
		root = NULL;
		return FAILURE;
	} 
    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
    cJSON_AddStringToObject(root,"port",myPort);
    cJSON_AddStringToObject(root,"destination",SZ_IOT_APP_NAME);


	cJSON_AddItemToObject(root,"payload",payload);
	cJSON_AddNumberToObject(payload, "code", 102);
	cJSON_AddStringToObject(payload, "id", id);
	cJSON_AddNumberToObject(payload, "ep", ep);
	cJSON_AddNumberToObject(payload,"serial",serial++);
    cJSON_AddNumberToObject(payload,"did",1);
    cJSON_AddNumberToObject(payload,"pid",65286);
	cJSON *control = cJSON_CreateObject();
	if(!control)
	{
		err_debug("create control error");
		cJSON_Delete(payload);
		payload =NULL;
		cJSON_Delete(root);
		root = NULL;
		return FAILURE;
	} 
	cJSON_AddItemToObject(payload,"control",control);
	cJSON_AddStringToObject(control, "read", rawdata);
	cJSON_AddNumberToObject(payload, "result", 0);
	cJSON_AddNumberToObject(payload, "cmdsource", 1);
	
    send_data = cJSON_PrintUnformatted(root);
    if(!send_data)
    {
        cJSON_Delete(root);
        root = NULL;
        err_debug("cjson print error");
        return FAILURE;
    }

	unsigned int send_len = strlen(send_data);
	debug("102 RSP--++");
    int ret = sz_mq_send_data_by_topic(szIotTopic, send_len, send_data);

    cJSON_Delete(root);
    root = NULL;
    sz_free((void *)send_data);
    send_data = NULL;
    return ret;	
}


int sz_102_device_control_rsp(unsigned char *id, unsigned int ep, char *rawdata)
{
	unsigned char *send_data = NULL;

    cJSON *root = cJSON_CreateObject();
    if(!root)
    {
        err_debug("create root error");
        return FAILURE;
    }

//	debug("control [%s]", myControl->child->valuestring);
	cJSON *payload = cJSON_CreateObject();
	if(!payload)
	{
		err_debug("create payload error");
		cJSON_Delete(root);
		root = NULL;
		return FAILURE;
	} 
    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
    cJSON_AddStringToObject(root,"port",myPort);
    cJSON_AddStringToObject(root,"destination",SZ_IOT_APP_NAME);


	cJSON_AddItemToObject(root,"payload",payload);
	cJSON_AddNumberToObject(payload, "code", 102);
	cJSON_AddStringToObject(payload, "id", id);
	cJSON_AddNumberToObject(payload, "ep", ep);
	cJSON_AddNumberToObject(payload,"serial",serial++);
    cJSON_AddNumberToObject(payload,"did",1);
    cJSON_AddNumberToObject(payload,"pid",65286);
	cJSON *control = cJSON_CreateObject();
	if(!control)
	{
		err_debug("create control error");
		cJSON_Delete(payload);
		payload =NULL;
		cJSON_Delete(root);
		root = NULL;
		return FAILURE;
	} 
	cJSON_AddItemToObject(payload,"control",control);
	cJSON_AddStringToObject(control, "sz06ctrl", rawdata);
	cJSON_AddNumberToObject(payload, "result", 0);
	cJSON_AddNumberToObject(payload, "cmdsource", 1);
	
    send_data = cJSON_PrintUnformatted(root);
    if(!send_data)
    {
        cJSON_Delete(root);
        root = NULL;
        err_debug("cjson print error");
        return FAILURE;
    }

	unsigned int send_len = strlen(send_data);
	debug("102 RSP--++");
    int ret = sz_mq_send_data_by_topic(szIotTopic, send_len, send_data);

    cJSON_Delete(root);
    root = NULL;
    sz_free((void *)send_data);
    send_data = NULL;
    return ret;	
}

int sz_103_delete_device_rsp(unsigned char *id, int32 serial)
{
	unsigned char *send_data = NULL;

	int rc = 0, i;
	char sql[500] = {0};
	int inset_result = 0;
  	char *zErrMsg = NULL;

	sprintf(sql,"DELETE FROM device_tb WHERE ieee = '%s';",id);
	printf("sql:[%s]",sql);
	sz06_delete_device(id);
	rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
						
	if (rc != SQLITE_OK)
	{
		err_debug("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		return 1;
	} 

	cJSON *root = cJSON_CreateObject();
    if(!root)
    {
        err_debug("create root error");
        return FAILURE;
    }

	
    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
    cJSON_AddStringToObject(root,"port",myPort);
    cJSON_AddStringToObject(root,"destination",SZ_IOT_APP_NAME);
    cJSON *payload = cJSON_CreateObject();
    if(!payload)
    {
        err_debug("create payload error");
        cJSON_Delete(root);
        root = NULL;
        return FAILURE;
    }
    cJSON_AddItemToObject(root,"payload",payload);
    cJSON_AddNumberToObject(payload,"code",103);
    cJSON_AddStringToObject(payload,"id",id);
    cJSON_AddNumberToObject(payload,"serial",serial);

	send_data = cJSON_PrintUnformatted(root);
    if(!send_data)
    {
        cJSON_Delete(root);
        root = NULL;
        err_debug("cjson print error");
        return FAILURE;
    }

	unsigned int send_len = strlen(send_data);

    int ret = sz_mq_send_data_by_topic(szIotTopic, send_len, send_data);

    cJSON_Delete(root);
    root = NULL;
    sz_free((void *)send_data);
    send_data = NULL;

    return ret;
	
}

int sz_104_delete_device_report(unsigned char *id)
{
	unsigned char *send_data = NULL;

	cJSON *root = cJSON_CreateObject();
    if(!root)
    {
        err_debug("create root error");
        return FAILURE;
    }

	
    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
    cJSON_AddStringToObject(root,"port",myPort);
    cJSON_AddStringToObject(root,"destination",SZ_IOT_APP_NAME);
    cJSON *payload = cJSON_CreateObject();
    if(!payload)
    {
        err_debug("create payload error");
        cJSON_Delete(root);
        root = NULL;
        return FAILURE;
    }

	cJSON *idArry = cJSON_CreateArray();
	if(!idArry)
	{
		err_debug("create idArry error");
        cJSON_Delete(root);
        root = NULL;
		cJSON_Delete(payload);
		payload = NULL;
        return FAILURE;
	}

	cJSON_AddItemToArray(idArry, cJSON_CreateString(id));
//	cJSON_AddNullToObject(idArry, id);
	
    cJSON_AddItemToObject(root,"payload",payload);
	cJSON_AddItemToObject(payload, "id", idArry);
    cJSON_AddNumberToObject(payload,"code",104);
    cJSON_AddNumberToObject(payload,"serial",serial++);
	cJSON_AddNumberToObject(payload, "control", 1);

	send_data = cJSON_PrintUnformatted(root);
    if(!send_data)
    {
        cJSON_Delete(root);
        root = NULL;
        err_debug("cjson print error");
        return FAILURE;
    }

	unsigned int send_len = strlen(send_data);

    int ret = sz_mq_send_data_by_topic(szIotTopic, send_len, send_data);

    cJSON_Delete(root);
    root = NULL;
    sz_free((void *)send_data);
    send_data = NULL;

    return ret;
}

int sz_105_device_register_rsp(cJSON *payload)
{
	int rc = 0, i;
	char sql[500] = {0};
	int inset_result = 0;
  	char *zErrMsg = NULL;

	if(!payload)
    {
        err_debug("payload is NULL");
        return FAILURE;
    }
	
	cJSON *check_list = cJSON_GetObjectItem(payload, "check_list");
	int arraySize =  cJSON_GetArraySize(check_list);
	if(!arraySize)
    {
        err_debug("arraySize is 0");
        return FAILURE;
    }
	debug("updata status");
	for(i = 0; i < arraySize; i++)
	{
		cJSON *checkList = cJSON_GetArrayItem(check_list, i);
		cJSON *id = cJSON_GetObjectItem(checkList, "id");
		cJSON *control = cJSON_GetObjectItem(checkList, "control");
		if(control->valueint == 0){
			sprintf(sql,"UPDATE device_tb SET status = %d WHERE ieee = '%s';", 1, id->valuestring);
			rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
			if (rc != SQLITE_OK)
			{
				err_debug("SQL error: %s\n", zErrMsg);
				sqlite3_free(zErrMsg);
				return 1;
			} 
		}
		else if(control->valueint == 1)
		{
			sprintf(sql,"DELETE FROM device_tb WHERE ieee = '%s';", id->valuestring);
			rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
			if (rc != SQLITE_OK)
			{
				err_debug("SQL error: %s\n", zErrMsg);
				sqlite3_free(zErrMsg);
				return 1;
			} 
		}
	}
}



int sz_110_add_device_rsp(cJSON *ids, int devclass, int32 devSerial)
{
	unsigned char *send_data = NULL;

	cJSON *root = cJSON_CreateObject();
    if(!root)
    {
        err_debug("create root error");
        return FAILURE;
    }

	
    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
    cJSON_AddStringToObject(root,"port",myPort);
    cJSON_AddStringToObject(root,"destination",SZ_IOT_APP_NAME);
    cJSON *payload = cJSON_CreateObject();
    if(!payload)
    {
        err_debug("create payload error");
        cJSON_Delete(root);
        root = NULL;
        return FAILURE;
    }

	
    cJSON_AddItemToObject(root,"payload",payload);
	cJSON_AddItemToObject(payload, "ids", ids);
    cJSON_AddNumberToObject(payload,"code",110);
    cJSON_AddNumberToObject(payload,"serial",devSerial);
	cJSON_AddNumberToObject(payload, "control", 3);

	send_data = cJSON_PrintUnformatted(root);
    if(!send_data)
    {
        cJSON_Delete(root);
        root = NULL;
        err_debug("cjson print error");
        return FAILURE;
    }

	unsigned int send_len = strlen(send_data);

    int ret = sz_mq_send_data_by_topic(szIotTopic, send_len, send_data);

    cJSON_Delete(root);
    root = NULL;
    sz_free((void *)send_data);
    send_data = NULL;

    return ret;
}


int parse_raw_data(cJSON *payload)
{
	int rc = 0, epCount = 0;
	char sql[500] = {0};
	int inset_result = 0;
  	char *zErrMsg = NULL;
	char **dbResult = NULL;
	int nRow, nColumn;
	uint16_t index = 0;
	uint32_t i, j, idAdded = 0, registered = 0;
	
    if(!payload)
    {
        err_debug("payload is NULL");
        return FAILURE;
    }


    cJSON *id = cJSON_GetObjectItem(payload,"id");
	if(!id)
    {
        err_debug("id is NULL");
        return FAILURE;
    }
	
    cJSON *ep = cJSON_GetObjectItem(payload,"ep");
    if(!ep)
    {
        err_debug("ep is NULL");
        return FAILURE;
    }
    cJSON *did = cJSON_GetObjectItem(payload,"did");
    if(!did)
    {
        err_debug("did is NULL");
        return FAILURE;
    }
    cJSON *pid = cJSON_GetObjectItem(payload,"pid");
    if(!pid)
    {
        err_debug("pid is NULL");
        return FAILURE;
    }

    cJSON *st = cJSON_GetObjectItem(payload,"st");
    if(!st)
    {
        err_debug("st is NULL");
        return FAILURE;
    }

	cJSON *rawData = cJSON_GetObjectItem(st,"rawData");
    if(!rawData)
    {
        err_debug("rawData is NULL");
        return FAILURE;
    }

//    debug("rawData:[%s]",rawData->valuestring);

	sz_rebuild_st(ep->valueint, did->valueint, pid->valueint, rawData->valuestring);

}

int sz_rebuild_st(unsigned int ep,unsigned short did,unsigned short pid,char *rawdata)
{
	int rawdata_string_len = strlen(rawdata);
	int rawdata_hex_len = 0;
	int dataStart = 6, port = 0;
	int returnValue, returnValue1;
	int rc = 0;
	char sql[500] = {0};
	int inset_result = 0;
  	char *zErrMsg = NULL;
	char **dbResult = NULL;
	int nRow, nColumn;
	int  epCount = 0;
	uint16 index = 0;
	uint32 i, j, idAdded = 0, registered = 0;
	unsigned char id[21] = {0};
	
	unsigned char rawdata_hex[rawdata_string_len/2];
    hexStr2bytes(rawdata,rawdata_hex,rawdata_string_len/2);
//	int dataType = rawdata_hex[dataStart];
//	int firstEndpoint = rawdata_hex[dataStart - 1];

//	printf("rawdata_hex = %d \n", rawdata_hex[0]);
	
	if(rawdata_hex[0] != 0x11 || rawdata_string_len > 256){
		err_debug("rawData is not we need");
        return FAILURE;
	}

	rawdata_hex_len = rawdata_hex[1];
	
	sprintf(id, "03%02x02000000%02x%02x%02x%02x", rawdata_application_port, rawdata_hex[2], rawdata_hex[3], rawdata_hex[4], rawdata_hex[5]);

	sz06_update_olflag(id,add);
	
	sprintf(sql,"SELECT ieee,status FROM device_tb;");	
	rc = sqlite3_get_table(db,sql, &dbResult, &nRow,&nColumn, &zErrMsg);

	if (rc != SQLITE_OK)
	{
		err_debug("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		return 1;
	} 
	
//	debug("nRow[%d]nColumn[%d]",nRow,nColumn);
	index = nColumn;
	for (i = 0; i < nRow; i++)
	{
		unsigned char ieee[21] = {0};
		unsigned int status = 0xffffffff;
//		debug("i[%d] nRow[%d]",i,nRow);
		for (j = 0; j < nColumn; j++)
		{
			if((strlen("ieee") == strlen(dbResult[j])) && (memcmp("ieee",dbResult[j],strlen("ieee")) == 0))
			{
				if(strlen(dbResult[index]) > 20)
					memcpy(ieee,dbResult[index],20);
				else
					strcpy(ieee,dbResult[index]);
			}
			else if((strlen("status") == strlen(dbResult[j])) && (memcmp("status",dbResult[j],strlen("status")) == 0))
			{
				if(dbResult[index] == NULL)
				{
					err_debug("status is NULL");
				}
				else
					status = atoi(dbResult[index]);
			}
//			debug("%s**%s", ieee, id->valuestring);
			if(strcmp(id,ieee) == 0){
				idAdded = 1;
//				debug("status = %d", status);
				if(status == 1)
					registered = 1;
			}
			
			index += 1;
		}
	}

	sqlite3_free_table(dbResult);
	
	if(!idAdded)
	{
		err_debug("%s device is not added", id);
        return FAILURE;
	}

	if(!registered)
	{	
		debug("device not registered! Will try to registered!");
		register_device(id);
/*		for(epCount = 1; epCount < 6; epCount++)
		{
			collect_data device;
	    	strncpy(device.id, id->valuestring, 21);
			device.ep = epCount;
			device.olflag = 3;
			device.elelev = 2;
			device.digidal = 2;
			device.eleout = 2;
			device.anal420 = 2;
			device.volt3_3 = 5;
			device.volt5_0 = 6;
			device.dstemp = 0.000001;
			device.pttemp = 0.000001;
			device.colltemp = 0.000001;
			device.collhumi = 0.000001;
			device.next = NULL;
			sz06_insetDevice(device);
		}*/
        return FAILURE;
	}
	else
	{
		if(rawdata_hex_len == rawdata_string_len/2)
		{
			sprintf(sql,"UPDATE device_tb SET rawdata = '%s' WHERE ieee = '%s';", rawdata, id);
			rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
			if (rc != SQLITE_OK)
			{
				err_debug("SQL error: %s\n", zErrMsg);
				sqlite3_free(zErrMsg);
				return 1;
			}
		}
//		sz_upData_device_info(id);
	}
//	cJSON *Port = cJSON_CreateObject();
	double collectValue;
	int boolData, dec_pl;
	char str[20];
				
	for(dataStart; dataStart < rawdata_hex_len;){
//		switch (rawdata_hex[dataStart++]){
	//		cJSON_AddItemToObject(st, "Port", endpoint0Data);		
//			case 0:
//				debug("*0*");

				cJSON *st= cJSON_CreateObject();  //need free

				if(!st){
					err_debug("st is NULL");
					return FAILURE;
				}
	
				ep = rawdata_hex[dataStart++] + 1;
				
				switch (rawdata_hex[dataStart++])
				{
					case 0:
						//debug("/0/");
						boolData = rawdata_hex[dataStart++];
						returnValue =  sz06_update_elelev(id, boolData, ep);
						if(returnValue)
						{
							cJSON_AddNumberToObject(st, "elelev", boolData);
							sz_create_package(st, ep, id);
						}
						else
						{
							cJSON_Delete(st);
       						st = NULL;
						}
						break;
					case 1:
						//debug("/1/");
						boolData = rawdata_hex[dataStart++];
						returnValue =  sz06_update_digidal(id, boolData, ep);
						if(returnValue)
						{
							cJSON_AddNumberToObject(st, "digidal", boolData);
							sz_create_package(st, ep, id);
						}
						else
						{
							cJSON_Delete(st);
       						st = NULL;
						}
						break;
					case 4:
						//debug("/4/");
						boolData = rawdata_hex[dataStart++];
						returnValue =  sz06_update_eleout(id, boolData, ep);
						if(returnValue)
						{
							cJSON_AddNumberToObject(st, "eleout", boolData);
							sz_create_package(st, ep, id);
						}
						else
						{
							cJSON_Delete(st);
       						st = NULL;
						}
						break;					
					case 5:
						//debug("/5/");
						collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
						returnValue =  sz06_update_anal420(id, collectValue, ep);
						if(returnValue)
						{
							sprintf(str,"%.2f MA", collectValue);
							cJSON_AddStringToObject(st, "anal420", str);
							sz_create_package(st, ep, id);
						}
						else
						{
							cJSON_Delete(st);
       						st = NULL;
						}
						break;
					case 7:
						//debug("/7/");
						collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
						returnValue =  sz06_update_volt3_3(id, collectValue, ep);
						if(returnValue)
						{
							sprintf(str,"%.2f V", collectValue);
							cJSON_AddStringToObject(st, "volt3.3", str);
							sz_create_package(st, ep, id);
						}
						else
						{
							cJSON_Delete(st);
       						st = NULL;
						}
						break;		
					case 8:
						//debug("/8/");
						collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
						returnValue =  sz06_update_volt5_0(id, collectValue, ep);
						if(returnValue)
						{
							sprintf(str,"%.2f V", collectValue);
							cJSON_AddStringToObject(st, "volt5.0", str);
							sz_create_package(st, ep, id);
						}
						else
						{
							cJSON_Delete(st);
       						st = NULL;
						}
						break;	
					case 9:
						//debug("/9/");
						if(rawdata_hex[dataStart++]){
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
							returnValue =  sz06_update_dstemp(id, collectValue, ep);
							if(returnValue)
							{
								sprintf(str, "%.2f ℃", collectValue);
								cJSON_AddStringToObject(st, "Dstemp", str);
								sz_create_package(st, ep, id);
							}
							else
							{
								cJSON_Delete(st);
	       						st = NULL;
							}
						}
						else{
							collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0);
							returnValue =  sz06_update_dstemp(id, collectValue, ep);
							if(returnValue)
							{
								sprintf(str, "%.2f ℃", collectValue);
								cJSON_AddStringToObject(st, "Dstemp", str);
								sz_create_package(st, ep, id);
							}
							else
							{
								cJSON_Delete(st);
	       						st = NULL;
							}
						}
						break;
					case 10:
						//debug("/10/");
						if(rawdata_hex[dataStart++]){
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
							returnValue =  sz06_update_pttemp(id, collectValue, ep);
							if(returnValue)
							{				
								sprintf(str, "%.2f ℃", collectValue);
								cJSON_AddStringToObject(st, "PTtemp", str);
								sz_create_package(st, ep, id);
							}
							else
							{
								cJSON_Delete(st);
	       						st = NULL;
							}
						}
						else{
							collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0);
							returnValue =  sz06_update_pttemp(id, collectValue, ep);
							if(returnValue)
							{				
								sprintf(str, "%.2f ℃", collectValue);
								cJSON_AddStringToObject(st, "PTtemp", str);
								sz_create_package(st, ep, id);
							}
							else
							{
								cJSON_Delete(st);
	       						st = NULL;
							}

						}
						break;
					case 11:
						//debug("/11/");
						if(rawdata_hex[dataStart++]){
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
							returnValue1 =  sz06_update_colltemp(id, collectValue, ep);
							if(returnValue1)
							{				
								sprintf(str, "%.2f ℃", collectValue);
								cJSON_AddStringToObject(st, "colltemp", str);
//								sz_create_package(st, ep);
							}
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
							returnValue =  sz06_update_collhumi(id, collectValue, ep);
							if(returnValue)
							{				
								sprintf(str, "%.2f%", collectValue);
								cJSON_AddStringToObject(st, "collhumi", str);
//								sz_create_package(st, ep);
							}
							if(returnValue || returnValue1)
								sz_create_package(st, ep, id);
							else
							{
								cJSON_Delete(st);
	       						st = NULL;
							}
						}
						else{
							collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0);
							returnValue1 =  sz06_update_colltemp(id, collectValue, ep);
							if(returnValue1)
							{				
								sprintf(str, "%.2f ℃", collectValue);
								cJSON_AddStringToObject(st, "colltemp", str);
//								sz_create_package(st, ep);
							}
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
							returnValue =  sz06_update_collhumi(id, collectValue, ep);
							if(returnValue)
							{				
								sprintf(str, "%.2f%", collectValue);
								cJSON_AddStringToObject(st, "collhumi", str);
//								sz_create_package(st, ep);
							}
							if(returnValue || returnValue1)
								sz_create_package(st, ep, id);
							else
							{
								cJSON_Delete(st);
	       						st = NULL;
							}
						}
						break;
					default:
						break;
				}
				
		//	break;
		//	}
	}
	sz_upData_device_info(id);
}

int sz_create_package(cJSON *st, unsigned  int ep, unsigned char *id)
{
	unsigned char *send_data = NULL;

    if(!st)
    {
        err_debug("st is NULL");
        return FAILURE;
    }

    if(!cJSON_GetArraySize(st))
    {
        err_debug("st size is 0");
        cJSON_Delete(st);
        st = NULL;
        return FAILURE;
    }

    cJSON *root = cJSON_CreateObject();
    if(!root)
    {
        err_debug("create root error");
        return FAILURE;
    }

	
    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
    cJSON_AddStringToObject(root,"port",myPort);
    cJSON_AddStringToObject(root,"destination",SZ_IOT_APP_NAME);
    cJSON *payload = cJSON_CreateObject();
    if(!payload)
    {
        err_debug("create payload error");
        cJSON_Delete(root);
        root = NULL;
        return FAILURE;
    }
    cJSON_AddItemToObject(root,"payload",payload);
    cJSON_AddNumberToObject(payload,"code",104);
    cJSON_AddNumberToObject(payload,"control",2);
    cJSON_AddNumberToObject(payload,"serial",serial++);
    cJSON_AddStringToObject(payload,"id", id);
    cJSON_AddNumberToObject(payload,"ep", ep);
    cJSON_AddNumberToObject(payload,"did",1);
    cJSON_AddNumberToObject(payload,"pid",65286);
	 cJSON_AddNumberToObject(payload,"dtype",1);
    cJSON_AddBoolToObject(payload,"ol",1);
    cJSON_AddItemToObject(payload,"st",st);

    send_data = cJSON_PrintUnformatted(root);
    if(!send_data)
    {
        cJSON_Delete(root);
        root = NULL;
        err_debug("cjson print error");
        return FAILURE;
    }

	unsigned int send_len = strlen(send_data);

    int ret = sz_mq_send_data_by_topic(szIotTopic, send_len, send_data);

    cJSON_Delete(root);
    root = NULL;
    sz_free((void *)send_data);
    send_data = NULL;

    return ret;
}


int sz_heartbeat_package(cJSON *device)
{
//	unsigned char *send_data = NULL;
	int deviceSize =0, tmpSize = 0, i = 0, j = 0;
	int ret;
	
    if(!device)
    {
        err_debug("st device NULL");
        return FAILURE;
    }

    if(!cJSON_GetArraySize(device))
    {
        err_debug("devicesize is 0");
        cJSON_Delete(device);
        device = NULL;
        return FAILURE;
    }

//	debug("devicesize is %d", cJSON_GetArraySize(device));

	deviceSize = cJSON_GetArraySize(device);
	tmpSize = deviceSize;

	while(tmpSize > 0){
		unsigned char *send_data = NULL;
		cJSON *heartbeatDevice = cJSON_CreateArray();
		if(!heartbeatDevice)
 		{
	   		err_debug("create heartbeatDevice error");
			cJSON_Delete(device);
        	device = NULL;
	    	return FAILURE;
 		}
//		if(tmpSize > 2)
//		{
			for(i = 0 ; i < 5; i++)
			{	
				if(j < deviceSize)
				{
					cJSON *device1 = cJSON_GetArrayItem(device, j++);
					cJSON *tmp = cJSON_Duplicate(device1, 1);
//					debug("j = %d", j);
					cJSON_AddItemToArray(heartbeatDevice, tmp);
				}
			}
//		}

//		debug("heartbeatDevice Size = %d", cJSON_GetArraySize(heartbeatDevice));
			
	    cJSON *root = cJSON_CreateObject();
	    if(!root)
	    {
	        err_debug("create root error");
			cJSON_Delete(heartbeatDevice);
	        heartbeatDevice = NULL;
			cJSON_Delete(device);
	        device = NULL;
	        return FAILURE;
	    }

	    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
	    cJSON_AddStringToObject(root,"port",myPort);
	    cJSON_AddStringToObject(root,"destination",SZ_IOT_APP_NAME);
	    cJSON *payload = cJSON_CreateObject();
	    if(!payload)
	    {
	        err_debug("create payload error");
			cJSON_Delete(heartbeatDevice);
	        heartbeatDevice = NULL;
			cJSON_Delete(device);
	        device = NULL;
	        cJSON_Delete(root);
	        root = NULL;
	        return FAILURE;
	    }

		cJSON_AddItemToObject(root,"payload",payload);
	    cJSON_AddNumberToObject(payload,"code",101);
	    cJSON_AddNumberToObject(payload,"serial",serial++);

	//    cJSON_AddItemToObject(payload,"device",device);
		cJSON_AddItemToObject(payload,"device",heartbeatDevice);

	    send_data = cJSON_PrintUnformatted(root);

	    if(!send_data)
	    {
	        cJSON_Delete(root);
	        root = NULL;
	        err_debug("cjson print error");
	        return FAILURE;
	    }

		unsigned int send_len = strlen(send_data);

	    ret = sz_mq_send_data_by_topic(szIotTopic, send_len, send_data);

	    cJSON_Delete(root);
	    root = NULL;
	    sz_free((void *)send_data);
	    send_data = NULL;
		tmpSize -= 5;
	}

	cJSON_Delete(device);
    device = NULL;
	
    return ret;
}


int sz_mq_send_data_by_topic(char *topic,int data_len,unsigned char *data)
{
    /*
    qos:0-send once;1-at least once;2-at most once
    int mosquitto_publish(struct mosquitto *mosq, uint16_t *mid,
    const char *topic, uint32_t payloadlen, const uint8_t *payload,
    int qos, bool retain)
    */
    mqtt_clinet_t *mqtt_client = &sz_mqtt.cloud_client.mqtt_client;

    int rc = mosquitto_publish(mqtt_client->mosq,NULL,topic,data_len,data,2, 0);
    if(rc == MOSQ_ERR_SUCCESS)
    {
        print_time_curr();
        ms_debug("mq send topic[%s] data_len[%d]",topic,data_len);
        if(data_len < 200000)
        {
            ms_debug("mq send data[%s]",data);
        }
        //debug("mosquitto_publish success");
    }
    else if(rc == MOSQ_ERR_INVAL)
    {
        err_debug("mosquitto_publish MOSQ_ERR_INVAL");
    }
    else if(rc == MOSQ_ERR_NOMEM)
    {
        err_debug("mosquitto_publish MOSQ_ERR_NOMEM");
    }
    else if(rc == MOSQ_ERR_NO_CONN)
    {
        err_debug("mosquitto_publish MOSQ_ERR_NO_CONN");
    }
    else if(rc == MOSQ_ERR_PROTOCOL)
    {
        err_debug("mosquitto_publish MOSQ_ERR_PROTOCOL");
    }
    else if(rc == MOSQ_ERR_PAYLOAD_SIZE)
    {
        err_debug("mosquitto_publish MOSQ_ERR_PAYLOAD_SIZE");
    }
    else
    {
        err_debug("mosquitto_publish rc[%d]",rc);
    }


}

//int register_device(cJSON * id)
int register_device(unsigned char *id)
{
	unsigned char *send_data = NULL;

	printf("\nregister  %s\n", id);

    cJSON *root = cJSON_CreateObject();
    if(!root)
    {
        err_debug("create root error");
        return FAILURE;
    }

    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
    cJSON_AddStringToObject(root,"port",myPort);
    cJSON_AddStringToObject(root,"destination",SZ_IOT_APP_NAME);
	
    cJSON *payload = cJSON_CreateObject();
    if(!payload)
    {
        err_debug("create payload error");
        cJSON_Delete(root);
        root = NULL;
        return FAILURE;
    }
    cJSON_AddItemToObject(root,"payload",payload);
    cJSON_AddNumberToObject(payload,"code",105);
    cJSON_AddNumberToObject(payload,"serial",serial++);
	cJSON_AddStringToObject(payload,"id", id);

//	cJSON_AddItemToObject(payload, "id", id);
    cJSON_AddNumberToObject(payload,"ep", 1);
    cJSON_AddNumberToObject(payload,"did",1);
    cJSON_AddNumberToObject(payload,"pid",65286);
    cJSON_AddBoolToObject(payload,"ol",1);
	cJSON *st = cJSON_CreateObject();
    if(!st)
    {
        err_debug("create st error");
        cJSON_Delete(root);
        root = NULL;
        return FAILURE;
    }
    cJSON_AddItemToObject(payload,"st",st);
	cJSON_AddStringToObject(st, "dsp", "SZ06");
	cJSON_AddStringToObject(st, "eplist", "001");

    send_data = cJSON_PrintUnformatted(root);
    if(!send_data)
    {
        cJSON_Delete(root);
        root = NULL;
        err_debug("cjson print error");
        return FAILURE;
    }

	unsigned int send_len = strlen(send_data);

    int ret = sz_mq_send_data_by_topic(szIotTopic, send_len, send_data);

    cJSON_Delete(root);
    root = NULL;
    sz_free((void *)send_data);
    send_data = NULL;

    return ret;
}

void sz06_collectDataInit(void)
{
	if(0 != pthread_mutex_init(&device_manage_lock,NULL))
		err_debug("--------------------> device_data_lock init error");
	
	memset(sz06_collectDataHead.id,0,21);
	memset(sz06_collectDataHead.addr,0,9);
	sz06_collectDataHead.olflag = 3;
	sz06_collectDataHead.elelev = 0xff;
	sz06_collectDataHead.digidal = 0xff;
	sz06_collectDataHead.eleout = 0xff;
	sz06_collectDataHead.anal420 = 0.0;
	sz06_collectDataHead.volt3_3 = 0.0;
	sz06_collectDataHead.volt5_0 = 0.0;
	sz06_collectDataHead.dstemp = 0.0;
	sz06_collectDataHead.pttemp = 0.0;
	sz06_collectDataHead.colltemp = 0.0;
	sz06_collectDataHead.collhumi = 0.0;
	sz06_collectDataHead.next = NULL;
	
	return;
}

int sz06_insetDevice(collect_data data)
{
//	debug("device join");
	DEVICE_MANAGE_UNLOCK;
	DEVICE_MANAGE_LOCK;

	collect_data *tmpData = sz06_collectDataHead.next;
	collect_data *myData = (collect_data *)sz_malloc(sizeof(collect_data));

	if(myData == NULL)
	{
		err_debug("collect_data sz_malloc failure");
		DEVICE_MANAGE_UNLOCK;
		return 1;
	}
	else
	{
		memcpy((unsigned char *)myData,(unsigned char *)&data,sizeof(collect_data));
		myData->next = NULL;
	}

	while(tmpData != NULL)
	{
		if((memcmp(myData->id,tmpData->id,20) == 0) && myData->ep == tmpData->ep)
		{
//			debug("device already in list");

			sz_free((void *)myData);
			DEVICE_MANAGE_UNLOCK;
			return 2;
		}
		tmpData = tmpData->next;
	}

	myData->next = sz06_collectDataHead.next;
	sz06_collectDataHead.next = myData;
	DEVICE_MANAGE_UNLOCK;
//    debug("device_info:id:[%s]",myData->id);
	return 3;
}

int sz06_delete_device(unsigned char *id)
{
	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;

	collect_data *prev_device = &sz06_collectDataHead;
	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if(memcmp(id,tmp_device->id,20) == 0)
		{
			
			prev_device->next = tmp_device->next;
			sz_free((void *)tmp_device);
			tmp_device = prev_device->next;
//			debug("delete device[%s] ",id);
		}
		else
		{
			prev_device = tmp_device;
			tmp_device = prev_device->next;
		}
	}
	DEVICE_MANAGE_UNLOCK;
	
	return SUCCESS;
}

int sz06_update_olflag(unsigned char *id,int olflag)
{
	int returnValue;
	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;
	
	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20)== 0 ))
		{
			if((tmp_device->olflag >= 0) && (tmp_device->olflag < 4))
			{
				if((olflag == 1) && (tmp_device->olflag < 3))
					tmp_device->olflag += 1;
				else if((olflag == 0) && (tmp_device->olflag > 0))
					tmp_device->olflag -= 1;
			}
//			debug("olFlag = %d", tmp_device->olflag);
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	return returnValue;
}


//1  --changed   0  --the same
int sz06_update_elelev(unsigned char *id,int elelev, int ep)
{
	int returnValue;

	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;

	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20)) == 0 && (ep == tmp_device->ep))
		{
			if(tmp_device->elelev == elelev)
				returnValue = 0;
			else
			{
			   tmp_device->elelev = elelev;
			   returnValue = 1;
			}
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	return returnValue;
}

int sz06_update_digidal(unsigned char *id,int digidal, int ep)
{
	int returnValue;

	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;

	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20)) == 0 && (ep == tmp_device->ep))
		{
			if(tmp_device->digidal == digidal)
				returnValue = 0;
			else
			{
			   tmp_device->digidal = digidal;
			   returnValue = 1;
			}
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	return returnValue;
}

int sz06_update_eleout(unsigned char *id,int eleout, int ep)
{
	int returnValue;

	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;

	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20)) == 0 && (ep == tmp_device->ep))
		{
			if(tmp_device->eleout == eleout)
				returnValue = 0;
			else
			{
			   tmp_device->eleout = eleout;
			   returnValue = 1;
			}
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	return returnValue;
}

int sz06_update_anal420(unsigned char *id,double anal420, int ep)
{
	int returnValue;

	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;

	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20) == 0) && (ep == tmp_device->ep))
		{
			if(tmp_device->anal420 == anal420)
				returnValue = 0;
			else
			{
			   tmp_device->anal420 = anal420;
			   returnValue = 1;
			}
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	return returnValue;
}

int sz06_update_volt3_3(unsigned char *id,double volt3_3, int ep)
{
	int returnValue;

	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;

	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20)) == 0 && (ep == tmp_device->ep))
		{
			if(tmp_device->volt3_3 == volt3_3)
				returnValue = 0;
			else
			{
			   tmp_device->volt3_3 = volt3_3;
			   returnValue = 1;
			}
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	return returnValue;
}

int sz06_update_volt5_0(unsigned char *id,double volt5_0, int ep)
{
	int returnValue;

	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;

	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20)) == 0 && (ep == tmp_device->ep))
		{
			if(tmp_device->volt5_0 == volt5_0)
				returnValue = 0;
			else
			{
			   tmp_device->volt5_0 = volt5_0;
			   returnValue = 1;
			}
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	return returnValue;
}

int sz06_update_dstemp(unsigned char *id,double dstemp, int ep)
{
	int returnValue;

	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;

	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20)) == 0 && (ep == tmp_device->ep))
		{
			if(tmp_device->dstemp == dstemp)
				returnValue = 0;
			else
			{
			   tmp_device->dstemp = dstemp;
			   returnValue = 1;
			}
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	return returnValue;
}

int sz06_update_pttemp(unsigned char *id,double pttemp, int ep)
{
	int returnValue;

	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;

	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20)) == 0 && (ep == tmp_device->ep))
		{
			if(tmp_device->pttemp == pttemp)
				returnValue = 0;
			else
			{
			   tmp_device->pttemp = pttemp;
			   returnValue = 1;
			}
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	return returnValue;
}

int sz06_update_colltemp(unsigned char *id,double colltemp, int ep)
{
	int returnValue;

	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;

	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20)) == 0 && (ep == tmp_device->ep))
		{
			if(tmp_device->colltemp == colltemp)
				returnValue = 0;
			else
			{
			   tmp_device->colltemp = colltemp;
			   returnValue = 1;
			}
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	return returnValue;
}

int sz06_update_collhumi(unsigned char *id,double collhumi, int ep)
{
	int returnValue;

	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MANAGE_LOCK;

	collect_data *tmp_device = sz06_collectDataHead.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20)) == 0 && (ep == tmp_device->ep))
		{
			if(tmp_device->collhumi == collhumi)
				returnValue = 0;
			else
			{
			   tmp_device->collhumi = collhumi;
			   returnValue = 1;
			}
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	return returnValue;
}

void sz06_heartbeat_handler(void)
{
	int i, strLen, stFlag;

	DEVICE_MANAGE_LOCK;
	
	collect_data *tmp_device = sz06_collectDataHead.next;
	collect_data deviceinfo;
	char str[20];
	unsigned char idStr[21];
	debug("heartbeat_handler!");
	
	cJSON *device = cJSON_CreateArray();
	if(!device)
 	{
	    err_debug("create device error");
	    return ;
 	}
	
	while(tmp_device != NULL)
	{
		cJSON *info = cJSON_CreateObject();
		if(!info)
 	    {
	        err_debug("create info error");
	        return ;
	    }
		cJSON *st = cJSON_CreateObject();
		if(!st)
 	    {
	        err_debug("create st error");
	        return ;
	    }
		strncpy(idStr, tmp_device->id, 21);
//		debug("[%s] [%s]", idStr, tmp_device->id);
		cJSON_AddStringToObject(info, "id", idStr);
        cJSON_AddNumberToObject(info,"ep", tmp_device->ep);
        cJSON_AddNumberToObject(info,"did",1);
        cJSON_AddNumberToObject(info,"pid",65286);
		if(tmp_device->olflag == 0)
			cJSON_AddBoolToObject(info, "ol", 0);
		else
			cJSON_AddBoolToObject(info, "ol", 1);
//		while((tmp_device != NULL) && (memcmp((void *)idStr, (void *)tmp_device->id,20) == 0))
//		{
//			debug("find data");
			if(tmp_device->elelev != 2)
			{
				cJSON_AddNumberToObject(st, "elelev", tmp_device->elelev);
			}
			if(tmp_device->digidal != 2)
			{
				cJSON_AddNumberToObject(st, "digidal", tmp_device->digidal);
			}
			if(tmp_device->eleout != 2)
			{
				cJSON_AddNumberToObject(st, "eleout", tmp_device->eleout);
			}
			if(tmp_device->anal420 != 2)
			{
//				debug("anal420 %.2f", tmp_device->anal420);
				sprintf(str,"%.2f MA", tmp_device->anal420);
				cJSON_AddStringToObject(st, "anal420", str);
			}
			if(tmp_device->volt3_3 != 5)
			{	
				sprintf(str,"%.2f V", tmp_device->volt3_3);
				cJSON_AddStringToObject(st, "volt3.3", str);
			}
			if(tmp_device->volt5_0 != 6)
			{
				sprintf(str,"%.2f V", tmp_device->volt5_0);
				cJSON_AddStringToObject(st, "volt5.0", str);
			}
			if(tmp_device->dstemp != 0.000001)
			{
				sprintf(str, "%.2f ℃", tmp_device->dstemp);
				cJSON_AddStringToObject(st, "Dstemp", str);
			}
			if(tmp_device->pttemp != 0.000001)
			{
				sprintf(str, "%.2f ℃", tmp_device->pttemp);
				cJSON_AddStringToObject(st, "PTtemp", str);
			}
			if(tmp_device->colltemp != 0.000001)
			{
				sprintf(str, "%.2f ℃", tmp_device->colltemp);
				cJSON_AddStringToObject(st, "colltemp", str);
			}
			if(tmp_device->collhumi != 0.000001)
			{
				sprintf(str, "%.2f%", tmp_device->collhumi);
				cJSON_AddStringToObject(st, "collhumi", str);
			}
			tmp_device = tmp_device->next;
			
//		}
//		strLen = strlen(idStr);
//		printf("\n%d\n", strLen);
//		sz_heartbeat_package(st, 1, idStr);
		if(!cJSON_GetArraySize(st))
		{
//			err_debug("st is null");
			cJSON_Delete(st);
    		st = NULL;
			cJSON_Delete(info);
   			info = NULL;
		}
		else
		{
			cJSON_AddItemToObject(info, "st", st);
			cJSON_AddItemToArray(device, info);
		}
//		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	sz_heartbeat_package(device);
	
	return ;
}

void checkOl_thread_init(void)
{
    pthread_t thread_reconnect_t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread_reconnect_t, &attr, thread_checkOl, (void *)NULL))
    {
        debug("pthread of checkOl_thread_init create error\n");
    }
    else
    {
        debug("pthread of checkOl_thread_init create success\n");
    }
}

void *thread_checkOl(void *p)
{
    time_t	nowTime;
	struct	tm * timeNow;
	struct timeval tv;
	int myTime = 1;
  // heartbeatCount 
    while(1)
    {
	/* get the system time */
	time(&nowTime);
	timeNow = localtime(&nowTime);

	myTime = timeNow->tm_min % 1;
	if((myTime == 0) && (timeNow->tm_sec == 0))
	{
//	   debug("myTime = %d", myTime);
	   checkOl_handler();
	}
    sleep(1);
    }

}

void checkOl_handler(void)
{
	collect_data *tmp_device = sz06_collectDataHead.next;
	unsigned char idStr[21];
	unsigned char addr[9];
	unsigned char rawdata[15];

	while(tmp_device != NULL)
	{	
		if(tmp_device->ep == 1)
		{
			unsigned char *send_data = NULL;
			
			cJSON *root = cJSON_CreateObject();
		    if(!root)
		    {
		        err_debug("create root error");
		        return FAILURE;
		    }
			strncpy(idStr, tmp_device->id, 21);
			strncpy(addr, tmp_device->addr, 9);
			sprintf(rawdata, "1007%sFF", addr);
			debug("[%s] [%s] [%s]", idStr, tmp_device->id, addr);
		    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
		    cJSON_AddStringToObject(root,"port",myPort);
		    cJSON_AddStringToObject(root,"destination",THROUGH_DATA_APPLICATION);
		    cJSON *payload = cJSON_CreateObject();
		    if(!payload)
		    {
		        err_debug("create payload error");
		        cJSON_Delete(root);
		        root = NULL;
		        return FAILURE;
		    }
			cJSON *control = cJSON_CreateObject();
			if(!control)
		    {
		        err_debug("create control error");
		        cJSON_Delete(root);
		        root = NULL;
				cJSON_Delete(payload);
		        payload = NULL;
		        return FAILURE;
		    }
			cJSON_AddItemToObject(root,"payload",payload);
		    cJSON_AddNumberToObject(payload,"code",1002);
		    cJSON_AddNumberToObject(payload,"serial",serial++);
		    cJSON_AddStringToObject(payload,"id", rawdata_application_id);
		    cJSON_AddNumberToObject(payload,"ep", 1);
			cJSON_AddNumberToObject(payload,"did",1);
		    cJSON_AddNumberToObject(payload,"pid",65286);
			cJSON_AddItemToObject(payload, "control", control);

			cJSON_AddStringToObject(control, "rawData", rawdata);

		    send_data = cJSON_PrintUnformatted(root);
		    if(!send_data)
		    {
		        cJSON_Delete(root);
		        root = NULL;
		        err_debug("cjson print error");
		        return FAILURE;
		    }

			unsigned int send_len = strlen(send_data);

		    int ret = sz_mq_send_data_by_topic(szZigBee5_0Topic, send_len, send_data);
			sz06_update_olflag(idStr, sub);

		    cJSON_Delete(root);
		    root = NULL;
		    sz_free((void *)send_data);
		    send_data = NULL;
		}
		tmp_device = tmp_device->next;
	}
	return;
}

