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

int sz_rebuild_st(unsigned char *id, unsigned int ep,unsigned short did,unsigned short pid,char *rawdata);
int sz_mq_package_handle(unsigned char* topic,int len,unsigned char* payload);
int parse_raw_data(cJSON *payload);
int register_device(unsigned char *id);
void sz06_collectDataInit(void);
int sz06_insetDevice(collect_data data);
int sz06_delete_device(unsigned char *id);
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


collect_data sz06_collectDataHead;

pthread_mutex_t device_manage_lock;



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
		
        parse_raw_data(p_payload);
	}

	if((strlen(p_application->valuestring) == strlen(CCIOT_CLOUD_APP_NAME)) && \
		(0 == memcmp(CCIOT_CLOUD_APP_NAME,p_application->valuestring,strlen(CCIOT_CLOUD_APP_NAME))))
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
		else if(code->valueint == 1002){
			sz_102_device_control_rsp(p_payload);
			sz_control_device(p_payload);
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

int sz_control_device(cJSON payload)
{
	
}

int sz_102_device_control_rsp(cJSON *payload)
{
	unsigned char *send_data = NULL;

    if(!payload)
    {
        err_debug("payload is NULL");
        return FAILURE;
    }

    cJSON *root = cJSON_CreateObject();
    if(!root)
    {
        err_debug("create root error");
        return FAILURE;
    }

//	cJSON *control = cJSON_GetObjectItem(payload, "control");
	cJSON_DeleteItemFromObject(payload, "code");
	
    cJSON_AddStringToObject(root,"application",APPLICATION_NAME_ITSELF);
    cJSON_AddStringToObject(root,"port",myPort);
    cJSON_AddStringToObject(root,"destination",SZ_IOT_APP_NAME);
	
    cJSON *myPayload = cJSON_CreateObject();
    if(!myPayload)
    {
        err_debug("create myPayload error");
        cJSON_Delete(root);
        root = NULL;
        return FAILURE;
    }
    cJSON_AddItemToObject(root,"payload",payload);
    cJSON_AddNumberToObject(myPayload,"code",102);
//    cJSON_AddNumberToObject(myPayload,"serial",serial++);
//    cJSON_AddStringToObject(myPayload,"id", id->valuestring);
//    cJSON_AddNumberToObject(myPayload,"ep", 1);
//    cJSON_AddNumberToObject(myPayload,"did",1);
//   cJSON_AddNumberToObject(myPayload,"pid",65286);
//	cJSON_AddItemToObject(myPayload, "control", control);
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
		debug("i[%d] nRow[%d]",i,nRow);
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
			if(strcmp(id->valuestring,ieee) == 0){
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
		err_debug("%s device is not added", id->valuestring);
        return FAILURE;
	}

	if(!registered)
	{	
		debug("device not registered! Will try to registered!");
		register_device(id->valuestring);
		for(epCount = 1; epCount < 6; epCount++)
		{
			collect_data device;
	    	strncpy(device.id, id->valuestring, 21);
			device.ep = epCount;
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
		}
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

    debug("rawData:[%s]",rawData->valuestring);

	sz_rebuild_st(id->valuestring, ep->valueint, did->valueint, pid->valueint, rawData->valuestring);

}

int sz_rebuild_st(unsigned char *id, unsigned int ep,unsigned short did,unsigned short pid,char *rawdata)
{
	int rawdata_string_len = strlen(rawdata);
	int dataStart = 6, port = 0;
	int returnValue, returnValue1;
	int rc = 0;
	char sql[500] = {0};
	int inset_result = 0;
  	char *zErrMsg = NULL;
	char **dbResult = NULL;
	int nRow, nColumn;

	char rawdata_hex[rawdata_string_len/2];
    hexStr2bytes(rawdata,rawdata_hex,rawdata_string_len/2);
	int dataType = rawdata_hex[dataStart];
	int firstEndpoint = rawdata_hex[dataStart - 1];

//	printf("rawdata_hex = %d \n", rawdata_hex[0]);
	
	if(rawdata_hex[0] != 0x11){
		err_debug("rawData is not we need");
        return FAILURE;
	}

//	cJSON *Port = cJSON_CreateObject();
	double collectValue;
	int boolData, dec_pl;
	char str[20];
				
	for(dataStart; dataStart < rawdata_string_len/2;){
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
						returnValue =  sz06_update_digidal(id, boolData, ep);
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
						collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/100.0;
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
						collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/100.0;
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
						collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/100.0;
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
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/100.0;
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
							collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/100.0);
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
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/100.0;
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
							collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/100.0);
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
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/100.0;
							returnValue1 =  sz06_update_colltemp(id, collectValue, ep);
							if(returnValue1)
							{				
								sprintf(str, "%.2f ℃", collectValue);
								cJSON_AddStringToObject(st, "colltemp", str);
//								sz_create_package(st, ep);
							}
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/100.0;
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
							collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/100.0);
							returnValue1 =  sz06_update_colltemp(id, collectValue, ep);
							if(returnValue1)
							{				
								sprintf(str, "%.2f ℃", collectValue);
								cJSON_AddStringToObject(st, "colltemp", str);
//								sz_create_package(st, ep);
							}
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/100.0;
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
	unsigned char *send_data = NULL;

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
    cJSON_AddNumberToObject(payload,"code",101);
    cJSON_AddNumberToObject(payload,"serial",serial++);
//    cJSON_AddStringToObject(payload,"id", id);
//    cJSON_AddNumberToObject(payload,"ep", ep);
//    cJSON_AddNumberToObject(payload,"did",1);
//    cJSON_AddNumberToObject(payload,"pid",65286);
//    cJSON_AddBoolToObject(payload,"ol",1);
    cJSON_AddItemToObject(payload,"device",device);

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

	printf("\n%s\n", id);

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
	debug("device join");
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
			debug("device already in list");

			sz_free((void *)myData);
			DEVICE_MANAGE_UNLOCK;
			return 2;
		}
		tmpData = tmpData->next;
	}

	myData->next = sz06_collectDataHead.next;
	sz06_collectDataHead.next = myData;
	DEVICE_MANAGE_UNLOCK;
    debug("device_info:id:[%s]",myData->id);
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
			debug("delete device[%s] ",id);
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
	int i, strLen;

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
		cJSON *st = cJSON_CreateObject();
		if(!st)
 	    {
	        err_debug("create st error");
	        return ;
	    }
		strncpy(idStr, tmp_device->id, 21);
		debug("[%s] [%s]", idStr, tmp_device->id);
		cJSON_AddStringToObject(st, "id", idStr);
        cJSON_AddNumberToObject(st,"ep", 1);
        cJSON_AddNumberToObject(st,"did",1);
        cJSON_AddNumberToObject(st,"pid",65286);
		while((tmp_device != NULL) && (memcmp((void *)idStr, (void *)tmp_device->id,20) == 0))
		{
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
			
		}
//		strLen = strlen(idStr);
//		printf("\n%d\n", strLen);
//		sz_heartbeat_package(st, 1, idStr);
		cJSON_AddItemToArray(device, st);
//		tmp_device = tmp_device->next;
	}
	DEVICE_MANAGE_UNLOCK;

	sz_heartbeat_package(device);
	
	return ;
}

void heartbeat_thread_init(void)
{
    pthread_t thread_reconnect_t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread_reconnect_t, &attr, thread_heartbeat1, (void *)NULL))
    {
        debug("pthread of heartbeat_thread_init create error\n");
    }
    else
    {
        debug("pthread of heartbeat_thread_init create success\n");
    }
}

void *thread_heartbeat1(void *p)
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
	   sz06_heartbeat_handler();
	}
    sleep(1);
    }

}

