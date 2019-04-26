/*************************************************************************
  > File Name: zha_strategy.c
  > Author: lunan
  > Mail: 6616@shuncom.com 
  > Created Time: 2015�?5�?0�?星期�?16�?2�?3�? ************************************************************************/

#include <stdio.h>
#include <sys/timeb.h>
#include <unistd.h>
#include <libubus.h>
#include <libubox/utils.h>
#include <math.h>
#include <time.h>
#include "cJSON.h"
#include "sz06_info.h"
#include "sql_fun.h"
#include "ubus.h"
#include "sz_printf.h"
#include "recmqtt.h"

struct blob_buf b;

sz_device_info device_header;
struct ubus_context *global_ctx;
struct ubus_request_data *global_req;


/*
coordInfo_t coordInfo=;

const char ieee_id[] = "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX";
extern uint16_t openNetworkTimeRemainingS;
extern bool whiteListEnable ;
extern void szgw_cmdBufferMalloc(uint16_t nwkAddr,uint8_t endpointId,cJSON *cmd);
extern uint32_t szdb_getWhiteList(uint8_t *ieeeaddr);
extern int szdb_whiteListInsert(uint8_t *macAddr);
extern int szdb_whiteListDelete(uint8_t *macAddr);

*/


int	zha_get_coord_info(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	int result = UBUS_STATUS_OK;

	char ieeeaddr_string[17];
	

    printf("******************ubus  get coordinfo\n***************");

	//coord_getInfo(&coordInfo);

	blob_buf_init(&b, 0);

	snprintf(ieeeaddr_string,17,"%02x%02x%02x%02x%02x%02x%02x%02x",\
		0x01,0x02,\
		0x03,0x04,\
		0x05,0x06,\
		0x07,0x08);
	
	blobmsg_add_string(&b,"ieeeAddr",ieeeaddr_string);

	blobmsg_add_u32(&b,"channel",11);

	blobmsg_add_u32(&b,"panId",0x1234);

	blobmsg_add_u32(&b,"permitJoin",30);

	blobmsg_add_u32(&b,"whitelistEnable",1);

  	ubus_send_reply(ctx, req, b.head);
	return result;
}



int zha_get_ver(struct ubus_context *ctx, struct ubus_object *obj,
						struct ubus_request_data *req, const char *method,
						struct blob_attr *msg)
{
		blob_buf_init(&b, 0);
		blobmsg_add_string(&b,"versions","v1.1.1");		
		ubus_send_reply(ctx, req, b.head);
		return UBUS_STATUS_OK;
				
}

int get_SZ06ID(struct ubus_context *ctx, struct ubus_object *obj,
						struct ubus_request_data *req, const char *method,
						struct blob_attr *msg)
{
		blob_buf_init(&b, 0);
		sz_device_info tmp_device;
		char sql[200] = {0};
		int rc = 0;
		int inset_result = 0;
	  	char *zErrMsg = NULL;
		char **dbResult = NULL;
		unsigned char id[21];
		int nRow, nColumn;
		int index = 0;
		int i = 0;
		int j = 0;
		rc = sqlite3_get_table(db,sql, &dbResult, &nRow,&nColumn, &zErrMsg);
		if (rc == SQLITE_OK)
		{
			debug("nRow[%d]nColumn[%d]",nRow,nColumn);
			index = nColumn;
			for (i; i < nRow; i++)
			{
				unsigned char ieee[21] = {0};

				debug("i[%d] nRow[%d]",i,nRow);
				for (j = 0; j < nColumn; j++)
				{
					if((strlen("ieee") == strlen(dbResult[j])) && (memcmp("ieee",dbResult[j],strlen("ieee")) == 0))
					{
						if(strlen(dbResult[index]) > 20)
							memcpy(ieee,dbResult[index],20);
						else
							strcpy(ieee,dbResult[index]);
						blobmsg_add_string(&b,"ieee", ieee);
					}
					index++;
				}
			}
		}
//		blobmsg_add_string(&b,"ieee", &dbResult); 	
		ubus_send_reply(ctx, req, b.head);
		return UBUS_STATUS_OK;
}

int add_SZ06ID(struct ubus_context *ctx, struct ubus_object *obj,
						struct ubus_request_data *req, const char *method,
						struct blob_attr *msg)
{	
	debug("%d**",0);
	unsigned char id[21] = {0};
	sz_device_info *device;
    struct blob_attr *tb[__SZ06_MAX];

    blobmsg_parse(sz06_id, __SZ06_MAX, tb, blob_data(msg), blob_len(msg));

    if (tb[SZ06_ID])
    {
    	debug("%d++",0);
        strcpy(id, blobmsg_get_string(tb[SZ06_ID]));
//        hexStr2bytes(id, ieee_addr, 10);
		strcpy(device->id, id);
		device->did = 1;
		device->pid = 65286;
		device->ep = 1;
		device->next = NULL;
        if (sz_inset_device_tb(device))
        {
            debug("write ID failed [%s]\n", id);
            return UBUS_STATUS_OK;
        }
        debug("write ID success [%s]\n", id);
        return UBUS_STATUS_OK;
    }
    return UBUS_STATUS_INVALID_ARGUMENT;
}


/*
*
*	0:finded
*	1:could not finded
*	2:sql error
*
*/
int sz_is_device_exist(unsigned char* ieee,unsigned char endpoint)
{
	char sql[200] = {0};
	int rc = 0;
	char *zErrMsg = NULL;
	char **dbResult = NULL;
	int nRow, nColumn;
	int index;
	int i, j;
							
	sprintf(sql,"SELECT * FROM device_tb WHERE ieee='%s' AND ep='%d';",ieee,endpoint);
	debug("sql[%s]",sql);
						
	rc = sqlite3_get_table(db,sql, &dbResult, &nRow,&nColumn, &zErrMsg);
	if (rc == SQLITE_OK)
	{
		index = nColumn;
		if(nRow == 0)
		{
			err_debug("could not find device[%s:%d]",ieee,endpoint);
			sqlite3_free_table(dbResult);
			return 1;
		}
		else
		{
			//debug("device[%s:%d] finded record[%d]",ieee,endpoint,nColumn);
			sqlite3_free_table(dbResult);
			return 0;
		}
	}
	else
		{
			err_debug("SQL error: %s\n", zErrMsg);
			sqlite3_free_table(dbResult);
			sqlite3_free(zErrMsg);
			return 2;
		}
								
} 


/*
*
*	0:success
*	1:failure
*/
int sz_inset_device_tb(sz_device_info *device)
{
	debug("%d--",0);
	int rc = 0;
	char *zErrMsg = NULL;
	sz_device_info *tmp_device = device;
	unsigned char port[10] = {0};

							
	char sql[500] = {0};//"INSERT INTO device_tb(date,ieee,ep,pid,did,device_type,status,port) VALUES(date('now'),?,?,?,?,?,?,?);";
						
	if(1 != sz_is_device_exist(tmp_device->id,tmp_device->ep))
	{
			debug("device[%s] is exits",tmp_device->id);
			return 1; 
	}
	debug("%d//",0);			
//	memcpy(port,device->id + 2,2);
	sprintf(sql,"INSERT INTO device_tb(date,ieee,ep,pid,did) \
	VALUES(date('now'),'%s',%d,%d,%d);",tmp_device->id,tmp_device->ep,tmp_device->pid, \
	tmp_device->did);
	debug("sql:[%s]",sql);
	rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
	
	if (rc != SQLITE_OK)
	{
			err_debug("SQL error: %s\n", zErrMsg);
			sqlite3_free(zErrMsg);
			return 1;
	} 
	else 
	{
								
			debug("Table INSERT device_tb successfully\n");
			return 0;
	}
						
}



#if 0
int zha_coordChangeChannel(struct ubus_context *ctx, struct ubus_object *obj, 
				struct ubus_request_data *req, const char *method, 
				struct blob_attr *msg)
{
	uint8_t channel=0;
	struct blob_attr *tb[__ZHA_GATEWAY_ATTR_MAX];
	
	blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
	
	printf("***************set channel *********\n");
	if(tb[ZHA_GATEWAY_ATTR_CHANNEL])
	{
		//channel = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_CHANNEL]);
		channel = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_CHANNEL]);
		//coord_changeChannel(channel);
		
		printf("channel = %d\n",channel);
		if(channel>=0x0b && channel<=0x1A)
		{
		  // uint8_t status = emberChannelChangeRequest(channel);
          cJSON *channelChangeCmd = NULL;
		  channelChangeCmd = cJSON_CreateObject();//malloc +1
		  if(channelChangeCmd){
		      cJSON_AddIntegerToObject(channelChangeCmd, "channel",channel);
		      szgw_cmdBufferMalloc(0, 0, channelChangeCmd);		  
		      printf("ubus Changing to channel %d", channel);
			  cJSON_Delete(channelChangeCmd);//free +1
		  }
		  else{
			  printf("ubus error:channelChangeCmd = NULL\n");  
		  }
		}
	    else
		{ 
			  printf("ubus error:invaild channel[%d]\n", channel);  
		}
			
	}
	return UBUS_STATUS_OK;
}


int	zha_coordResetFactNew(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{

	cJSON *resetFactoryNewCmd = NULL;
	resetFactoryNewCmd = cJSON_CreateObject();//malloc +1
	if(resetFactoryNewCmd){
		 cJSON_AddStringToObject(resetFactoryNewCmd, "resetFactoryNew","resetFactoryNew");
		 szgw_cmdBufferMalloc(0, 0, resetFactoryNewCmd);		 
		 printf("ubus resetFactoryNew  ");
		 cJSON_Delete(resetFactoryNewCmd);//free +1
    }
	//coord_resetFactNew();
	return UBUS_STATUS_OK;
}
#endif
		
int zha_get_idlist(struct ubus_context *ctx, struct ubus_object *obj, 
				struct ubus_request_data *req, const char *method, 
				struct blob_attr *msg)
{
			uint8_t ieeeAddr[10 * 1000];
			uint32_t i, j,num_ieeeAddr;
			void *l,*e;
			char id[21];
			uint16_t index = 0;
			unsigned char ieee_id[21];
			int rc = 0;
			char sql[500] = {0};
			int inset_result = 0;
  			char *zErrMsg = NULL;
			char **dbResult = NULL;
			int nRow, nColumn;
		
			//num_ieeeAddr = device_getWhitelist(ieeeAddr);
			sprintf(sql,"SELECT ieee FROM device_tb;");
		
			blob_buf_init(&b, 0);
			l = blobmsg_open_array(&b,"idlist");
			printf("get id list\n");
//			num_ieeeAddr = szdb_getWhiteList(ieeeAddr);
			rc = sqlite3_get_table(db,sql, &dbResult, &nRow,&nColumn, &zErrMsg);

			debug("nRow[%d]nColumn[%d]",nRow,nColumn);
			index = nColumn;
			for (i = 0; i < nRow; i++)
			{
				unsigned char ieee[21] = {0};
				e = blobmsg_open_table(&b,NULL);
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
					debug("%s", ieee);
					blobmsg_add_string(&b, "id", ieee);
					blobmsg_close_table(&b,e);
					index += 1;
				}
			}

//			printf("ubus zha get idlist,num_ieeeAddr[%d]",num_ieeeAddr);
/*			for(i=0;i<num_ieeeAddr;i++)
			{
				e = blobmsg_open_table(&b,NULL);
				snprintf(id, sizeof(id), ieee_id,\
						ieeeAddr[index + 0], ieeeAddr[index + 1],\
						ieeeAddr[index + 2], ieeeAddr[index + 3],\
						ieeeAddr[index + 4], ieeeAddr[index + 5],\
						ieeeAddr[index + 6], ieeeAddr[index + 7],\
						ieeeAddr[index + 8], ieeeAddr[index + 9]);
				index += 10;
				blobmsg_add_string(&b, "id", id);
				blobmsg_close_table(&b,e);
		
			}*/
			blobmsg_close_array(&b, l);
		
			ubus_send_reply(ctx, req, b.head);

			sqlite3_free_table(dbResult);
		
			return UBUS_STATUS_OK;
}
		
int zha_write_idlist(struct ubus_context *ctx, struct ubus_object *obj, 
				struct ubus_request_data *req, const char *method, 
				struct blob_attr *msg)
{
			unsigned char ieeeaddr[10] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
			struct blob_attr *tb[__ZHA_GATEWAY_ATTR_MAX];
			struct blob_attr *pattr;
			struct blob_attr *wttb[__ZHA_GATEWAY_ATTR_MAX];
			uint16_t len;
			uint8_t i;
			sz_device_info tmp_device;
			char sql[500] = {0};
			char *zErrMsg = NULL;
			int rc, epCount, returnValue = 0;

			blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
//			cJSON * id = cJSON_CreateObject();
		
			if(tb[ZHA_GATEWAY_ATTR_WHITELIST])
			{
				len = blobmsg_len(tb[ZHA_GATEWAY_ATTR_WHITELIST]);
				__blob_for_each_attr(pattr, blobmsg_data(tb[ZHA_GATEWAY_ATTR_WHITELIST]),len  )
				{ 
		
					blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, wttb, blobmsg_data(pattr), blobmsg_len(pattr)); 
					if(wttb[ZHA_GATEWAY_ATTR_ID])
					{
                        printf("1");
						strncpy(tmp_device.id, blobmsg_get_string(wttb[ZHA_GATEWAY_ATTR_ID]), 20);
						strncpy(tmp_device.addr, blobmsg_get_string(wttb[ZHA_GATEWAY_ATTR_ID])+20, 9);
						
						register_device(tmp_device.id);
						for(epCount = 1; epCount < 17; epCount++)
						{
							collect_data device;
					    	strncpy(device.id, tmp_device.id, 21);
							strncpy(device.addr, tmp_device.addr,9);
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
							VALUES(date('now'),'%s','%s','%s',%d,%d,%d);",tmp_device.id,tmp_device.addr,tmp_device.ep, "1112451b6599000103010103020403030403",tmp_device.did,0);
						printf("sql:[%s]",sql);
						rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
						
						if (rc != SQLITE_OK)
						{
								err_debug("SQL error: %s\n", zErrMsg);
								sqlite3_free(zErrMsg);
								return 1;
						} 
						sz_recover_device_info();
						
					}
				return UBUS_STATUS_OK;
				}
			}
		return UBUS_STATUS_INVALID_ARGUMENT;
}

int zha_delete_idlist(struct ubus_context *ctx, struct ubus_object *obj, 
				struct ubus_request_data *req, const char *method, 
				struct blob_attr *msg)
{
			uint8_t ieeeaddr[8] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
			struct blob_attr *tb[__ZHA_GATEWAY_ATTR_MAX];
			struct blob_attr *pattr;
			struct blob_attr *wttb[__ZHA_GATEWAY_ATTR_MAX];
			uint16_t len;
			uint8_t i = 0;
			sz_device_info device;
			char sql[500] = {0};
			char *zErrMsg = NULL;
			int rc;
			//int ieee_count = 0;
			//unsigned char ieee[50][9];
			//unsigned char * p_ieee[50] = {NULL};
			
			blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
			if(tb[ZHA_GATEWAY_ATTR_WHITELIST])
			{
				len = blobmsg_len(tb[ZHA_GATEWAY_ATTR_WHITELIST]);
		
				__blob_for_each_attr(pattr, blobmsg_data(tb[ZHA_GATEWAY_ATTR_WHITELIST]),len  )
				{ 
					blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, wttb, blobmsg_data(pattr), blobmsg_len(pattr)); 
					if(wttb[ZHA_GATEWAY_ATTR_ID])
					{
						printf("2");
						strncpy(device.id, blobmsg_get_string(wttb[ZHA_GATEWAY_ATTR_ID]), 21);
						device.did = 1;
						device.ep = 1;
//						strcpy(device->dsp, dsp);
						sprintf(sql,"DELETE FROM device_tb WHERE ieee = '%s';",device.id);
						printf("sql:[%s]",sql);
						sz06_delete_device(device.id);
						rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
						
						if (rc != SQLITE_OK)
						{
								err_debug("SQL error: %s\n", zErrMsg);
								sqlite3_free(zErrMsg);
								return 1;
						} 
					}
				}
				return UBUS_STATUS_OK;
			}
		
		
			return UBUS_STATUS_INVALID_ARGUMENT;
}



#if 0

int zha_list(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{




	void *l;

	char *result=NULL;

	blob_buf_init(&b, 0);
	l = blobmsg_open_array(&b,"devices");
	
    result = sz_getDevicesList();
	blobmsg_add_string(&b, "list", result);
	
	if(result){
        free(result);
	}

	blobmsg_close_array(&b, l);
	ubus_send_reply(ctx, req, b.head);
	
	return UBUS_STATUS_OK;
}



#endif
	





#if 0
#include "defines.h"
#include "user_types.h"
#include "user_api.h"
#include "cloud.h"
#include "cloud_cmd.h"
#include "cloud_callback.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/crypto.h> 
#include <openssl/sha.h> 
#include <openssl/opensslv.h> 
#include "local_change.h"
#include "local_cmd.h"



struct blob_buf b;

struct ubus_context *global_ctx;
struct ubus_request_data *global_req;

const char ieee_id[] = "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX";
/*
   static struct device_info_request{
   struct ubus_request_data req;
   struct uloop_timeout timeout;
   } * device_info_req;
   */


int	zha_scan(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
//	device_scanNet();
  uint16_t clusterId = 0x0102;
         uint16_t attrId= 0x0017;
                uint8_t dataType = 0x18;
               static  uint8_t value = 0;
  uint8_t ieeeAddr[8] = {0x00,0x12,0x4b,0x00,0x0c,0xb8,0x80,0x48};
  if(value){
    value = 0;
  }else{
    value = 1;
  }
  device_writeDeviceAttr(ieeeAddr,8,clusterId,attrId,dataType,&value);

	return UBUS_STATUS_OK;
}


int	zha_cloud_report(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	device_getDevicesList();

	return UBUS_STATUS_OK;
}

int	zha_coordResetFactNew(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
  
	coord_resetFactNew();
	return UBUS_STATUS_OK;
}

int	zha_coordChangeChannel(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	uint8_t channel;
	struct blob_attr *tb[__ZHA_GATEWAY_ATTR_MAX];

	if(tb[ZHA_GATEWAY_ATTR_CHANNEL])
	{
		channel = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_CHANNEL]);
		coord_changeChannel(channel);
	}
	return UBUS_STATUS_OK;
}




int	test1(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	shuncom_test();
	return ZSUCCESS;
}


int	zha_get_coord_info(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	int result = UBUS_STATUS_OK;

	char ieeeaddr_string[17];
	coordInfo_t coordInfo;

	coord_getInfo(&coordInfo);

	blob_buf_init(&b, 0);

	snprintf(ieeeaddr_string,17,"%02x%02x%02x%02x%02x%02x%02x%02x",\
		coordInfo.ieeeAddr[0],coordInfo.ieeeAddr[1],\
		coordInfo.ieeeAddr[2],coordInfo.ieeeAddr[3],\
		coordInfo.ieeeAddr[4],coordInfo.ieeeAddr[5],\
		coordInfo.ieeeAddr[6],coordInfo.ieeeAddr[7]);

	blobmsg_add_string(&b,"ieeeAddr",ieeeaddr_string);

	blobmsg_add_u32(&b,"channel",coordInfo.channel);

	blobmsg_add_u32(&b,"panId",coordInfo.panId);

	blobmsg_add_u32(&b,"permitJoin",coordInfo.permitJoin);

	blobmsg_add_u32(&b,"whitelistEnable",coordInfo.whitelistEnable);

  	ubus_send_reply(ctx, req, b.head);

	return result;
}


int	zha_list(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{

	void *l, *e;
	uint16_t numOfDevices,i,j,temp_uint16;
	uint8_t ieeeaddr[EXT_ADDR_LEN] ;
	char ieeeaddr_string[17];
	double temp_double ;
	int16_t temp_int16;
	char temp_string[100];
  attrInfo_t *attrInfo;

  deviceInfoString_t *devices,*tmpDevice;

	numOfDevices = shuncom_getDevicesListString_fill(&devices);
	blob_buf_init(&b, 0);
	l = blobmsg_open_array(&b,"devices");

	debug(DEBUG_GENERAL,"ubus zha list,numOfDevices[%d]",numOfDevices);
  tmpDevice = devices;

  while(tmpDevice){

		snprintf(ieeeaddr_string,17,"%02x%02x%02x%02x%02x%02x%02x%02x",\
			tmpDevice->ieeeAddr[0],\
			tmpDevice->ieeeAddr[1],\
			tmpDevice->ieeeAddr[2],\
			tmpDevice->ieeeAddr[3],\
			tmpDevice->ieeeAddr[4],\
			tmpDevice->ieeeAddr[5],\
			tmpDevice->ieeeAddr[6],\
			tmpDevice->ieeeAddr[7]);
     printf("device ieeeAddr:");
     for(i=0;i<EXT_ADDR_LEN;i++){
			printf(" %02x ",tmpDevice->ieeeAddr[i]);
     }
     printf("\n");
     printf("ieeeaddr_string :%s\n",ieeeaddr_string);
      e = blobmsg_open_table(&b,NULL);
	   	blobmsg_add_string(&b,"id",ieeeaddr_string);
		  blobmsg_add_u8(&b,"ol",tmpDevice->online);
		  blobmsg_add_u32(&b,"ep",tmpDevice->endpointId);
		  blobmsg_add_u32(&b,"pid",tmpDevice->profileId);
		  blobmsg_add_u32(&b,"did",tmpDevice->deviceId);
      attrInfo = tmpDevice->attrInfo;
      while(attrInfo){
	   	  blobmsg_add_string(&b,attrInfo->attrName,attrInfo->attrValue);
        attrInfo = attrInfo->next;
      }
		  blobmsg_close_table(&b,e);
      tmpDevice = tmpDevice->next;
  }
	blobmsg_close_array(&b, l);
  shuncom_getDevicesListString_free(&devices);
	ubus_send_reply(ctx, req, b.head);

#if 0	
	deviceInfo_t * devices;
	numOfDevices = device_getDevicesList_fill(&devices);
	blob_buf_init(&b, 0);
	l = blobmsg_open_array(&b,"devices");

	debug(DEBUG_GENERAL,"ubus zha list,numOfDevices[%d]",numOfDevices);
	for(i=0;i<numOfDevices;i++)
	{
		snprintf(ieeeaddr_string,17,"%02x%02x%02x%02x%02x%02x%02x%02x",\
			devices[i].deviceBasic.ieeeAddr[0],\
			devices[i].deviceBasic.ieeeAddr[1],\
			devices[i].deviceBasic.ieeeAddr[2],\
			devices[i].deviceBasic.ieeeAddr[3],\
			devices[i].deviceBasic.ieeeAddr[4],\
			devices[i].deviceBasic.ieeeAddr[5],\
			devices[i].deviceBasic.ieeeAddr[6],\
			devices[i].deviceBasic.ieeeAddr[7]);

		e = blobmsg_open_table(&b,NULL);
		blobmsg_add_string(&b,"id",ieeeaddr_string);
		blobmsg_add_u8(&b,"ol",devices[i].deviceBasic.online);
		blobmsg_add_u32(&b,"ep",devices[i].deviceBasic.endpointId);
		blobmsg_add_u32(&b,"pid",devices[i].deviceBasic.profileId);
		blobmsg_add_u32(&b,"did",devices[i].deviceBasic.deviceId);
		if(devices[i].deviceBasic.ManufacturerName_len != 0)
			blobmsg_add_string(&b,"facid",devices[i].deviceBasic.ManufacturerName);
		if(devices[i].deviceBasic.LocationDescription_len != 0)
			blobmsg_add_string(&b,"dsp",devices[i].deviceBasic.LocationDescription);

		if(devices[i].deviceBasic.profileId == ZCL_HA_PROFILE_ID)
		{
			switch(devices[i].deviceBasic.deviceId)
			{
				case  ZCL_HA_DEVICEID_DIMMABLE_LIGHT:
				case  ZCL_HA_DEVICEID_ON_OFF_LIGHT:
				case  ZCL_HA_DEVICEID_COLORED_DIMMABLE_LIGHT:
					blobmsg_add_u8(&b,"on",devices[i].deviceState.lightState.on);
					blobmsg_add_u32(&b,"bri",devices[i].deviceState.lightState.bri);
					blobmsg_add_u32(&b,"hue",devices[i].deviceState.lightState.hue);
					blobmsg_add_u32(&b,"sat",devices[i].deviceState.lightState.sat);
					blobmsg_add_u32(&b,"ctp",devices[i].deviceState.lightState.colortemp);
					break;
				case  ZCL_HA_DEVICEID_MAINS_POWER_OUTLET:
				case  ZCL_HA_DEVICEID_REMOTE_CONTROL:
				case  ZCL_HA_DEVICEID_DOOR_LOCK:
					blobmsg_add_u8(&b,"on",devices[i].deviceState.onoffState.status);
				break;
				case  ZCL_HA_DEVICEID_ON_OFF_SWITCH:
					for(j=0;j<devices[i].deviceState.simpleSensor.sensorNum;j++)
					{
						//debug(DEBUG_ERROR,"unsupport cluster id %04x\n",devices[i].deviceState.simpleSensor.sensor[j].clusterId);
						//debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
						//debug(DEBUG_ERROR,"unsupport attr val: %02x \n",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
						switch(devices[i].deviceState.simpleSensor.sensor[j].clusterId)
						{
			              	case ZCL_CLUSTER_ID_GEN_ON_OFF:
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case 0x0000:
										blobmsg_add_u8(&b,"on",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
										break;
									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
			                break;
							case 0xfe05:
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case 0X0000:
										blobmsg_add_u32(&b,"val",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
									break;
									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
								break;
							default:
								debug(DEBUG_ERROR,"unsupport cluster id %04x\n",devices[i].deviceState.simpleSensor.sensor[j].clusterId);
								break;
						}

					}
					break;
				case  ZCL_HA_DEVICEID_SMART_PLUG:
					for(j=0;j<devices[i].deviceState.simpleSensor.sensorNum;j++)
					{
						switch(devices[i].deviceState.simpleSensor.sensor[j].clusterId)
						{
			              	case ZCL_CLUSTER_ID_GEN_ON_OFF:
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case 0x8000:
										blobmsg_add_u8(&b,"childlock",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
									break;
									case 0x0000:
										blobmsg_add_u8(&b,"on",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
										break;
									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
			                break;
							case ZCL_CLUSTER_ID_SE_SIMPLE_METERING:
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case 0X0000:
										;
										char buf[6] = {0};
										memcpy(buf,devices[i].deviceState.simpleSensor.sensor[j].data,6);
										uint64_t tempp = (uint64_t)((((uint64_t)buf[5] & 0x00000000000000ff) << 40) + \
											(((uint64_t)buf[4] & 0x00000000000000ff) << 32) + \
											(((uint64_t)buf[3] & 0x00000000000000ff) << 24) + \
											(((uint64_t)buf[2] & 0x00000000000000ff) << 16) + \
											(((uint64_t)buf[1] & 0x00000000000000ff) << 8) + \
											(((uint64_t)buf[0] & 0x00000000000000ff) << 0));
										debug(DEBUG_ERROR,"energy is [%lld]",tempp);
										sprintf(temp_string,"%lld",tempp);
										blobmsg_add_string(&b,"energy",temp_string);
									break;
									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
								break;
							case ZCL_CLUSTER_ID_HA_ELECTRICAL_MEASUREMENT  :
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case ATTRID_ELECTRICAL_MEASUREMENT_RMS_VOLTAGE:
										;
										uint16_t temp1 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
										debug(DEBUG_ERROR,"volt is [%d]",temp1);
										blobmsg_add_u32(&b,"volt",temp1);
									break;
									case ATTRID_ELECTRICAL_MEASUREMENT_RMS_CURRENT:
										;
										uint16_t temp2 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
										debug(DEBUG_ERROR,"curr is [%d]",temp2);
										blobmsg_add_u32(&b,"curr",temp2);
										break;
									case ATTRID_ELECTRICAL_MEASUREMENT_ACTIVE_POWER:
										;
										uint16_t temp3 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
										debug(DEBUG_ERROR,"actp is [%d]",temp3);
										blobmsg_add_u32(&b,"actp",temp3);
									break;
									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
								break;
							default:
								debug(DEBUG_ERROR,"unsupport cluster id %04x\n",devices[i].deviceState.simpleSensor.sensor[j].clusterId);
								break;
						}

					}
					break;
				case ZCL_HA_DEVICEID_WHITE_GOODS:
				case ZCL_HA_DEVICEID_SIMPLE_SENSOR :
				case ZCL_HA_DEVICEID_LIGHT_SENSOR:
				case ZCL_HA_DEVICEID_TEMPERATURE_SENSOR:
				case ZCL_HA_DEVICEID_PUMP:
				case ZCL_HA_DEVICEID_HEATING_COOLING_UNIT:
				case ZCL_HA_DEVICEID_THERMOSTAT:
					for(j=0;j<devices[i].deviceState.simpleSensor.sensorNum;j++)
					{
						//SCprintf("sensor enter\n");
						//SCprintf("sensor %d :\n",j);
						switch(devices[i].deviceState.simpleSensor.sensor[j].clusterId)
						{
			              	case ZCL_CLUSTER_ID_GEN_ON_OFF:
								 blobmsg_add_u8(&b,"on",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
			                break;
							case ZCL_CLUSTER_ID_MS_TEMPERATURE_MEASUREMENT:
								temp_int16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								debug(DEBUG_GENERAL,"temperature is %04x %d\n",temp_int16,temp_int16);
								sprintf(temp_string,"%d.%d",temp_int16/100,temp_int16%100);
								blobmsg_add_string(&b,"temp",temp_string);
								break;
							case ZCL_CLUSTER_ID_MS_RELATIVE_HUMIDITY:
								temp_int16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								//SCprintf("humidity is %04x\n",temp_int16);
								temp_int16 = temp_int16/100;
								sprintf(temp_string,"%d",temp_int16);
								blobmsg_add_string(&b,"humi",temp_string);
								break;
							case ZCL_CLUSTER_ID_MS_ILLUMINANCE_LEVEL_SENSING_CONFIG  :
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case ATTRID_MS_ILLUMINANCE_LEVEL_STATUS:
										if(devices[i].deviceState.simpleSensor.sensor[j].dataType == ZCL_DATATYPE_ENUM8)
										{
											//SCprintf("level status : %02x\n",*(uint8_t *)(devices[i].deviceState.simpleSensor.sensor[j].data));
											blobmsg_add_u32(&b,"llux",*(uint8_t *)(devices[i].deviceState.simpleSensor.sensor[j].data));
										}
										break;
									case ATTRID_MS_ILLUMINANCE_TARGET_LEVEL:
										if(devices[i].deviceState.simpleSensor.sensor[j].dataType == ZCL_DATATYPE_UINT16)
										{
											temp_uint16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
											//SCprintf("target temp uint16 : %04x\n",temp_uint16);
											temp_double = temp_uint16;
											temp_double = (temp_double/10000);
											temp_double = pow(10.0,temp_double);
											//SCprintf("target lux value : %f \n",temp_double);
											sprintf(temp_string,"%f",temp_double);
											//SCprintf("target lux string: %s \n",temp_string);
											blobmsg_add_string(&b,"tlux",temp_string);
										}
										break;

									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
								break;
							case ZCL_CLUSTER_ID_MS_ILLUMINANCE_MEASUREMENT:
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case ATTRID_MS_ILLUMINANCE_MEASURED_VALUE:
										if(devices[i].deviceState.simpleSensor.sensor[j].dataType == ZCL_DATATYPE_UINT16)
										{
											temp_uint16 = BUILD_UINT16( devices[i].deviceState.simpleSensor.sensor[j].data[1] , devices[i].deviceState.simpleSensor.sensor[j].data[0] );
											debug(DEBUG_GENERAL,"now temp uint16 : %04x\n",temp_uint16);
											temp_double = temp_uint16;
											temp_double = (temp_double/10000);
											temp_double = pow(10.0,temp_double);
											debug(DEBUG_GENERAL,"now lux value : %f \n",temp_double);
											sprintf(temp_string,"%f",temp_double);
											debug(DEBUG_GENERAL,"now lux string: %s \n",temp_string);

											blobmsg_add_string(&b,"nlux",temp_string);
										}
										break;
								default:
										break;
								}
								break;
							case ZCL_CLUSTER_ID_GEN_ANALOG_INPUT_BASIC:
								temp_uint16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								debug(DEBUG_GENERAL,"temp uint16 : %04x\n",temp_uint16 );
								if(devices[i].deviceBasic.endpointId == 9)
								{
									debug(DEBUG_GENERAL,"pm2.5 :%04x \n",temp_uint16 );
									blobmsg_add_u32(&b,"pm25",temp_uint16);
								}
								else if(devices[i].deviceBasic.endpointId == 10)
								{
									debug(DEBUG_GENERAL,"voc: %04x \n",temp_uint16 );
									blobmsg_add_u32(&b,"voc",temp_uint16);
								}
								break;
							case ZCL_CLUSTER_ID_HVAC_FAN_CONTROL:
				                switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
					                case 0x0000:
			  							debug(DEBUG_GENERAL,"fanMode :%02x \n",devices[i].deviceState.simpleSensor.sensor[j].data[0] );
				  						blobmsg_add_u32(&b,"fanMode",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
				                    break;
									case 0x8000:
										;
										unsigned char temp = devices[i].deviceState.simpleSensor.sensor[j].data[0];
										debug(DEBUG_GENERAL,"powermode :%04x \n",temp );
										blobmsg_add_u32(&b,"powermode",temp);
		                				break;
					                default:
					                    break;
				                }
                				break;
							case ZCL_CLUSTER_ID_HVAC_THERMOSTAT:
				                switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
				                   case 0x00:
								    temp_int16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
									temp_int16 = temp_int16/100;
								    sprintf(temp_string,"%d",temp_int16);
								    blobmsg_add_string(&b,"tgtemp",temp_string);
					                break;
					                default:
				                    break;
				                }
				                break;
							case 0xFE02:
								temp_uint16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								debug(DEBUG_GENERAL,"pm2.5 :%04x \n",temp_uint16 );
								blobmsg_add_u32(&b,"pm25",temp_uint16);
				            	break;
							case 0xFE03:
								temp_uint16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								debug(DEBUG_GENERAL,"CO2 :%04x \n",temp_uint16 );
								blobmsg_add_u32(&b,"CO2",temp_uint16);
               	 				break;
							case 0xFE04:
								temp_uint16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								debug(DEBUG_GENERAL,"formaldehyde :%04x \n",temp_uint16 );
								blobmsg_add_u32(&b,"formaldehyde",temp_uint16);
                				break;
							
							default:
								debug(DEBUG_ERROR,"unsupport cluster id %04x\n",devices[i].deviceState.simpleSensor.sensor[j].clusterId);
								break;
						}

					}
					break;
				case ZCL_HA_DEVICEID_IAS_ZONE :
					blobmsg_add_u32(&b,"zid",devices[i].deviceState.zoneState.zoneId);
					blobmsg_add_u32(&b,"type",devices[i].deviceState.zoneState.zoneType);
					blobmsg_add_u32(&b,"sta",devices[i].deviceState.zoneState.status);
					break;
				case ZCL_HA_DEVICEID_WINDOW_COVERING_DEVICE:
					blobmsg_add_u32(&b,"pt",devices[i].deviceState.percentage.percentage);
					break;
				default:
				{
					debug(DEBUG_ERROR,"unsupport device\n");
					//blobmsg_add_string(&b,"id","unsupprot device");
					break;
				}
			}
		}
		else if(devices[i].deviceBasic.profileId == ZLL_PROFILE_ID)
		{
			switch(devices[i].deviceBasic.deviceId)
			{
				case  ZLL_DEVICEID_COLOR_LIGHT:
				case  ZLL_DEVICEID_EXTENDED_COLOR_LIGHT:
				case  ZLL_DEVICEID_DIMMABLE_LIGHT:
				case  ZLL_DEVICEID_COLOR_TEMPERATURE_LIGHT:
					blobmsg_add_u8(&b,"on",devices[i].deviceState.lightState.on);
					blobmsg_add_u32(&b,"bri",devices[i].deviceState.lightState.bri);
					blobmsg_add_u32(&b,"hue",devices[i].deviceState.lightState.hue);
					blobmsg_add_u32(&b,"sat",devices[i].deviceState.lightState.sat);
					blobmsg_add_u32(&b,"ctp",devices[i].deviceState.lightState.colortemp);
					break;
				default:
				{
					debug(DEBUG_ERROR,"unsupport device");
					//blobmsg_add_string(&b,"id","unsupprot device");
					break;
				}
			}
		}
		else if(devices[i].deviceBasic.profileId == ZCL_SHUNCOM_PROFILE_ID)
		{
			char rawData[MAX_DATA_LEN];
			debug(DEBUG_GENERAL,"devices[i].deviceState.rawData.dataLen : %d\n",devices[i].deviceState.rawData.dataLen);
			if(devices[i].deviceState.rawData.dataLen != 0)
			{
				bytes2hexStr(devices[i].deviceState.rawData.data,rawData,devices[i].deviceState.rawData.dataLen);
				blobmsg_add_string(&b,"rwd",rawData);
			}
		}
		else
		{
			debug(DEBUG_ERROR,"unknow device profileID[%d]",devices[i].deviceBasic.profileId);
		}
		blobmsg_close_table(&b,e);
	}
	free(devices);
	blobmsg_close_array(&b, l);
	ubus_send_reply(ctx, req, b.head);
#endif
	return UBUS_STATUS_OK;
}

int	zha_getAttr(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	struct blob_attr *tb[__ZHA_GATEWAY_ATTR_MAX];
  uint16_t nwkAddr,clusterId,attrId;
  nwkAddr = 0;
  clusterId = 0;
  attrId = 0;

	blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if(tb[ZHA_GATEWAY_ATTR_NWKADDR])
	{
		 nwkAddr = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_NWKADDR]);
     printf("nwkAddr :%04x\n",nwkAddr);
	}

	if(tb[ZHA_GATEWAY_ATTR_CLUSTERID])
	{
		 clusterId = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_CLUSTERID]);
     printf("[%s]clusterId :%04x\n",__FUNCTION__,clusterId);
	}

	if(tb[ZHA_GATEWAY_ATTR_ATTRID])
	{
    attrId =  blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_ATTRID]);
     printf("[%s]attrId :%04x\n",__FUNCTION__,attrId);
	}

      shuncom_test1(nwkAddr,clusterId,attrId);

	return UBUS_STATUS_OK;
}


int	zha_set(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	struct blob_attr *tb[__ZHA_GATEWAY_ATTR_MAX];
	int index = 0;
	struct timeb tp;
	int i;
  	uint8_t ieeeAddr[EXT_ADDR_LEN];
  	uint8_t endpointId;
	deviceState_t  deviceState;

	blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
	ftime(&tp);

	if( (!tb[ZHA_GATEWAY_ATTR_ID]) || (!tb[ZHA_GATEWAY_ATTR_ENDPOINT_ID]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	hexStr2bytes(blobmsg_get_string(tb[ZHA_GATEWAY_ATTR_ID]),ieeeAddr,EXT_ADDR_LEN );
  	endpointId =  blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_ENDPOINT_ID]);

	if(tb[ZHA_GATEWAY_ATTR_ON])
	{
		deviceState.onoffState.status = blobmsg_get_u8(tb[ZHA_GATEWAY_ATTR_ON]);
        device_setDeviceAttr(ieeeAddr,endpointId,"on",&deviceState.onoffState.status);
	}

	if(tb[ZHA_GATEWAY_ATTR_BRI])
	{
		deviceState.lightState.bri = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_BRI]);
        device_setDeviceAttr(ieeeAddr,endpointId,"bri",&deviceState.lightState.bri);
	}
	if(tb[ZHA_GATEWAY_ATTR_HUE])
	{
		deviceState.lightState.hue = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_HUE]);
        device_setDeviceAttr(ieeeAddr,endpointId,"hue",&deviceState.lightState.hue);
	}

	if(tb[ZHA_GATEWAY_ATTR_SAT])
	{
		deviceState.lightState.sat = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_SAT]);
        device_setDeviceAttr(ieeeAddr,endpointId,"sat",&deviceState.lightState.sat);
	}

	if(tb[ZHA_GATEWAY_ATTR_COLORTEMP])
	{
		deviceState.lightState.colortemp = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_COLORTEMP]);
        device_setDeviceAttr(ieeeAddr,endpointId,"colortemp",&deviceState.lightState.colortemp);
	}


	if(tb[ZHA_GATEWAY_ATTR_NAME]) 
	{
	}

	if(tb[ZHA_GATEWAY_ATTR_RAWDATA])
	{
		deviceState.rawData.dataLen = (strlen(blobmsg_get_string(tb[ZHA_GATEWAY_ATTR_RAWDATA]))/2);
		hexStr2bytes(blobmsg_get_string(tb[ZHA_GATEWAY_ATTR_RAWDATA]),deviceState.rawData.data,deviceState.rawData.dataLen);
		debug(DEBUG_ERROR,"rawdata[");
		for(i=0;i<deviceState.rawData.dataLen;i++)
		{
		  printf("%02x",deviceState.rawData.data[i]);
		}
		printf("]\n");
		device_setDeviceAttr(ieeeAddr,endpointId,"rawdata",&deviceState);
	}

	if(tb[ZHA_GATEWAY_ATTR_INFAREDCODE])
	{
		deviceState.rawData.dataLen = (strlen(blobmsg_get_string(tb[ZHA_GATEWAY_ATTR_INFAREDCODE]))/2);
		hexStr2bytes(blobmsg_get_string(tb[ZHA_GATEWAY_ATTR_INFAREDCODE]),deviceState.rawData.data,deviceState.rawData.dataLen);
		device_setDeviceAttr(ieeeAddr,endpointId,"infraredcode",&deviceState);
	}

	if(tb[ZHA_GATEWAY_ATTR_INFAREDLEARN])
	{
		if((blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_INFAREDLEARN]) >= 0) && (blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_INFAREDLEARN]) < 30))
		{
			deviceState.rawData.data[0] = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_INFAREDLEARN]);
			device_setDeviceAttr(ieeeAddr,endpointId,"infraredlearn",&(deviceState.rawData.data[0]));
		}
	}

	if (tb[ZHA_GATEWAY_ATTR_INFAREDCONTROL])
	{
		if((blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_INFAREDCONTROL]) >= 0)&&(blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_INFAREDCONTROL]) < 30))
		{
			deviceState.rawData.data[0] = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_INFAREDCONTROL]);
			device_setDeviceAttr(ieeeAddr,endpointId,"infraredcontrol",&(deviceState.rawData.data[0]));
		}
	}


	if (tb[ZHA_GATEWAY_ATTR_CTRL])
	{
		if(blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_CTRL]) == 0)
			device_setDeviceAttr(ieeeAddr,endpointId,"downclose",NULL);
		else if(blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_CTRL]) == 1)
			device_setDeviceAttr(ieeeAddr,endpointId,"upopen",NULL);
		else if(blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_CTRL]) == 2)
			device_setDeviceAttr(ieeeAddr,endpointId,"stop",NULL);
	}

	if(tb[ZHA_GATEWAY_ATTR_PERCENTAGE])
	{
		deviceState.percentage.percentage = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_PERCENTAGE]);
		device_setDeviceAttr(ieeeAddr,endpointId,"liftpercentage",&(deviceState.percentage.percentage));
	}

	if (tb[ZHA_GATEWAY_ATTR_FAN])
	{
		uint8_t tmpUint8 = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_FAN]);
		device_setDeviceAttr(ieeeAddr,endpointId,"fan",&tmpUint8);
	}
	

	if(tb[ZHA_HVAC_THERMOSTAT_MODE] && tb[ZHA_HVAC_THERMOSTAT_VALUE])
	{
		unsigned char value[2] = {0,0};
		value[0] = blobmsg_get_u32(tb[ZHA_HVAC_THERMOSTAT_MODE]);
		value[1] = (unsigned char)blobmsg_get_u32(tb[ZHA_HVAC_THERMOSTAT_VALUE]);
		device_setDeviceAttr(ieeeAddr,endpointId,"pointraiselower",value);
	}

	if (tb[ZHA_HVAC_TARGET_TEMP])
	{
		short tmpUint8 = (short)blobmsg_get_u32(tb[ZHA_HVAC_TARGET_TEMP]);
		if(ZSUCCESS != device_setDeviceAttr(ieeeAddr,endpointId,"temperature",&tmpUint8))
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (tb[ZHA_HVAC_POWER_MODE])
	{
		unsigned char tmpUint8 = (short)blobmsg_get_u32(tb[ZHA_HVAC_POWER_MODE]);
		debug(DEBUG_ERROR,"powermode[%d]",tmpUint8);
		if(ZSUCCESS != device_setDeviceAttr(ieeeAddr,endpointId,"powermode",&tmpUint8))
			return UBUS_STATUS_INVALID_ARGUMENT;
	}
	

	if(tb[ZHA_GATEWAY_ATTR_CHILD_LOCK])
	{
		unsigned char tmpUint8 = blobmsg_get_u8(tb[ZHA_GATEWAY_ATTR_CHILD_LOCK]);
		device_writeDeviceAttr(ieeeAddr,endpointId,ZCL_CLUSTER_ID_GEN_ON_OFF,0x8000,ZCL_DATATYPE_BOOLEAN,&tmpUint8);
	}

	if(tb[ZHA_GATEWAY_ATTR_WORK_MODE])
	{
		unsigned char tmpUint8 = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_WORK_MODE]);
		device_writeDeviceAttr(ieeeAddr,endpointId,ZCL_CLUSTER_ID_HVAC_THERMOSTAT,0x001c,ZCL_DATATYPE_ENUM8,&tmpUint8);
	}
	
	ftime(&tp);

	return UBUS_STATUS_OK;
}

int	zha_get_node_info(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	void *l, *e;
	uint16_t numOfDevices,i,j,temp_uint16;
	uint8_t ieeeaddr[EXT_ADDR_LEN] ;
	char ieeeaddr_string[17];
	double temp_double ;
	int16_t temp_int16;
	char temp_string[100];
	struct blob_attr *tb[__ZHA_GATEWAY_ATTR_MAX];
	deviceInfo_t * devices = NULL;

	blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if(!tb[ZHA_GATEWAY_ATTR_ID])
	{
		debug(DEBUG_ERROR,"don't get id");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	hexStr2bytes(blobmsg_get_string(tb[ZHA_GATEWAY_ATTR_ID]),ieeeaddr,EXT_ADDR_LEN );

	numOfDevices = device_getDevice(ieeeaddr,&devices);

	if(numOfDevices <= 0)
	{
		debug(DEBUG_ERROR,"numOfDevices error\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if(devices == NULL)
	{
		debug(DEBUG_ERROR,"devices is NULL\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	
	blob_buf_init(&b, 0);
	l = blobmsg_open_array(&b,"devices");
	for(i=0;i<numOfDevices;i++)
	{
		snprintf(ieeeaddr_string,17,"%02x%02x%02x%02x%02x%02x%02x%02x",\
			devices[i].deviceBasic.ieeeAddr[0],\
			devices[i].deviceBasic.ieeeAddr[1],\
			devices[i].deviceBasic.ieeeAddr[2],\
			devices[i].deviceBasic.ieeeAddr[3],\
			devices[i].deviceBasic.ieeeAddr[4],\
			devices[i].deviceBasic.ieeeAddr[5],\
			devices[i].deviceBasic.ieeeAddr[6],\
			devices[i].deviceBasic.ieeeAddr[7]);
		e = blobmsg_open_table(&b,NULL);
		blobmsg_add_string(&b,"id",ieeeaddr_string);
		blobmsg_add_u8(&b,"ol",devices[i].deviceBasic.online);
		blobmsg_add_u32(&b,"ep",devices[i].deviceBasic.endpointId);
		blobmsg_add_u32(&b,"pid",devices[i].deviceBasic.profileId);
		blobmsg_add_u32(&b,"did",devices[i].deviceBasic.deviceId);
		if(devices[i].deviceBasic.ManufacturerName_len != 0)
			blobmsg_add_string(&b,"facid",devices[i].deviceBasic.ManufacturerName);
		if(devices[i].deviceBasic.LocationDescription_len != 0)
			blobmsg_add_string(&b,"dsp",devices[i].deviceBasic.LocationDescription);

		if(devices[i].deviceBasic.profileId == ZCL_HA_PROFILE_ID)
		{
			switch(devices[i].deviceBasic.deviceId)
			{
				case  ZCL_HA_DEVICEID_DIMMABLE_LIGHT:
				case  ZCL_HA_DEVICEID_ON_OFF_LIGHT:
				case  ZCL_HA_DEVICEID_COLORED_DIMMABLE_LIGHT:
					blobmsg_add_u8(&b,"on",devices[i].deviceState.lightState.on);
					blobmsg_add_u32(&b,"bri",devices[i].deviceState.lightState.bri);
					blobmsg_add_u32(&b,"hue",devices[i].deviceState.lightState.hue);
					blobmsg_add_u32(&b,"sat",devices[i].deviceState.lightState.sat);
					blobmsg_add_u32(&b,"ctp",devices[i].deviceState.lightState.colortemp);
					break;
				case  ZCL_HA_DEVICEID_MAINS_POWER_OUTLET:
				case  ZCL_HA_DEVICEID_REMOTE_CONTROL:
				case  ZCL_HA_DEVICEID_DOOR_LOCK:
					blobmsg_add_u8(&b,"on",devices[i].deviceState.onoffState.status);
					break;
				case  ZCL_HA_DEVICEID_ON_OFF_SWITCH:
					for(j=0;j<devices[i].deviceState.simpleSensor.sensorNum;j++)
					{
						debug(DEBUG_ERROR,"unsupport cluster id %04x\n",devices[i].deviceState.simpleSensor.sensor[j].clusterId);
						debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
						debug(DEBUG_ERROR,"unsupport attr val: %02x \n",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
						switch(devices[i].deviceState.simpleSensor.sensor[j].clusterId)
						{
			              	case ZCL_CLUSTER_ID_GEN_ON_OFF:
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case 0x0000:
										blobmsg_add_u8(&b,"on",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
										break;
									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
			                break;
							case 0xfe05:
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case 0X0000:
										blobmsg_add_u32(&b,"val",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
									break;
									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
								break;
							default:
								debug(DEBUG_ERROR,"unsupport cluster id %04x\n",devices[i].deviceState.simpleSensor.sensor[j].clusterId);
								break;
						}

					}
					break;
				case  ZCL_HA_DEVICEID_SMART_PLUG:
					for(j=0;j<devices[i].deviceState.simpleSensor.sensorNum;j++)
					{
						switch(devices[i].deviceState.simpleSensor.sensor[j].clusterId)
						{
			              	case ZCL_CLUSTER_ID_GEN_ON_OFF:
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case 0x8000:
										blobmsg_add_u8(&b,"childlock",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
									break;
									case 0x0000:
										blobmsg_add_u8(&b,"on",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
										break;
									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
			                break;
							case ZCL_CLUSTER_ID_SE_SIMPLE_METERING:
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case 0X0000:
										;
										char buf[6] = {0};
										memcpy(buf,devices[i].deviceState.simpleSensor.sensor[j].data,6);
										uint64_t tempp = (uint64_t)((((uint64_t)buf[5] & 0x00000000000000ff) << 40) + \
											(((uint64_t)buf[4] & 0x00000000000000ff) << 32) + \
											(((uint64_t)buf[3] & 0x00000000000000ff) << 24) + \
											(((uint64_t)buf[2] & 0x00000000000000ff) << 16) + \
											(((uint64_t)buf[1] & 0x00000000000000ff) << 8) + \
											(((uint64_t)buf[0] & 0x00000000000000ff) << 0));
										debug(DEBUG_ERROR,"energy is [%lld]",tempp);
										sprintf(temp_string,"%lld",tempp);
										blobmsg_add_string(&b,"energy",temp_string);
									break;
									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
								break;
							case ZCL_CLUSTER_ID_HA_ELECTRICAL_MEASUREMENT  :
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case ATTRID_ELECTRICAL_MEASUREMENT_RMS_VOLTAGE:
										;
										uint16_t temp1 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
										debug(DEBUG_ERROR,"volt is [%d]",temp1);
										blobmsg_add_u32(&b,"volt",temp1);
									break;
									case ATTRID_ELECTRICAL_MEASUREMENT_RMS_CURRENT:
										;
										uint16_t temp2 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
										debug(DEBUG_ERROR,"curr is [%d]",temp2);
										blobmsg_add_u32(&b,"curr",temp2);
										break;
									case ATTRID_ELECTRICAL_MEASUREMENT_ACTIVE_POWER:
										;
										uint16_t temp3 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
										debug(DEBUG_ERROR,"actp is [%d]",temp3);
										blobmsg_add_u32(&b,"actp",temp3);
									break;
									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
								break;
							default:
								debug(DEBUG_ERROR,"unsupport cluster id %04x\n",devices[i].deviceState.simpleSensor.sensor[j].clusterId);
								break;
						}

					}
					break;
				case ZCL_HA_DEVICEID_WHITE_GOODS:
				case ZCL_HA_DEVICEID_SIMPLE_SENSOR :
				case ZCL_HA_DEVICEID_LIGHT_SENSOR:
				case ZCL_HA_DEVICEID_TEMPERATURE_SENSOR:
				case ZCL_HA_DEVICEID_PUMP:
				case ZCL_HA_DEVICEID_HEATING_COOLING_UNIT:
				case ZCL_HA_DEVICEID_THERMOSTAT:
					for(j=0;j<devices[i].deviceState.simpleSensor.sensorNum;j++)
					{
						//SCprintf("sensor enter\n");
						//SCprintf("sensor %d :\n",j);
						switch(devices[i].deviceState.simpleSensor.sensor[j].clusterId)
						{
							case ZCL_CLUSTER_ID_GEN_ON_OFF:
								 blobmsg_add_u8(&b,"on",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
			                break;
							case ZCL_CLUSTER_ID_MS_TEMPERATURE_MEASUREMENT:
								temp_int16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								//SCprintf("temperature is %04x\n",temp_int16);
								sprintf(temp_string,"%d.%d",temp_int16/100,temp_int16%100);
								blobmsg_add_string(&b,"temp",temp_string);
								break;
							case ZCL_CLUSTER_ID_MS_RELATIVE_HUMIDITY:
								temp_int16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								//SCprintf("humidity is %04x\n",temp_int16);
								temp_int16 = temp_int16/100;
								sprintf(temp_string,"%d",temp_int16);
								blobmsg_add_string(&b,"humi",temp_string);
								break;
							case ZCL_CLUSTER_ID_MS_ILLUMINANCE_LEVEL_SENSING_CONFIG  :
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case ATTRID_MS_ILLUMINANCE_LEVEL_STATUS:
										if(devices[i].deviceState.simpleSensor.sensor[j].dataType == ZCL_DATATYPE_ENUM8)
										{
											//SCprintf("level status : %02x\n",*(uint8_t *)(devices[i].deviceState.simpleSensor.sensor[j].data));
											blobmsg_add_u32(&b,"llux",*(uint8_t *)(devices[i].deviceState.simpleSensor.sensor[j].data));
										}
										break;
									case ATTRID_MS_ILLUMINANCE_TARGET_LEVEL:
										if(devices[i].deviceState.simpleSensor.sensor[j].dataType == ZCL_DATATYPE_UINT16)
										{
											temp_uint16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
											//SCprintf("target temp uint16 : %04x\n",temp_uint16);
											temp_double = temp_uint16;
											temp_double = (temp_double/10000);
											temp_double = pow(10.0,temp_double);
											//SCprintf("target lux value : %f \n",temp_double);
											sprintf(temp_string,"%f",temp_double);
											//SCprintf("target lux string: %s \n",temp_string);
											blobmsg_add_string(&b,"tlux",temp_string);
										}
										break;

									default:
										debug(DEBUG_ERROR,"unsupport attrid: %04x \n",devices[i].deviceState.simpleSensor.sensor[j].attrId);
										break;
								}
								break;
							case ZCL_CLUSTER_ID_MS_ILLUMINANCE_MEASUREMENT:
								switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
									case ATTRID_MS_ILLUMINANCE_MEASURED_VALUE:
										if(devices[i].deviceState.simpleSensor.sensor[j].dataType == ZCL_DATATYPE_UINT16)
										{
											temp_uint16 = BUILD_UINT16( devices[i].deviceState.simpleSensor.sensor[j].data[1] , devices[i].deviceState.simpleSensor.sensor[j].data[0] );
											//SCprintf("now temp uint16 : %04x\n",temp_uint16);
											temp_double = temp_uint16;
											temp_double = (temp_double/10000);
											temp_double = pow(10.0,temp_double);
											//SCprintf("now lux value : %f \n",temp_double);
											sprintf(temp_string,"%f",temp_double);
											//SCprintf("now lux string: %s \n",temp_string);

											blobmsg_add_string(&b,"nlux",temp_string);
										}
										break;
								default:
										break;
								}
								break;
							case ZCL_CLUSTER_ID_GEN_ANALOG_INPUT_BASIC:
								temp_uint16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								//SCprintf("temp uint16 : %04x\n",temp_uint16 );
								if(devices[i].deviceBasic.endpointId == 9)
								{
									//SCprintf("pm2.5 :%04x \n",temp_uint16 );
									blobmsg_add_u32(&b,"pm25",temp_uint16);
								}
								else if(devices[i].deviceBasic.endpointId == 10)
								{
									//SCprintf("voc: %04x \n",temp_uint16 );
									blobmsg_add_u32(&b,"voc",temp_uint16);
								}
								break;
							case ZCL_CLUSTER_ID_HVAC_FAN_CONTROL:
				                switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
					                case 0x00:
			  							debug(DEBUG_GENERAL,"fanMode :%02x \n",devices[i].deviceState.simpleSensor.sensor[j].data[0] );
				  						blobmsg_add_u32(&b,"fanMode",devices[i].deviceState.simpleSensor.sensor[j].data[0]);
				                    break;
					                default:
					                    break;
				                }
                				break;
							case ZCL_CLUSTER_ID_HVAC_THERMOSTAT:
				                switch(devices[i].deviceState.simpleSensor.sensor[j].attrId)
								{
				                   case 0x0000:
									    temp_int16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
										temp_int16 = temp_int16/100;
									    sprintf(temp_string,"%d",temp_int16);
									    blobmsg_add_string(&b,"tgtemp",temp_string);
					                break;
									case 0x8000:
										;
										unsigned char temp = devices[i].deviceState.simpleSensor.sensor[j].data[0];
										debug(DEBUG_GENERAL,"powermode :%04x \n",temp );
										blobmsg_add_u32(&b,"powermode",temp);
		                				break;
									default:
				                    	break;
				                }
				                break;
							case 0xFE02:
								temp_uint16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								debug(DEBUG_GENERAL,"pm2.5 :%04x \n",temp_uint16 );
								blobmsg_add_u32(&b,"pm25",temp_uint16);
				            	break;
							case 0xFE03:
								temp_uint16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								debug(DEBUG_GENERAL,"CO2 :%04x \n",temp_uint16 );
								blobmsg_add_u32(&b,"CO2",temp_uint16);
               	 				break;
							case 0xFE04:
								temp_uint16 = BUILD_UINT16(devices[i].deviceState.simpleSensor.sensor[j].data[1] ,devices[i].deviceState.simpleSensor.sensor[j].data[0] );
								debug(DEBUG_GENERAL,"formaldehyde :%04x \n",temp_uint16 );
								blobmsg_add_u32(&b,"formaldehyde",temp_uint16);
                				break;
							
								debug(DEBUG_ERROR,"unsupport cluster id %04x\n",devices[i].deviceState.simpleSensor.sensor[j].clusterId);
								break;
						}

						//SCprintf("i : %d j: %d\n",i,j);
					}
					break;
				case ZCL_HA_DEVICEID_IAS_ZONE :
					blobmsg_add_u32(&b,"zid",devices[i].deviceState.zoneState.zoneId);
					blobmsg_add_u32(&b,"type",devices[i].deviceState.zoneState.zoneType);
					blobmsg_add_u32(&b,"sta",devices[i].deviceState.zoneState.status);
					break;
				case ZCL_HA_DEVICEID_WINDOW_COVERING_DEVICE:
					blobmsg_add_u32(&b,"pt",devices[i].deviceState.percentage.percentage);
					break;
				default:
				{
					debug(DEBUG_ERROR,"unsupport device\n");
					//blobmsg_add_string(&b,"id","unsupprot device");
					break;
				}
			}
		}
		else if(devices[i].deviceBasic.profileId == ZLL_PROFILE_ID)
		{
			switch(devices[i].deviceBasic.deviceId)
			{
				case  ZLL_DEVICEID_COLOR_LIGHT:
				case  ZLL_DEVICEID_EXTENDED_COLOR_LIGHT:
				case  ZLL_DEVICEID_DIMMABLE_LIGHT:
				case  ZLL_DEVICEID_COLOR_TEMPERATURE_LIGHT:
					blobmsg_add_u8(&b,"on",devices[i].deviceState.lightState.on);
					blobmsg_add_u32(&b,"bri",devices[i].deviceState.lightState.bri);
					blobmsg_add_u32(&b,"hue",devices[i].deviceState.lightState.hue);
					blobmsg_add_u32(&b,"sat",devices[i].deviceState.lightState.sat);
					blobmsg_add_u32(&b,"ctp",devices[i].deviceState.lightState.colortemp);
					break;
				default:
				{
					debug(DEBUG_ERROR,"unsupport device");
					//blobmsg_add_string(&b,"id","unsupprot device");
					break;
				}
			}
		}
		else if(devices[i].deviceBasic.profileId == ZCL_SHUNCOM_PROFILE_ID)
		{
			char rawData[MAX_DATA_LEN];
			//SCprintf("devices[i].deviceState.rawData.dataLen : %d\n",devices[i].deviceState.rawData.dataLen);
			if(devices[i].deviceState.rawData.dataLen != 0)
			{
				bytes2hexStr(devices[i].deviceState.rawData.data,rawData,devices[i].deviceState.rawData.dataLen);
				blobmsg_add_string(&b,"rwd",rawData);
			}
		}
		blobmsg_close_table(&b,e);
	}
	blobmsg_close_array(&b, l);
	ubus_send_reply(ctx, req, b.head);
	free(devices);
	return UBUS_STATUS_OK;
}




int	zha_permitjoin(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	struct blob_attr *tb[__ZHA_NWKMGR_ATTR_MAX];
	uint8_t duration = 0;
	uint8_t ieeeAddr[EXT_ADDR_LEN] = {0,0,0,0,0,0,0,0};
	uint8_t i;

	//SCprintf("zha _time _attrs :%d",__ZHA_NWKMGR_ATTR_MAX);

	blobmsg_parse(zha_nwkmgr_attrs, __ZHA_NWKMGR_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if(tb[ZHA_PERMITJOIN_TIME_ATTR_SET])
	{
		duration =  (uint8_t)blobmsg_get_u32(tb[ZHA_PERMITJOIN_TIME_ATTR_SET]);
	}

	//SCprintf("zha_permitjoin:time = %d",duration);

	device_setPermitJoin(ieeeAddr,duration);

	for(i=0;i<EXT_ADDR_LEN;i++)
	{
		ieeeAddr[i] = 0xFF;
	}
	device_setPermitJoin(ieeeAddr,duration);

	return UBUS_STATUS_OK;
}

int	zha_leave_req(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	uint8_t ieeeaddr[8] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	struct blob_attr *tb[__ZHA_GATEWAY_ATTR_MAX];

	blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
	if(tb[ZHA_GATEWAY_ATTR_ID])
	{
		hexStr2bytes(blobmsg_get_string(tb[ZHA_GATEWAY_ATTR_ID]),ieeeaddr,EXT_ADDR_LEN);
		device_leaveReq(ieeeaddr);
		return UBUS_STATUS_OK;
	}

	return UBUS_STATUS_INVALID_ARGUMENT;
}


Zstatus_t zha_list_backinfo(deviceInfo_t *device_info, uint16_t num)
{
	uint16_t i,index,deviceState_index,temp_uint16;
	int16_t temp_int16;
	deviceState_t deviceState;
	deviceBasic_t device_basic;
	uint8_t ieeeaddr[EXT_ADDR_LEN] ;
	uint16_t device_id = 0;
	uint8_t src_endpoint = 0;
	uint8_t deviceState_len = 0;
	char ieeeaddr_string[17];
	char sensor_string[8];
	void *l,*e;
	int ret = 0;
	uint8_t j;
	uint8_t k;
	char temp_string[8];
	double temp_double;
	uint8_t onlinedevices = 0;

	debug(DEBUG_GENERAL,"num of device info %d",num);
	for(i=0;i<num;i++)
	{
	  	snprintf(ieeeaddr_string,17,"%02x%02x%02x%02x%02x%02x%02x%02x",\
			device_info[i].deviceBasic.ieeeAddr[0],\
			device_info[i].deviceBasic.ieeeAddr[1],\
			device_info[i].deviceBasic.ieeeAddr[2],\
			device_info[i].deviceBasic.ieeeAddr[3],\
			device_info[i].deviceBasic.ieeeAddr[4],\
			device_info[i].deviceBasic.ieeeAddr[5],\
			device_info[i].deviceBasic.ieeeAddr[6],\
			device_info[i].deviceBasic.ieeeAddr[7]);
		debug(DEBUG_GENERAL,"id %s",ieeeaddr_string);
		onlinedevices++;
		debug(DEBUG_GENERAL,"endpointId :%d",device_info[i].deviceBasic.endpointId);
		debug(DEBUG_GENERAL,"profileId : %d",device_info[i].deviceBasic.profileId);
		debug(DEBUG_GENERAL,"deviceId : %d",device_info[i].deviceBasic.deviceId);

		if(device_info[i].deviceBasic.ManufacturerName_len != 0)
			debug(DEBUG_GENERAL,"ManufacturerName: %s",device_info[i].deviceBasic.ManufacturerName);
		if(device_info[i].deviceBasic.LocationDescription_len != 0)
			debug(DEBUG_GENERAL,"LocationDescription: %s",device_info[i].deviceBasic.LocationDescription);

		if(device_info[i].deviceBasic.online)
		{
			if(device_info[i].deviceBasic.profileId == ZCL_HA_PROFILE_ID)
			{
				switch(device_info[i].deviceBasic.deviceId)
				{
					case  ZCL_HA_DEVICEID_DIMMABLE_LIGHT:
					case  ZCL_HA_DEVICEID_ON_OFF_LIGHT:
					case  ZCL_HA_DEVICEID_COLORED_DIMMABLE_LIGHT:
						debug(DEBUG_GENERAL,"on : %d",device_info[i].deviceState.lightState.on);
						debug(DEBUG_GENERAL,"bri :%d",device_info[i].deviceState.lightState.bri);
						debug(DEBUG_GENERAL,"hue :%d",device_info[i].deviceState.lightState.hue);
						debug(DEBUG_GENERAL,"sat :%d",device_info[i].deviceState.lightState.sat);
						debug(DEBUG_GENERAL,"colortemp :%d",device_info[i].deviceState.lightState.colortemp);
						break;
					case  ZCL_HA_DEVICEID_MAINS_POWER_OUTLET:
					case  ZCL_HA_DEVICEID_REMOTE_CONTROL:
					case  ZCL_HA_DEVICEID_ON_OFF_SWITCH:
					case  ZCL_HA_DEVICEID_DOOR_LOCK:
						debug(DEBUG_GENERAL,"on :%d",device_info[i].deviceState.onoffState.status);
						break;
					case  ZCL_HA_DEVICEID_WHITE_GOODS:
			            if(device_info[i].deviceState.rawData.dataLen != 0)
						{
				            debug(DEBUG_ERROR,"infrared repeat return[");
							for(j=0;j<device_info[i].deviceState.rawData.dataLen;j++)
							{
				            	printf(" %02x ",device_info[i].deviceState.rawData.data[j]);
				            }
				            printf("]\n");
			            }
  						break;
					case ZCL_HA_DEVICEID_SIMPLE_SENSOR :
					case ZCL_HA_DEVICEID_LIGHT_SENSOR:
						debug(DEBUG_GENERAL,"device num : %d sensor num : %d",i,device_info[i].deviceState.simpleSensor.sensorNum);
						for(j=0;j<device_info[i].deviceState.simpleSensor.sensorNum;j++)
						{
							switch(device_info[i].deviceState.simpleSensor.sensor[j].clusterId)
							{
								case ZCL_CLUSTER_ID_MS_TEMPERATURE_MEASUREMENT:
									temp_int16 = BUILD_UINT16(device_info[i].deviceState.simpleSensor.sensor[j].data[0] ,device_info[i].deviceState.simpleSensor.sensor[j].data[1] );
									temp_int16 = temp_int16/100;
									sprintf(temp_string,"%d",temp_int16);
									debug(DEBUG_GENERAL,"temperature :%s",temp_string);
									break;
								case ZCL_CLUSTER_ID_MS_RELATIVE_HUMIDITY:
									temp_int16 = BUILD_UINT16(device_info[i].deviceState.simpleSensor.sensor[j].data[0] ,device_info[i].deviceState.simpleSensor.sensor[j].data[1] );
									temp_int16 = temp_int16/100;
									sprintf(temp_string,"%d",temp_int16);
									debug(DEBUG_GENERAL,"humidity :%s",temp_string);
									break;
								case ZCL_CLUSTER_ID_MS_ILLUMINANCE_LEVEL_SENSING_CONFIG  :
									switch(device_info[i].deviceState.simpleSensor.sensor[j].attrId)
									{
										case ATTRID_MS_ILLUMINANCE_LEVEL_STATUS:
											if(device_info[i].deviceState.simpleSensor.sensor[j].dataType == ZCL_DATATYPE_ENUM8)
											{
												debug(DEBUG_GENERAL,"level status : %02x",*(uint8_t *)(device_info[i].deviceState.simpleSensor.sensor[j].data));
											}
											break;
										case ATTRID_MS_ILLUMINANCE_TARGET_LEVEL:
											if(device_info[i].deviceState.simpleSensor.sensor[j].dataType == ZCL_DATATYPE_UINT16)
											{
												temp_uint16 = BUILD_UINT16(device_info[i].deviceState.simpleSensor.sensor[j].data[1] ,device_info[i].deviceState.simpleSensor.sensor[j].data[0] );
												debug(DEBUG_GENERAL,"target temp uint16 : %04x",temp_uint16);
												temp_double = temp_uint16;
												temp_double = (temp_double/10000);
												temp_double = pow(10.0,temp_double);
												debug(DEBUG_GENERAL,"target lux value : %f ",temp_double);
  											}
											break;

										default:
											debug(DEBUG_ERROR,"unsupport attrid: %04x ",device_info[i].deviceState.simpleSensor.sensor[j].attrId);
											break;
									}
									break;
								case ZCL_CLUSTER_ID_MS_ILLUMINANCE_MEASUREMENT:
									switch(device_info[i].deviceState.simpleSensor.sensor[j].attrId)
									{
										case ATTRID_MS_ILLUMINANCE_LEVEL_STATUS:
											if(device_info[i].deviceState.simpleSensor.sensor[j].dataType == ZCL_DATATYPE_UINT16)
											{
												temp_uint16 = BUILD_UINT16( device_info[i].deviceState.simpleSensor.sensor[j].data[1] , device_info[i].deviceState.simpleSensor.sensor[j].data[0] );
												debug(DEBUG_GENERAL,"now temp uint16 : %04x",temp_uint16);
												temp_double = temp_uint16;
												temp_double = (temp_double/10000);
												temp_double = pow(10.0,temp_double);
												debug(DEBUG_GENERAL,"now lux value : %f ",temp_double);
											}
											break;

										default:
											break;
									}
									break;
								case ZCL_CLUSTER_ID_GEN_ANALOG_INPUT_BASIC:
									temp_uint16 = BUILD_UINT16(device_info[i].deviceState.simpleSensor.sensor[j].data[1] ,device_info[i].deviceState.simpleSensor.sensor[j].data[0] );
									debug(DEBUG_GENERAL,"temp uint16 : %04x",temp_uint16 );
									if(memcmp(device_info[i].deviceBasic.LocationDescription,"pm2.5",5) == 0)
									{
										debug(DEBUG_GENERAL,"pm2.5 :%04x ",temp_uint16 );
									}
									else if(memcmp(device_info[i].deviceBasic.LocationDescription,"formaldehyde",12) == 0)
									{
										debug(DEBUG_GENERAL,"voc: %04x ",temp_uint16 );
									}
									break;
								default:
									debug(DEBUG_ERROR,"unsupport cluster id %04x",device_info[i].deviceState.simpleSensor.sensor[j].clusterId);
									break;
							}

						}
						break;
					case ZCL_HA_DEVICEID_IAS_ZONE :
						debug(DEBUG_GENERAL,"zoneid :%d",device_info[i].deviceState.zoneState.zoneId);
						debug(DEBUG_GENERAL,"zonetype :%d",device_info[i].deviceState.zoneState.zoneType);
						debug(DEBUG_GENERAL,"status :%d",device_info[i].deviceState.zoneState.status);
						break;
					default:
						debug(DEBUG_ERROR,"id unsupport device");
						break;
				}
			}
			else if(device_info[i].deviceBasic.profileId == ZLL_PROFILE_ID)
			{
				switch(device_info[i].deviceBasic.deviceId)
				{
					case  ZLL_DEVICEID_COLOR_LIGHT:
					case  ZLL_DEVICEID_EXTENDED_COLOR_LIGHT:
					case  ZLL_DEVICEID_DIMMABLE_LIGHT:
					case  ZLL_DEVICEID_COLOR_TEMPERATURE_LIGHT:
  						debug(DEBUG_GENERAL,"on : %d",device_info[i].deviceState.lightState.on);
						debug(DEBUG_GENERAL,"bri :%d",device_info[i].deviceState.lightState.bri);
						debug(DEBUG_GENERAL,"hue :%d",device_info[i].deviceState.lightState.hue);
						debug(DEBUG_GENERAL,"sat :%d",device_info[i].deviceState.lightState.sat);
						debug(DEBUG_GENERAL,"colortemp :%d",device_info[i].deviceState.lightState.colortemp);
						break;
					default:
						debug(DEBUG_ERROR,"id :%d",device_info[i].deviceBasic.deviceId);
						break;
				}
			}
			else if(device_info[i].deviceBasic.profileId == ZCL_SHUNCOM_PROFILE_ID)
			{
				if(device_info[i].deviceState.rawData.dataLen != 0)
				{
					debug(DEBUG_GENERAL,"shuncom device:");
					for(j=0;j<device_info[i].deviceState.rawData.dataLen;j++)
					{
						printf(" %02x ",device_info[i].deviceState.rawData.data[j]);
					}
					printf("\n");
				}
			}

		}
		else
		{
			debug(DEBUG_GENERAL,"offline");
		}

	}



	return 0;
}

int	zha_get_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	uint8_t ieeeAddr[EXT_ADDR_LEN * 1000];
	uint16_t i,num_ieeeAddr;
	void *l,*e;
	char id[17];
	uint16_t index = 0;

	num_ieeeAddr = device_getWhitelist(ieeeAddr);

	blob_buf_init(&b, 0);
	l = blobmsg_open_array(&b,"whitelist");

	debug(DEBUG_GENERAL,"ubus zha get whitelist,num_ieeeAddr[%d]",num_ieeeAddr);
	for(i=0;i<num_ieeeAddr;i++)
	{
		e = blobmsg_open_table(&b,NULL);
		snprintf(id, sizeof(id), ieee_id,\
				ieeeAddr[index + 0], ieeeAddr[index + 1],\
				ieeeAddr[index + 2], ieeeAddr[index + 3],\
				ieeeAddr[index + 4], ieeeAddr[index + 5],\
				ieeeAddr[index + 6], ieeeAddr[index + 7]);
		index += EXT_ADDR_LEN;
		blobmsg_add_string(&b, "id", id);
		blobmsg_close_table(&b,e);

	}
	blobmsg_close_array(&b, l);

  	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

int	zha_write_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	uint8_t ieeeaddr[8] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	struct blob_attr *tb[__ZHA_GATEWAY_ATTR_MAX];
	struct blob_attr *pattr;
	struct blob_attr *wttb[__ZHA_GATEWAY_ATTR_MAX];
	uint16_t len;
	uint8_t i;

	blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if(tb[ZHA_GATEWAY_ATTR_WHITELIST])
	{
		len = blobmsg_len(tb[ZHA_GATEWAY_ATTR_WHITELIST]);
		__blob_for_each_attr(pattr, blobmsg_data(tb[ZHA_GATEWAY_ATTR_WHITELIST]),len  )
		{ 

			blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, wttb, blobmsg_data(pattr), blobmsg_len(pattr)); 
			if(wttb[ZHA_GATEWAY_ATTR_ID])
			{
				hexStr2bytes(blobmsg_get_string(wttb[ZHA_GATEWAY_ATTR_ID]),ieeeaddr,EXT_ADDR_LEN);
				debug(DEBUG_WARN,"write whitelist[");
				for(i=0;i<EXT_ADDR_LEN;i++)
				{
					printf(" %02x ",ieeeaddr[i]);
				}
				printf("]\n");
				device_writeWhitelist(ieeeaddr);
#ifndef	DISABLE_LOCAL_NOTIFY

				change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
				change_info.flag = NODE_DEL_ADD;
				change_info.device_info = NULL;
				change_info.group_info = NULL;
				change_info.scene_info = NULL;
				change_info.rule_info = NULL;
				local_notify(&change_info,client_head);
#endif
			}
    	}
		return UBUS_STATUS_OK;
	}

	return UBUS_STATUS_INVALID_ARGUMENT;
}

int	zha_delete_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	uint8_t ieeeaddr[8] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	struct blob_attr *tb[__ZHA_GATEWAY_ATTR_MAX];
	struct blob_attr *pattr;
	struct blob_attr *wttb[__ZHA_GATEWAY_ATTR_MAX];
	uint16_t len;
	uint8_t i = 0;
	int ieee_count = 0;
	unsigned char ieee[50][9];
	unsigned char * p_ieee[50] = {NULL};
	
	blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
	if(tb[ZHA_GATEWAY_ATTR_WHITELIST])
	{
		len = blobmsg_len(tb[ZHA_GATEWAY_ATTR_WHITELIST]);

		__blob_for_each_attr(pattr, blobmsg_data(tb[ZHA_GATEWAY_ATTR_WHITELIST]),len  )
		{ 
			blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, wttb, blobmsg_data(pattr), blobmsg_len(pattr)); 
			if(wttb[ZHA_GATEWAY_ATTR_ID])
			{
				hexStr2bytes(blobmsg_get_string(wttb[ZHA_GATEWAY_ATTR_ID]),ieeeaddr,EXT_ADDR_LEN);
				debug(DEBUG_WARN,"delete whitelist");
				for(i=0;i<EXT_ADDR_LEN;i++)
				{
					printf(" %02x ",ieeeaddr[i]);
				}
				printf("\n");

				memcpy(ieee[ieee_count],ieeeaddr,8);
				p_ieee[ieee_count] = ieee[ieee_count];
				ieee_count = ieee_count + 1;
				
				
				device_deleteWhitelist(ieeeaddr);
#ifndef	DISABLE_LOCAL_NOTIFY


				change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
				change_info.flag = NODE_DEL_ADD;
				change_info.device_info = NULL;
				change_info.group_info = NULL;
				change_info.scene_info = NULL;
				change_info.rule_info = NULL;
				local_notify(&change_info,client_head);
#endif
			}
		}
		
#ifndef DISABLE_REPORT

		cloud_node_status_del_callback(&node_info,p_ieee,ieee_count);

#endif
		return UBUS_STATUS_OK;
	}


	return UBUS_STATUS_INVALID_ARGUMENT;
}

int	zha_enable_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	struct blob_attr *tb[__ZHA_GATEWAY_ATTR_MAX];
	uint8_t status;

	blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
	if(tb[ZHA_GATEWAY_ATTR_STATUS])
	{
		status = blobmsg_get_u32(tb[ZHA_GATEWAY_ATTR_STATUS]);
		device_enableWhitelist(status);
		return UBUS_STATUS_OK;
	}

	return UBUS_STATUS_INVALID_ARGUMENT;
}



int step[3] = {0,0,0};
struct uloop_timeout disable_timer = {0};
pthread_mutex_t whitelist_lock;

void disable_whitelist_timer_callback(struct uloop_timeout *t)
{
	extern struct uloop_timeout disable_timer;
	extern int step[3];
	static uint8_t ieeeAddr[EXT_ADDR_LEN] = {0,0,0,0,0,0,0,0};
	
	debug(DEBUG_GENERAL,"---remain time[%d]",step[1]);
	pthread_mutex_lock(&whitelist_lock);
	if(step[0] == 1)
	{
		debug(DEBUG_GENERAL,"disable whitelist");
		device_enableWhitelist(0);
		step[0] = 0;
	}
	if(step[1] == 0)
	{
		device_enableWhitelist(1);
		step[0] = 0;
		step[1] = 0;
		debug(DEBUG_GENERAL,"exit scan device thread");
		memset(ieeeAddr,0xff,8);
		device_setPermitJoin(ieeeAddr,0);
	}
	step[1] = step[1] - 1;
	
	if(step[1] >= 0)
		uloop_timeout_set(&disable_timer,1000);
	else
		step[2] = 0;
	pthread_mutex_unlock(&whitelist_lock);
}

int	zha_disable_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
		extern struct uloop_timeout disable_timer;
		extern int step[3];
		static int timert_flag = 0;
		struct blob_attr *tb[__ZHA_NWKMGR_ATTR_MAX];
		blobmsg_parse(zha_nwkmgr_attrs, __ZHA_NWKMGR_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
		
		if(tb[ZHA_PERMITJOIN_TIME_ATTR_SET])
		{
			pthread_mutex_lock(&whitelist_lock);
			step[0] = 1;
			step[1] =  (uint8_t)blobmsg_get_u32(tb[ZHA_PERMITJOIN_TIME_ATTR_SET]);
			pthread_mutex_unlock(&whitelist_lock);
		}
		pthread_mutex_lock(&whitelist_lock);
		if(step[2] == 0)
		{
			debug(DEBUG_GENERAL,"create timer");
			step[2] = 1;
			if(disable_timer.pending)
 				uloop_timeout_cancel(&disable_timer);
			disable_timer.cb = disable_whitelist_timer_callback;
			disable_timer.time.tv_sec = 1;
 			disable_timer.time.tv_usec = 0;
			uloop_timeout_add(&disable_timer);
		}
		pthread_mutex_unlock(&whitelist_lock);

	return UBUS_STATUS_OK;
}

int	zha_clean_whitelist(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	device_cleanWhitelist();

	return UBUS_STATUS_OK;
}


int zha_group_create(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	int result = UBUS_STATUS_OK;
	struct blob_attr *tb[__GROUP_ATTR_MAX];
	struct blob_attr *pattr;
	uint16_t groupId = 0;
	char group_name[32] = {0};
	char group_value[9] = {0};

	blobmsg_parse(group_attrs, __GROUP_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if(!tb[GROUP_ATTR_NAME])
	{
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	else
	{
		groupId = group_create(blobmsg_get_string(tb[GROUP_ATTR_NAME]));
		debug(DEBUG_GENERAL,"create group id[%d]",groupId);
		group_value[0] = group_value[0]|(0x01 << 0);
		strcpy(group_name,blobmsg_get_string(tb[GROUP_ATTR_NAME]));
#ifndef DISABLE_REPORT
		cloud_group_state_create_callback(&node_info,groupId,group_name,group_value);
#endif

#ifndef	DISABLE_LOCAL_NOTIFY

		change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
		change_info.flag = GROUP_DEL_ADD;
		change_info.device_info = NULL;
		change_info.group_info = NULL;
		change_info.scene_info = NULL;
		change_info.rule_info = NULL;
		local_notify(&change_info,client_head);
#endif
	   	blob_buf_init(&b, 0);
		blobmsg_add_u32(&b,"id",groupId);
	    ubus_send_reply(ctx, req, b.head);
	}

	return UBUS_STATUS_OK;

}


/**********************************************************************************
 * @brief	Get the group list. Include all content of the group.
 */
int zha_group_list(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{	
	uint16_t groupNum,index,i;
	void *l,*e,*e1,*ll,*attribute,*attribute_members;
	char ieeeAddrString[17];

	groupInfo_t *group = NULL;
	groupNum = 0;

	group = group_getList(&groupNum);
	if(group)
	{
		blob_buf_init(&b, 0);
		l = blobmsg_open_array(&b,"groups");
		for(index=0;index<groupNum;index++)
		{
			e = blobmsg_open_table(&b,NULL);
			blobmsg_add_string(&b,"name",group[index].name);
			blobmsg_add_u32(&b,"id",group[index].id);
			blobmsg_add_u8(&b,"visible",group[index].visible);
			ll = blobmsg_open_array(&b,"device");
			for(i=0;i<group[index].groupMembersNum;i++)
			{
				e1 = blobmsg_open_table(&b,NULL); 
				bytes2hexStr(group[index].groupMember[i].ieeeAddr,ieeeAddrString,EXT_ADDR_LEN);
				blobmsg_add_string(&b,"id",ieeeAddrString);
				blobmsg_add_u32(&b,"ep",group[index].groupMember[i].endpointId);
				blobmsg_add_u32(&b,"pid",group[index].groupMember[i].profileId);
				blobmsg_add_u32(&b,"did",group[index].groupMember[i].deviceId);
				blobmsg_close_table(&b,e1); 
			}
			blobmsg_close_array(&b,ll);

			attribute = blobmsg_open_array(&b,"attribute");
			attribute_members = blobmsg_open_table(&b,NULL);
			for(i=0;i<group[index].groupAttrsNum;i++)
			{
				blobmsg_add_string(&b,group[index].groupAttr[i].attrName,group[index].groupAttr[i].data);
			}
			blobmsg_close_table(&b,attribute_members);
			blobmsg_close_array(&b,attribute);

			blobmsg_close_table(&b,e);
		}
		blobmsg_close_array(&b,l);
		ubus_send_reply(ctx, req, b.head);
	}

	return UBUS_STATUS_OK;
}

int zha_group_set(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	uint8_t ieeeaddr[1024];
	struct blob_attr *tb[__GROUP_ATTR_MAX];
	struct blob_attr *pattr;
	struct blob_attr *wttb[__ZHA_GATEWAY_ATTR_MAX];
	groupInfo_t groupInfo;
	uint16_t len,i=0;
  	uint8_t tmpUint8;
  	uint16_t tmpUint16;
  	uint16_t groupId;
  	unsigned char group_value[9] = {0};
	

	blobmsg_parse(group_attrs, __GROUP_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if(!tb[GROUP_ATTR_ID])
	{
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if(tb[GROUP_ATTR_ID])
	{
	    groupId = (uint16_t)blobmsg_get_u32(tb[GROUP_ATTR_ID]);
	    if(group_get(groupId,&groupInfo) != ZSUCCESS)
		{
	        debug(DEBUG_ERROR,"can't get match group");
			return UBUS_STATUS_INVALID_ARGUMENT;
	    }
		
	}


	if(tb[GROUP_ATTR_VISIBLE])
	{
		groupInfo.visible = (uint8_t)blobmsg_get_u8(tb[GROUP_ATTR_VISIBLE]);
		group_value[0] = group_value[0]|(0x01 << 1);
		group_value[1] = groupInfo.visible;
	}

	if(tb[GROUP_ATTR_ON])
	{
        debug(DEBUG_GENERAL,"group on");
        tmpUint8 = (blobmsg_get_u8(tb[GROUP_ATTR_ON]));
        group_setDeviceAttr(groupId,"on",&tmpUint8);
		group_value[0] = group_value[0]|(0x01 << 2);
		group_value[2] = tmpUint8;
	}

	if(tb[GROUP_ATTR_BRI])
	{
        debug(DEBUG_GENERAL,"group bri");
        tmpUint8 = (blobmsg_get_u32(tb[GROUP_ATTR_BRI]));
        group_setDeviceAttr(groupId,"bri",&tmpUint8);
		group_value[0] = group_value[0]|(0x01 << 3);
		group_value[3] = tmpUint8;
	}

	if(tb[GROUP_ATTR_HUE])
	{
	    debug(DEBUG_GENERAL,"group hue");
	    tmpUint8 = (blobmsg_get_u32(tb[GROUP_ATTR_HUE]));
	    group_setDeviceAttr(groupId,"hue",&tmpUint8);
		group_value[0] = group_value[0]|(0x01 << 4);
		group_value[4] = tmpUint8;
	}

	if(tb[GROUP_ATTR_SAT])
	{
		debug(DEBUG_GENERAL,"group sat");
		tmpUint8 = (blobmsg_get_u32(tb[GROUP_ATTR_SAT]));
		group_setDeviceAttr(groupId,"sat",&tmpUint8);
		group_value[0] = group_value[0]|(0x01 << 5);
		group_value[5] = tmpUint8;
	}

	if(tb[GROUP_ATTR_COLORTEMP])
	{
	    debug(DEBUG_GENERAL,"group colortemp");
	    tmpUint16 = (blobmsg_get_u32(tb[GROUP_ATTR_COLORTEMP]));
	    group_setDeviceAttr(groupId,"colortemp",&tmpUint16);
		group_value[0] = group_value[0]|(0x01 << 6);
		group_value[7] = (unsigned char)(tmpUint16 >> 8);
		group_value[8] = (unsigned char)(tmpUint8 & 0x00ff);
	}

	if (tb[GROUP_ATTR_FAN])
	{
		uint8_t tmpUint8 = blobmsg_get_u32(tb[GROUP_ATTR_FAN]);
		group_setDeviceAttr(groupId,"fan",&tmpUint8);
	}

	if(tb[GROUP_THERMOSTAT_MODE] && tb[GROUP_THERMOSTAT_VALUE])
	{
		unsigned char value[2] = {0,0};
		value[0] = blobmsg_get_u32(tb[GROUP_THERMOSTAT_MODE]);
		value[1] = (unsigned char)blobmsg_get_u32(tb[GROUP_THERMOSTAT_VALUE]);
		if((value[0] != 0) || (value[0] != 1) || (value[0] != 2))
			return UBUS_STATUS_INVALID_ARGUMENT;
		group_setDeviceAttr(groupId,"pointraiselower",&value);
	}

	if (tb[GROUP_TARGET_TEMP])
	{
		short tmpUint8 = blobmsg_get_u32(tb[GROUP_TARGET_TEMP]);
		group_setDeviceAttr(groupId,"temperature",&tmpUint8);
	}

	if (tb[GROUP_POWER_MODE])
	{
		short tmpUint8 = (short)blobmsg_get_u32(tb[GROUP_POWER_MODE]);
		if(ZSUCCESS != group_setDeviceAttr(groupId,"powermode",&tmpUint8))
			return UBUS_STATUS_INVALID_ARGUMENT;
	}
	
#ifndef DISABLE_REPORT

	cloud_group_state_set_callback(&node_info,groupId,group_value);
#endif

#ifndef	DISABLE_LOCAL_NOTIFY
	groupInfo_t group_info = {0};
	if(group_get(groupId,&group_info) == ZSUCCESS)
	{
       	change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
		change_info.flag = GROUP_STATE_CHANGE;
		change_info.device_info = NULL;
		change_info.group_info = &group_info;
		change_info.scene_info = NULL;
		change_info.rule_info = NULL;
		local_notify(&change_info,client_head);
    }
#endif
	return UBUS_STATUS_OK;

}

int zha_group_change(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{

	uint8_t ieeeaddr[1024];
	struct blob_attr *tb[__GROUP_ATTR_MAX];
	struct blob_attr *pattr;
	struct blob_attr *wttb[__ZHA_GATEWAY_ATTR_MAX];
	groupInfo_t groupInfo = {0};
	uint16_t len,i=0;
	int j = 0;
	uint8_t tmpUint8;
	uint16_t tmpUint16;
	uint16_t groupId;
	unsigned char group_name[32] = {0};
	int ieee_count = 0;
	unsigned char ieee[100][9];
	unsigned char * p_ieee[100] = {NULL};
	unsigned char endpoint_id[100] = {0};
  	unsigned char group_value[9] = {0};
	groupMemberInfo_t groupMember[100] = {0};
	int find_flag = 0;
	unsigned int member_count = 0;

	blobmsg_parse(group_attrs, __GROUP_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if(!tb[GROUP_ATTR_ID])
	{
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if(tb[GROUP_ATTR_ID])
	{
	    groupId = (uint16_t)blobmsg_get_u32(tb[GROUP_ATTR_ID]);
	    if(group_get(groupId,&groupInfo) != ZSUCCESS)
		{
	       	debug(DEBUG_ERROR,"can't get match group");
			return UBUS_STATUS_INVALID_ARGUMENT;
	    }
		/*else
		{
			SCprintf("get group info success,groupInfo.name[%s]",groupInfo.name);
		}*/
		
	}

	if(tb[GROUP_ATTR_NAME])
	{
		debug(DEBUG_GENERAL,"change group name[%s]group_id[%d]",blobmsg_get_string(tb[GROUP_ATTR_NAME]),groupId);
		strcpy(group_name,blobmsg_get_string(tb[GROUP_ATTR_NAME]));
		group_value[0] = group_value[0]|(0x01 << 0);
		debug(DEBUG_GENERAL,"change group name[%s]group_id[%d]",blobmsg_get_string(tb[GROUP_ATTR_NAME]),groupId);
		group_changeName(groupId,group_name);
	}
	else
	{
		strcpy(group_name,groupInfo.name);
		debug(DEBUG_GENERAL,"groupInfo.name[%s]len[%d]group_name[%s]",groupInfo.name,strlen(groupInfo.name),group_name);
		group_value[0] = group_value[0]|(0x01 << 0);
	}

	if(tb[GROUP_ATTR_DEVICE])
	{
		len = blobmsg_len(tb[GROUP_ATTR_DEVICE]);
		debug(DEBUG_GENERAL,"group attr device len :%d\n",len);
		i=0;
		//group_removeAllDevices(groupId);
		//print_time_curr();
		debug(DEBUG_GENERAL,"group change device start");
		__blob_for_each_attr(pattr, blobmsg_data(tb[GROUP_ATTR_DEVICE]),len  )
		{
			blobmsg_parse(zha_gateway_attrs, __ZHA_GATEWAY_ATTR_MAX, wttb, blobmsg_data(pattr), blobmsg_len(pattr));
			if(wttb[ZHA_GATEWAY_ATTR_ID])
			{
				hexStr2bytes(blobmsg_get_string(wttb[ZHA_GATEWAY_ATTR_ID]),groupInfo.groupMember[i].ieeeAddr,EXT_ADDR_LEN);
			  	groupInfo.groupMember[i].endpointId = (uint8_t)blobmsg_get_u32(wttb[ZHA_GATEWAY_ATTR_ENDPOINT_ID]);
			  	
			  	
				if(i < 100)
				{
					memcpy(ieee[ieee_count],groupInfo.groupMember[i].ieeeAddr,8);
					p_ieee[ieee_count] = ieee[ieee_count];
					endpoint_id[ieee_count] = groupInfo.groupMember[i].endpointId;
					ieee_count = ieee_count + 1;

					hexStr2bytes(blobmsg_get_string(wttb[ZHA_GATEWAY_ATTR_ID]),groupMember[member_count].ieeeAddr,IEEE_ADDR_LEN);
					groupMember[member_count].endpointId = (uint8_t)blobmsg_get_u32(wttb[ZHA_GATEWAY_ATTR_ENDPOINT_ID]);
					member_count = member_count + 1;	
					group_addDevice(groupId,&(groupInfo.groupMember[i]));
				}
			  	i++;
			}
		}

		print_time_curr();
		debug(DEBUG_GENERAL,"group change device over");

		if(group_get(groupId,&groupInfo) != ZSUCCESS)
		{
	       	debug(DEBUG_ERROR,"can't get match group");
			return UBUS_STATUS_INVALID_ARGUMENT;
	    }

		debug(DEBUG_ERROR,"groupInfo.groupMembersNum[%d]",groupInfo.groupMembersNum);

		for(i = 0;i < groupInfo.groupMembersNum;i++)
		{
			for(j = 0;j < member_count;j++)
			{
				if(memcmp(groupMember[j].ieeeAddr,groupInfo.groupMember[i].ieeeAddr,8) == 0)
				{
					
					debug(DEBUG_ERROR,"couldn't find device");
					find_flag = 1;
					break;
				}
			}

			if(find_flag == 1)
			{
				find_flag = 0;
				continue;
			}
			else
			{
				if(ZSUCCESS != group_removeDevice(groupId,&groupInfo.groupMember[i]))
				{
					debug(DEBUG_ERROR,"group_removeDevice error");
					continue ;
				}
			}
		}

	}

#if 0

#ifndef DISABLE_REPORT

		cloud_group_state_change_callback(&node_info,groupId,p_ieee,ieee_count,endpoint_id,group_name,group_value);
#endif

#endif

#ifndef	DISABLE_LOCAL_NOTIFY

	if(group_get(groupId,&groupInfo) == ZSUCCESS)
	{
       	change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
		change_info.flag = GROUP_STATE_CHANGE;
		change_info.group_info = &groupInfo;
		local_notify(&change_info,client_head);
    }
#endif

	//print_time_curr();
	debug(DEBUG_ERROR,"group change right");
	return UBUS_STATUS_OK;

}


int zha_group_delete(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	int result = UBUS_STATUS_OK;
	uint16_t groupId;
	struct blob_attr *tb[__RULE_ATTR_MAX];


	blobmsg_parse(rule_attrs, __RULE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if(tb[GROUP_ATTR_ID])
	{
		groupId = blobmsg_get_u32(tb[GROUP_ATTR_ID]);
		if(group_del(groupId) ==ZSUCCESS)
		{
#ifndef DISABLE_REPORT

			cloud_group_state_del_callback(&node_info,groupId);
#endif

#ifndef	DISABLE_LOCAL_NOTIFY

			change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
			change_info.flag = GROUP_DEL_ADD;
			change_info.device_info = NULL;
			change_info.group_info = NULL;
			change_info.scene_info = NULL;
			change_info.rule_info = NULL;
			local_notify(&change_info,client_head);
#endif
			result = UBUS_STATUS_OK;
		}
		else
		{
			result = UBUS_STATUS_INVALID_ARGUMENT;
		}
	}
	return result;
}


int zha_scene_set(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	int result = UBUS_STATUS_OK;
	struct blob_attr *tb[__SCENE_ATTR_MAX];
	char* strname = NULL;
	uint16_t groupId =0 ;
	uint16_t iconId = 0;
	uint8_t id;
	unsigned char group_value[9] = {0};
	unsigned char scene_name[32] = {0};

	debug(DEBUG_GENERAL,"scene set");
	blobmsg_parse(scene_attrs, __SCENE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if(!tb[SCENE_ATTR_ID])
	{
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	else
	{
		if(tb[SCENE_ATTR_ID])
		{
			id = (uint8_t)blobmsg_get_u32(tb[SCENE_ATTR_ID]);
			group_value[0] = group_value[0] | (0x01 << 2);
			group_value[3] = id;
		}

		if(tb[SCENE_ATTR_NAME])
		{
			strname = blobmsg_get_string(tb[SCENE_ATTR_NAME]);
			strcpy(scene_name,strname);
			group_value[0] = group_value[0] | (0x01 << 0);
		}

		if(tb[SCENE_ATTR_GROUP_ID])
		{
			groupId = (uint16_t)blobmsg_get_u32(tb[SCENE_ATTR_GROUP_ID]);
		}

		if(tb[SCENE_ATTR_ICON_ID])
		{
			iconId = (uint16_t)blobmsg_get_u32(tb[SCENE_ATTR_ICON_ID]);
			group_value[0] = group_value[0] | (0x01 << 1);
			group_value[1] = (unsigned char)(iconId >> 8);
			group_value[2] = (unsigned char)(iconId & 0x00ff);
		}

		result = scene_set(id,strname,groupId,iconId);
#ifndef DISABLE_REPORT

		if(result == ZSUCCESS)
			cloud_scene_state_set_callback(&node_info,groupId,group_value,scene_name);
#endif
#ifndef	DISABLE_LOCAL_NOTIFY

		sceneInfo_t sence_info = {0};
		sence_info.id = id;
		change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
		change_info.flag = SCENE_STATE_CHANGE;
		change_info.device_info = NULL;
		change_info.group_info = NULL;
		change_info.scene_info = &sence_info;
		change_info.rule_info = NULL;
		local_notify(&change_info,client_head);
#endif
	}
	return result;
}


int zha_scene_create(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
  	int result = UBUS_STATUS_OK;
	struct blob_attr *tb[__SCENE_ATTR_MAX];
	char* strname;
	uint16_t groupId,iconId = 0;
  	uint8_t id;
	unsigned char group_value[9] = {0};
	unsigned char scene_name[32] = {0};

	blobmsg_parse(scene_attrs, __SCENE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if((!tb[SCENE_ATTR_NAME]) || (!tb[SCENE_ATTR_GROUP_ID]))
	{
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	else
	{
		strname = blobmsg_get_string(tb[SCENE_ATTR_NAME]);
		strcpy(scene_name,strname);
		group_value[0] = group_value[0] | (0x01 << 0);

	    if(tb[SCENE_ATTR_ICON_ID])
		{
	       iconId = (uint16_t)blobmsg_get_u32(tb[SCENE_ATTR_ICON_ID]);
		   group_value[0] = group_value[0] | (0x01 << 1);
		   group_value[1] = (unsigned char)(iconId >> 8);
		   group_value[2] = (unsigned char)(iconId & 0x00ff);
	    }
		else
		{
			debug(DEBUG_GENERAL,"default icon\n");
			group_value[0] = group_value[0] | (0x01 << 1);
		   	group_value[1] = (unsigned char)(0 >> 8);
		   	group_value[2] = (unsigned char)(0 & 0x00ff);
		}
		groupId = (uint16_t)blobmsg_get_u32(tb[SCENE_ATTR_GROUP_ID]);
		id = scene_create(strname,groupId,iconId);
		group_value[0] = group_value[0] | (0x01 << 2);
		group_value[3] = id;
	   	blob_buf_init(&b, 0);
		blobmsg_add_u32(&b,"id",id);
	    ubus_send_reply(ctx, req, b.head);
	}
#ifndef DISABLE_REPORT

	cloud_scene_state_create_callback(&node_info,groupId,group_value,scene_name);

#endif
#ifndef	DISABLE_LOCAL_NOTIFY

	change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
	change_info.flag = SCENE_DEL_ADD;
	change_info.device_info = NULL;
	change_info.group_info = NULL;
	change_info.scene_info = NULL;
	change_info.rule_info = NULL;
	local_notify(&change_info,client_head);
#endif
	return result;
}

int zha_scene_store(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	int result = UBUS_STATUS_OK;
  	uint8 test;
	unsigned char group_value[9] = {0};

	struct blob_attr *tb[__SCENE_ATTR_MAX];

	blobmsg_parse(scene_attrs, __SCENE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[SCENE_ATTR_ID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	debug(DEBUG_GENERAL,"scene store");
	group_value[0] = group_value[0] | (0x01 << 2);
	group_value[3] = (uint8_t)blobmsg_get_u32(tb[SCENE_ATTR_ID]);
	test = scene_store((uint8_t)blobmsg_get_u32(tb[SCENE_ATTR_ID]));


	if(test == ZSUCCESS)
	{
#ifndef DISABLE_REPORT

		cloud_scene_state_store_callback(&node_info,group_value);
#endif
#ifndef	DISABLE_LOCAL_NOTIFY

		sceneInfo_t sence_info = {0};
		sence_info.id = (uint8_t)blobmsg_get_u32(tb[SCENE_ATTR_ID]);
		change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
		change_info.flag = SCENE_STATE_CHANGE;
		change_info.device_info = NULL;
		change_info.group_info = NULL;
		change_info.scene_info = &sence_info;
		change_info.rule_info = NULL;
		local_notify(&change_info,client_head);
#endif
	}

	debug(DEBUG_GENERAL,"scene store result :%d\n",test);
	return result;
}
int zha_scene_recall(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	int result = UBUS_STATUS_OK;
	unsigned char group_value[9] = {0};
	struct blob_attr *tb[__SCENE_ATTR_MAX];

	blobmsg_parse(scene_attrs, __SCENE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[SCENE_ATTR_ID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if(ZSUCCESS == scene_recall((uint8_t)blobmsg_get_u32(tb[SCENE_ATTR_ID])))
	{
		debug(DEBUG_GENERAL,"scene recall ");
		group_value[0] = group_value[0] | (0x01 << 2);
		group_value[3] = (uint8_t)blobmsg_get_u32(tb[SCENE_ATTR_ID]);
#ifndef DISABLE_REPORT

		cloud_scene_state_recall_callback(&node_info,group_value);
#endif
#ifndef	DISABLE_LOCAL_NOTIFY

		sceneInfo_t sence_info = {0};
		sence_info.id = (uint8_t)blobmsg_get_u32(tb[SCENE_ATTR_ID]);
		change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
		change_info.flag = SCENE_STATE_CHANGE;
		change_info.device_info = NULL;
		change_info.group_info = NULL;
		change_info.scene_info = &sence_info;
		change_info.rule_info = NULL;
		local_notify(&change_info,client_head);
#endif
	}

	return result;
}

int zha_scene_list(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	sceneInfo_t *scene;
	uint16_t nums,i,index;
	void *l,*e,*e1,*ll,*attribute,*attribute_members;
	char ieeeAddrString[17];

	scene = scene_getList(&nums);
	debug(DEBUG_GENERAL,"[%s] enter nums :%d\n",(char *)__FUNCTION__,nums);
	if(scene)
	{
		blob_buf_init(&b, 0);
		l = blobmsg_open_array(&b,"scenes");
		for(index=0;index<nums;index++)
		{
			e = blobmsg_open_table(&b,NULL);
			blobmsg_add_string(&b,"name",scene[index].name);
			blobmsg_add_u32(&b,"id",scene[index].id);
			blobmsg_add_u32(&b,"gid",scene[index].groupId);
			blobmsg_add_u32(&b,"icon",scene[index].iconId);
			ll = blobmsg_open_array(&b,"device");
			debug(DEBUG_GENERAL,"sceneMembersNum :%d\n",scene[index].sceneMembersNum);
			for(i=0;i<scene[index].sceneMembersNum;i++)
			{
				e1 = blobmsg_open_table(&b,NULL);
				bytes2hexStr(scene[index].sceneMember[i].deviceBasic.ieeeAddr,ieeeAddrString,EXT_ADDR_LEN);
				blobmsg_add_string(&b,"id",ieeeAddrString);
				blobmsg_add_u32(&b,"ep",scene[index].sceneMember[i].deviceBasic.endpointId);
				blobmsg_add_u32(&b,"pid",scene[index].sceneMember[i].deviceBasic.profileId);
				blobmsg_add_u32(&b,"did",scene[index].sceneMember[i].deviceBasic.deviceId);
				blobmsg_add_u8(&b,"ol",scene[index].sceneMember[i].deviceBasic.online);
				debug(DEBUG_GENERAL,"profileId :%04x\n",scene[index].sceneMember[i].deviceBasic.profileId);
    			if(scene[index].sceneMember[i].deviceBasic.profileId == ZCL_HA_PROFILE_ID)
				{
					switch(scene[index].sceneMember[i].deviceBasic.deviceId)
					{
						case  ZCL_HA_DEVICEID_DIMMABLE_LIGHT:
						case  ZCL_HA_DEVICEID_ON_OFF_LIGHT:
						case  ZCL_HA_DEVICEID_COLORED_DIMMABLE_LIGHT:
							blobmsg_add_u8(&b,"on",scene[index].sceneMember[i].deviceState.lightState.on);
							blobmsg_add_u32(&b,"bri",scene[index].sceneMember[i].deviceState.lightState.bri);
							blobmsg_add_u32(&b,"hue",scene[index].sceneMember[i].deviceState.lightState.hue);
							blobmsg_add_u32(&b,"sat",scene[index].sceneMember[i].deviceState.lightState.sat);
							blobmsg_add_u32(&b,"ctp",scene[index].sceneMember[i].deviceState.lightState.colortemp);
							break;
						case  ZCL_HA_DEVICEID_MAINS_POWER_OUTLET:
						case  ZCL_HA_DEVICEID_REMOTE_CONTROL:
						case  ZCL_HA_DEVICEID_ON_OFF_SWITCH:
						case  ZCL_HA_DEVICEID_DOOR_LOCK:
							blobmsg_add_u8(&b,"on",scene[index].sceneMember[i].deviceState.onoffState.status);
							break;
						case ZCL_HA_DEVICEID_WINDOW_COVERING_DEVICE:
							blobmsg_add_u32(&b,"pt",scene[index].sceneMember[i].deviceState.percentage.percentage);
							break;
						default:
						{
							debug(DEBUG_ERROR,"unsupport device\n");
					    	//blobmsg_add_string(&b,"id","unsupprot device");
						  	break;
						}
					}
    			}
				else if(scene[index].sceneMember[i].deviceBasic.profileId == ZLL_PROFILE_ID)
				{
	    			switch(scene[index].sceneMember[i].deviceBasic.deviceId)
					{
			      		case  ZLL_DEVICEID_COLOR_LIGHT:
				      	case  ZLL_DEVICEID_EXTENDED_COLOR_LIGHT:
				      	case  ZLL_DEVICEID_DIMMABLE_LIGHT:
				    	case  ZLL_DEVICEID_COLOR_TEMPERATURE_LIGHT:
				    		blobmsg_add_u8(&b,"on",scene[index].sceneMember[i].deviceState.lightState.on);
				    		blobmsg_add_u32(&b,"bri",scene[index].sceneMember[i].deviceState.lightState.bri);
				    		blobmsg_add_u32(&b,"hue",scene[index].sceneMember[i].deviceState.lightState.hue);
				    		blobmsg_add_u32(&b,"sat",scene[index].sceneMember[i].deviceState.lightState.sat);
					    	blobmsg_add_u32(&b,"ctp",scene[index].sceneMember[i].deviceState.lightState.colortemp);
					    	break;
					    default:
						{
							debug(DEBUG_ERROR,"unsupport device\n");
					    	//blobmsg_add_string(&b,"id","unsupprot device");
					  		break;
						}
			  		}
          		}
	
				blobmsg_close_table(&b,e1); 
			}
			blobmsg_close_array(&b,ll);

			attribute = blobmsg_open_array(&b,"attribute");
			attribute_members = blobmsg_open_table(&b,NULL);
			blobmsg_close_table(&b,attribute_members);
			blobmsg_close_array(&b,attribute);
 
			blobmsg_close_table(&b,e);
		}
		blobmsg_close_array(&b,l);
		ubus_send_reply(ctx, req, b.head);
	}
	return UBUS_STATUS_OK;
}

int zha_scene_delete(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	int result = UBUS_STATUS_OK;
	uint8_t sceneId;
	struct blob_attr *tb[__RULE_ATTR_MAX];
	unsigned char group_value[9] = {0};

	blobmsg_parse(rule_attrs, __RULE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if(tb[SCENE_ATTR_ID])
	{
		sceneId = blobmsg_get_u32(tb[SCENE_ATTR_ID]);
		if(scene_del(sceneId) ==ZSUCCESS)
		{
      		result = UBUS_STATUS_OK;
			group_value[0] = group_value[0] | (0x01 << 2);
			group_value[3] = sceneId;
#ifndef DISABLE_REPORT

			cloud_scene_state_del_callback(&node_info,group_value);
#endif
#ifndef	DISABLE_LOCAL_NOTIFY

			change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
			change_info.flag = SCENE_DEL_ADD;
			change_info.device_info = NULL;
			change_info.group_info = NULL;
			change_info.scene_info = NULL;
			change_info.rule_info = NULL;
			local_notify(&change_info,client_head);
#endif
	    }
		else
		{
	      	result = UBUS_STATUS_INVALID_ARGUMENT;
	    }
	}
	return result;
}


static int zha_time_exp_to_struct(char * time_exp,struct shuncom_tm * time)
{
	char *p_tmp = NULL;
	char *p_year = NULL;
	char *p_month = NULL;
	char *p_day = NULL;
	char *p_hour = NULL;
	char *p_min = NULL;
	char *p_sec = NULL;
	char *p_wday = NULL;
	int i = 0;
	int time_exp_len = 0;
	char flag[] = "-";
	int flag_count = 0;

	if(!time_exp)
	{
		debug(DEBUG_ERROR,"time_exp error");
		return 0;
	}
	time_exp_len = strlen(time_exp);
	if((time_exp_len > 50)||(time_exp_len <= 0))
	{
		debug(DEBUG_ERROR,"time_exp_len[%d] error",time_exp_len);
		return 0;
	}

	for(i = 0;i < time_exp_len;i++)
	{
		if(time_exp[i] == '-')
			flag_count = flag_count + 1;
	}
	if(flag_count != 6)
	{
		debug(DEBUG_ERROR,"flag_count[%d] error",flag_count);
		return 0;
	}

	debug(DEBUG_GENERAL,"time_exp[%s]",time_exp);

	p_year = time_exp;
	p_tmp = strstr(p_year,flag);
	if(p_tmp)
	{
		p_tmp[0] = '\0';
		p_tmp = p_tmp + 1;
		if(p_tmp[0] == '\0')
		{
			debug(DEBUG_ERROR,"time_exp_len formate error");
			return 0;
		}
		if(p_year[0] == '#')
		{
			time->tm_year = 0xffff;
		}
		else
		{
			time->tm_year = atoi(p_year) - 1900;
			debug(DEBUG_GENERAL,"atoi(p_year)[%d] atoi(p_year) - 1900[%d]",atoi(p_year),atoi(p_year) - 1900);
		}
		debug(DEBUG_GENERAL,"time->tm_year[%d]",time->tm_year);
	}
	else
	{
		debug(DEBUG_ERROR,"p_year error");
		return 0;
	}
	debug(DEBUG_GENERAL,"p_tmp[%s]",p_tmp);
	
	p_month = p_tmp;
	p_tmp = NULL;
	p_tmp = strstr(p_month,flag);
	if(p_tmp)
	{
		p_tmp[0] = '\0';
		p_tmp = p_tmp + 1;
		if(p_tmp[0] == '\0')
		{
			debug(DEBUG_ERROR,"time_exp_len formate error");
			return 0;
		}
		if(p_month[0] == '#')
		{
			time->tm_mon = 0xff;
		}
		else
		{
			time->tm_mon = (atoi(p_month)&0xff) - 1;
		}
		debug(DEBUG_GENERAL,"time->tm_mon[%d]",time->tm_mon);
	}
	else
	{
		debug(DEBUG_ERROR,"p_month error");
		return 0;
	}
	debug(DEBUG_GENERAL,"p_tmp[%s]",p_tmp);

	p_day = p_tmp;
	p_tmp = NULL;
	p_tmp = strstr(p_day,flag);
	if(p_tmp)
	{
		p_tmp[0] = '\0';
		p_tmp = p_tmp + 1;
		if(p_tmp[0] == '\0')
		{
			debug(DEBUG_ERROR,"time_exp_len formate error");
			return 0;
		}
		if(p_day[0] == '#')
		{
			time->tm_mday = 0xff;
		}
		else
		{
			time->tm_mday = atoi(p_day)&0xff;
		}
		debug(DEBUG_GENERAL,"time->tm_mday[%d]",time->tm_mday);
	}
	else
	{
		debug(DEBUG_ERROR,"p_day error");
		return 0;
	}
	debug(DEBUG_GENERAL,"p_tmp[%s]",p_tmp);
	
	p_hour = p_tmp;
	p_tmp = NULL;
	p_tmp = strstr(p_hour,flag);
	if(p_tmp)
	{
		p_tmp[0] = '\0';
		p_tmp = p_tmp + 1;
		if(p_tmp[0] == '\0')
		{
			debug(DEBUG_ERROR,"time_exp_len formate error");
			return 0;
		}
		if(p_hour[0] == '#')
		{
			time->tm_hour = 0xff;
		}
		else
		{
			time->tm_hour = atoi(p_hour)&0xff;
		}
		debug(DEBUG_GENERAL,"time->tm_hour[%d]",time->tm_hour);
	}
	else
	{
		debug(DEBUG_ERROR,"p_hour error");
		return 0;
	}
	debug(DEBUG_GENERAL,"p_tmp[%s]",p_tmp);

	p_min = p_tmp;
	p_tmp = NULL;
	p_tmp = strstr(p_min,flag);
	if(p_tmp)
	{
		p_tmp[0] = '\0';
		p_tmp = p_tmp + 1;
		if(p_tmp[0] == '\0')
		{
			debug(DEBUG_ERROR,"time_exp_len formate error");
			return 0;
		}
		if(p_min[0] == '#')
		{
			time->tm_min = 0xff;
		}
		else
		{
			time->tm_min = atoi(p_min)&0xff;
		}
		debug(DEBUG_GENERAL,"time->tm_min[%d]",time->tm_min);
	}
	else
	{
		debug(DEBUG_ERROR,"p_min error");
		return 0;
	}
	debug(DEBUG_GENERAL,"p_tmp[%s]",p_tmp);

	p_sec = p_tmp;
	p_tmp = NULL;
	p_tmp = strstr(p_sec,flag);
	if(p_tmp)
	{
		p_tmp[0] = '\0';
		p_tmp = p_tmp + 1;
		if(p_tmp[0] == '\0')
		{
			debug(DEBUG_ERROR,"time_exp_len formate error");
			return 0;
		}
		if(p_sec[0] == '#')
		{
			time->tm_sec = 0xff;
		}
		else
		{
			time->tm_sec = atoi(p_sec)&0xff;
		}
		debug(DEBUG_GENERAL,"time->tm_sec[%d]",time->tm_sec);
	}
	else
	{
		debug(DEBUG_ERROR,"p_sec error");
		return 0;
	}

	debug(DEBUG_GENERAL,"p_tmp[%s]",p_tmp);
	p_wday = p_tmp;
	for(i = 0;i < strlen(p_wday);i++)
	{
		if(p_wday[i] == '#')
		{
			time->tm_wday = 0x00;
			break;
		}
		else if((p_wday[i] >= '1') && (p_wday[i] <= '9'))
		{
			time->tm_wday = time->tm_wday | (0x01 << (p_wday[i] - '1'));
			debug(DEBUG_GENERAL,"time->tm_wday[%d]",time->tm_wday);
		}
		else if(p_wday[i] == ',')
		{
			continue;
		}
		else
		{
			debug(DEBUG_ERROR,"p_wday formate error");
			return 0;
		}
	}
	debug(DEBUG_GENERAL,"time->tm_wday[%d]",time->tm_wday);

	if(((time->tm_sec > 59)||(time->tm_sec < 0)) && (time->tm_sec != 0xff))
	{
		debug(DEBUG_ERROR,"time->tm_sec[%d] error",time->tm_sec);
		return 0;
	}
	if(((time->tm_min > 59)||(time->tm_min < 0)) && (time->tm_min != 0xff))
	{
		debug(DEBUG_ERROR,"time->tm_min[%d] error",time->tm_min);
		return 0;
	}
	if(((time->tm_hour > 23)||(time->tm_hour < 0)) && (time->tm_hour != 0xff))
	{
		debug(DEBUG_ERROR,"time->tm_hour[%d] error",time->tm_hour);
		return 0;
	}
	if(((time->tm_mday > 31)||(time->tm_mday < 1)) && (time->tm_mday != 0xff))
	{
		debug(DEBUG_ERROR,"time->tm_mday[%d] error",time->tm_mday);
		return 0;
	}
	if(((time->tm_mon > 11)||(time->tm_mon < 0)) && (time->tm_mon != 0xff))
	{
		debug(DEBUG_ERROR,"time->tm_mon[%d] error",time->tm_mon);
		return 0;
	}
	if((time->tm_yday > 365)||(time->tm_yday < 0))
	{
		debug(DEBUG_ERROR,"time->tm_yday[%d] error",time->tm_yday);
		return 0;
	}
	
	return 1;
}

int zha_rule_create(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	rule_conditions_t *condition = NULL;
	rule_conditions_t *tmp_condition = NULL;
	rule_actions_t *action = NULL;
	rule_actions_t *tmp_action = NULL;
	rule_conditions_t *tmp_cond = NULL;
	rule_actions_t *tmp_act = NULL;
	int result = UBUS_STATUS_OK;
	uint8_t i = 0;
	rule_t_t rule_st = {0};
	struct blob_attr *tb[__RULE_ATTR_MAX] = {NULL};
	struct blob_attr *pattr = NULL;
	struct blob_attr * subCondTb[__RULE_ATTR_COND_MAX] = {NULL};
	struct blob_attr * subActTb[__RULE_ATTR_ACT_MAX] = {NULL};
	uint16_t rule_id = 0;
	uint16_t group_id = 0;
	uint32_t value_tmp = 0;
	uint8_t tmp_uint8 = 0;
	struct tm tmp_time = {0};

	blobmsg_parse(rule_attrs, __RULE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
	bzero(&rule_st,sizeof(rule_t_t));
	rule_st.actions = NULL;
	rule_st.conditions = NULL;
	rule_st.conditions_expression = NULL;

	if(tb[RULE_ATTR_NAME])
	{
		if(strlen(blobmsg_get_string(tb[RULE_ATTR_NAME])) < MAX_NAME_LEN)
			strcpy(rule_st.name,blobmsg_get_string(tb[RULE_ATTR_NAME]));
		else
		{
			debug(DEBUG_ERROR,"name len is too large");
			goto END;
		}
	}
	else
	{
		debug(DEBUG_ERROR,"rule name isn't get");
    	goto END;
  	}
	if(tb[RULE_ATTR_STATE])
	{
		rule_st.state = (uint8_t)blobmsg_get_u32(tb[RULE_ATTR_STATE]);
	}
	else
	{
		rule_st.state = 1;
		debug(DEBUG_GENERAL,"rule state isn't get,set 1");
	}


	if(tb[RULE_ATTR_CREATETIME])
	{
		if(!strptime(blobmsg_get_string(tb[RULE_ATTR_CREATETIME]), date_time_format,&(rule_st.create_time)))
		{
			debug(DEBUG_ERROR,"strptime createtime error");
			goto END;
		}
	}
	else
	{
		debug(DEBUG_WARN,"create time isn't get");
	}

	if (tb[RULE_ATTR_LAST_TRIGGERED])
	{
		if(!strptime(blobmsg_get_string(tb[RULE_ATTR_LAST_TRIGGERED]), date_time_format,&(rule_st.last_triggered)))
		{
			debug(DEBUG_ERROR,"strptime createtime error");
			goto END;
		}
	}
	else
	{
		debug(DEBUG_WARN,"last triggered time isn't get");
	}

	if(tb[RULE_ATTR_TRIGGERED_COUNT])
	{
		rule_st.times_triggered = blobmsg_get_u32(tb[RULE_ATTR_TRIGGERED_COUNT]);
	}
	else
	{
		rule_st.times_triggered = 0;
		debug(DEBUG_GENERAL,"triggered count isn't get,set 0");
	}

	if (tb[RULE_ATTR_CONDITION_EXPRESSION])
	{
    	rule_st.conditions_expression = (char *)malloc(strlen(blobmsg_get_string(tb[RULE_ATTR_CONDITION_EXPRESSION]))+1);
		if(rule_st.conditions_expression == NULL)
		{
			debug(DEBUG_ERROR,"rule_st.conditions_expression malloc error");
			goto END;
		}
		memset(rule_st.conditions_expression,0,strlen(blobmsg_get_string(tb[RULE_ATTR_CONDITION_EXPRESSION]))+1);
    	strcpy(rule_st.conditions_expression, blobmsg_get_string(tb[RULE_ATTR_CONDITION_EXPRESSION]));
    	debug(DEBUG_GENERAL,"conditions_expression[%s]",rule_st.conditions_expression);
	}
	else
	{
		debug(DEBUG_ERROR,"condition expression isn't get");
		goto END;
	}


	if(tb[RULE_ATTR_CONDITIONS])
	{
		// free old rule condition
		group_id = blobmsg_len(tb[RULE_ATTR_CONDITIONS]);
		__blob_for_each_attr(pattr, blobmsg_data(tb[RULE_ATTR_CONDITIONS]), group_id)
		{

			blobmsg_parse(rule_cond_attrs, __RULE_ATTR_COND_MAX, subCondTb, blobmsg_data(pattr),(uint32_t)blobmsg_len(pattr));
			
			condition = (rule_conditions_t *)malloc(sizeof(rule_conditions_t));
			if(condition == NULL)
			{
				debug(DEBUG_ERROR,"condition isn't get");
				goto END;
			}
			memset(condition,0,sizeof(rule_conditions_t));
			condition->next = NULL;

			if(subCondTb[RULE_ATTR_COND_INDEX])
			{
				condition->conditionIdx = blobmsg_get_u32(subCondTb[RULE_ATTR_COND_INDEX]); 
				debug(DEBUG_GENERAL,"condition->conditionIdx[%d]",condition->conditionIdx);
			}
			else
			{
				debug(DEBUG_ERROR,"conditionIdx isn't get");
     			goto END;
			}

			if(subCondTb[RULE_ATTR_COND_REPEAT_TIMES])
			{
				condition->times_triggered = blobmsg_get_u32(subCondTb[RULE_ATTR_COND_REPEAT_TIMES]); 
				debug(DEBUG_GENERAL,"condition->times_triggered[%d]",condition->times_triggered);
			}
			else
			{
				debug(DEBUG_ERROR,"condition times_triggered isn't get");
     			goto END;
			}
			
			if(subCondTb[RULE_ATTR_COND_TYPE])
			{
		        condition->cond_type = blobmsg_get_u32(subCondTb[RULE_ATTR_COND_TYPE]);
				if((condition->cond_type != 1)&&(condition->cond_type != 2))
				{
		        	debug(DEBUG_ERROR,"condition type is wrong[%d]",condition->cond_type);
		            goto END;
		        }
			}
			else
			{
			    	debug(DEBUG_ERROR,"condition type isn't get");
		    		goto END;
			}

			switch(condition->cond_type)
			{
				case 1:
				{
					if(subCondTb[RULE_ATTR_COND_ACT_TIME])
					{
						char time_exp[50] = {0};
						int time_exp_len = strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_ACT_TIME]));

						if((time_exp_len > 50) || (time_exp_len <= 0))
						{
							debug(DEBUG_ERROR,"pare time_exp error");
		     				goto END;
						}
						else
						{
							strcpy(time_exp,blobmsg_get_string(subCondTb[RULE_ATTR_COND_ACT_TIME]));
						}

						if(0 == zha_time_exp_to_struct(time_exp,&(condition->rule_cond.act_time)))
						{
							debug(DEBUG_ERROR,"pare time_exp error");
		     				goto END;
						}
						
					}
					else
					{
						debug(DEBUG_ERROR,"condition act time isn't get");
		     			goto END;
					}
					break;
				}
				case 2:
				{
					if(subCondTb[RULE_ATTR_COND_ID])
					{
						sscanf(blobmsg_get_string(subCondTb[RULE_ATTR_COND_ID]), ieee_id,\
							condition->rule_cond.triggered_t.ieeeAddr + 0,\
							condition->rule_cond.triggered_t.ieeeAddr + 1,\
							condition->rule_cond.triggered_t.ieeeAddr + 2,\
							condition->rule_cond.triggered_t.ieeeAddr + 3,\
							condition->rule_cond.triggered_t.ieeeAddr + 4,\
							condition->rule_cond.triggered_t.ieeeAddr + 5,\
							condition->rule_cond.triggered_t.ieeeAddr + 6,\
							condition->rule_cond.triggered_t.ieeeAddr + 7);
					}
					else
					{
						debug(DEBUG_ERROR,"condition ieeeaddr isn't get");
		     			goto END;
					}

					if(subCondTb[RULE_ATTR_COND_EP])
					{
						condition->rule_cond.triggered_t.endpointId= (uint8_t)blobmsg_get_u32(subCondTb[RULE_ATTR_COND_EP]);
					}
					else
					{
						debug(DEBUG_ERROR,"condition endpoint id isn't get");
		     			goto END;
					}

					if(subCondTb[RULE_ATTR_COND_CMD])
					{
						if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"ctp",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"colortemp");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"nlux",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"now_lux");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"llux",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"level_status");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"pt",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"liftpercentage");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"sta",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"status");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"temp",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"temperature");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"humi",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"humidity");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"tlux",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"target_lux");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"voc",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"voc_level");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"zid",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"zoneid");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"type",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"zonetype");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"raw",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"rawdata");
						else
							strcpy(condition->rule_cond.triggered_t.attrName, blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]));
					}
					else
					{
						debug(DEBUG_ERROR,"condition attrName isn't get");
		     			goto END;
					}

					if(subCondTb[RULE_ATTR_COND_OP])
					{
				        if(strcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_OP]),"great") == 0)
						{
							condition->rule_cond.triggered_t.operater_type = 1;
			            }
						else if(strcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_OP]),"equal") == 0)
						{
							condition->rule_cond.triggered_t.operater_type = 0;
			            }
						else if(strcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_OP]),"less") == 0)
						{
							condition->rule_cond.triggered_t.operater_type = -1;
			            }
						else if(strcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_OP]),"change") == 0)
						{
							condition->rule_cond.triggered_t.operater_type = 2;
			            }
						else
						{
							debug(DEBUG_ERROR,"condition option error");
			                goto END;
			            }

					}
					else
					{
						debug(DEBUG_ERROR,"condition option isn't get");
		        		goto END;
					}

					if(subCondTb[RULE_ATTR_COND_VALUE])
					{
						strcpy(condition->rule_cond.triggered_t.value,blobmsg_get_string(subCondTb[RULE_ATTR_COND_VALUE])); 
					}
					else
					{
						debug(DEBUG_ERROR,"condition value isn't get");
		     			goto END;
					}
					break;
				}
			}
			if(rule_st.conditions == NULL)
			{
				rule_st.conditions = condition;
			}
			else
			{
				tmp_condition = rule_st.conditions;
				while(tmp_condition->next)
				{
			  		tmp_condition = tmp_condition->next;
				}
				tmp_condition->next = condition;
			}
			condition = NULL;
		}
	}

	if(tb[RULE_ATTR_ACTIONS])
	{
		// free old rule action
		group_id = blobmsg_len(tb[RULE_ATTR_ACTIONS]);
		__blob_for_each_attr(pattr, blobmsg_data(tb[RULE_ATTR_ACTIONS]), group_id)
		{
			blobmsg_parse(rule_act_attrs, __RULE_ATTR_ACT_MAX, subActTb, blobmsg_data(pattr),(uint32_t)blobmsg_len(pattr));
			
			action = (rule_actions_t *)malloc(sizeof(rule_actions_t));

			if(action == NULL)
			{
				debug(DEBUG_ERROR,"action isn't get");
				goto END;
			}
			memset(action,0,sizeof(rule_actions_t));
			action->next = NULL;

			if(subActTb[RULE_ATTR_ACT_INDEX])
			{
				action->actionIdx = blobmsg_get_u32(subActTb[RULE_ATTR_ACT_INDEX]); 
				debug(DEBUG_GENERAL,"action->actionIdx[%d]",action->actionIdx);
			}
			else
			{
				debug(DEBUG_ERROR,"actionIdx isn't get");
     			goto END;
			}
			
			if(subActTb[RULE_ATTR_ACT_DELAY_TIMEOUT])
			{
				action->delay_timeout = blobmsg_get_u32(subActTb[RULE_ATTR_ACT_DELAY_TIMEOUT]); 
				debug(DEBUG_GENERAL,"action->delay_timeout[%d]",action->delay_timeout);
			}
			else
			{
				debug(DEBUG_ERROR,"delay_timeout isn't get");
     			goto END;
			}
					
			if(subActTb[RULE_ATTR_ACT_TARGET_TYPE])
			{
				action->target_type = (uint8_t)blobmsg_get_u32(subActTb[RULE_ATTR_ACT_TARGET_TYPE]);
				debug(DEBUG_GENERAL,"action->target_type[%d]",action->target_type);
				if(action->target_type == 1)//device
				{
					if(subActTb[RULE_ATTR_ACT_IEEEADDR])
					{
						sscanf(blobmsg_get_string(subActTb[RULE_ATTR_ACT_IEEEADDR]), ieee_id,\
							action->target_id.ieeeAddr + 0,\
							action->target_id.ieeeAddr + 1,\
							action->target_id.ieeeAddr + 2,\
							action->target_id.ieeeAddr + 3,\
							action->target_id.ieeeAddr + 4,\
							action->target_id.ieeeAddr + 5,\
							action->target_id.ieeeAddr + 6,\
							action->target_id.ieeeAddr + 7);
					}
					else
					{
						debug(DEBUG_ERROR,"action ieeeaddr isn't get");
		     			goto END;
					}
				}
				else if(action->target_type == 2)//group
				{
					if(subActTb[RULE_ATTR_ACT_GROUP_ID])
					{
						action->target_id.nwkAddr = (uint16_t)blobmsg_get_u32(subActTb[RULE_ATTR_ACT_GROUP_ID]);
					}
					else
					{
						debug(DEBUG_ERROR,"action group_id isn't get");
		     			goto END;
					}
				}
				else if(action->target_type == 3)//scene
				{
					
					if(subActTb[RULE_ATTR_ACT_SCENE_ID])
					{
						action->target_id.scene_id = (uint8_t)blobmsg_get_u32(subActTb[RULE_ATTR_ACT_SCENE_ID]);
					}
					else
					{
						debug(DEBUG_ERROR,"action scene_id isn't get");
		     			goto END;
					}
				}
				else
				{
					debug(DEBUG_ERROR,"action target_type error");
		     		goto END;
				}
			}
			else
			{
				debug(DEBUG_ERROR,"action target_type isn't get");
				goto END;
			}

			if (subActTb[RULE_ATTR_ACT_ENDPOINT_ID])
			{
				action->target_ep = (uint8_t)blobmsg_get_u32(subActTb[RULE_ATTR_ACT_ENDPOINT_ID]);
			}
			else
			{
				debug(DEBUG_GENERAL,"action target_ep isn't get");
			}

			if(subActTb[RULE_ATTR_ACT_CMD])
			{
				if(subActTb[RULE_ATTR_ACT_VALUE])
				{
					if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"on",strlen("on")) == 0)
					{
						strcpy(action->attrName,blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]));
						strcpy(action->value,blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE]));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"scene",strlen("scene")) == 0)
					{
						strcpy(action->attrName,blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]));
						if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE]),"store",strlen("store")) == 0)
							strcpy(action->value,"store");
						else
							strcpy(action->value,"recall");
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"pt",strlen("pt")) == 0)
					{
						strcpy(action->attrName,"liftpercentage");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if((0 == memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"bri",strlen("bri")))\
						|| (0 == memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"hue",strlen("hue")))\
						|| (0 == memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"sat",strlen("sat")))\
						|| (0 == memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"ctp",strlen("ctp"))))
					{
						if(0 == memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"ctp",strlen("ctp")))
							strcpy(action->attrName,"colortemp");
						else
							strcpy(action->attrName,blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]));	
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"raw",strlen("raw")) == 0)
					{
						strcpy(action->attrName,"rawdata");
						strcpy(action->value,blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE]));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"inle",strlen("inle")) == 0)
					{
						strcpy(action->attrName,"infraredlearn");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"inct",strlen("inct")) == 0)
					{
						strcpy(action->attrName,"infraredcontrol");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"incd",strlen("incd")) == 0)
					{
						strcpy(action->attrName,"infraredcode");
						strcpy(action->value,blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE]));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"ctrl",strlen("ctrl")) == 0)
					{
						if(atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])) == 0)
							strcpy(action->attrName,"downclose");
						else if(atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])) == 1)
							strcpy(action->attrName,"upopen");
						else
							strcpy(action->attrName,"stop");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"nlux",strlen("nlux")) == 0)
					{
						strcpy(action->attrName,"now_lux");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"llux",strlen("llux")) == 0)
					{
						strcpy(action->attrName,"level_status");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"sta",strlen("sta")) == 0)
					{
						strcpy(action->attrName,"status");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"temp",strlen("temp")) == 0)
					{
						strcpy(action->attrName,"temperature");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"humi",strlen("humi")) == 0)
					{
						strcpy(action->attrName,"humidity");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"tlux",strlen("tlux")) == 0)
					{
						strcpy(action->attrName,"target_lux");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"voc",strlen("voc")) == 0)
					{
						strcpy(action->attrName,"voc_level");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"zid",strlen("zid")) == 0)
					{
						strcpy(action->attrName,"zoneid");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"type",strlen("type")) == 0)
					{
						strcpy(action->attrName,"zonetype");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else
					{
						strcpy(action->attrName,blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]));
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
				}
				else
				{
					debug(DEBUG_ERROR,"action val null");
					goto END;
				}
			}
			else
			{
				debug(DEBUG_ERROR,"action cmd null");
				goto END;
			}
			if(rule_st.actions == NULL)
			{
				rule_st.actions = action;
			}
			else
			{
				tmp_action = rule_st.actions;
				while(tmp_action->next)
				{
					tmp_action = tmp_action->next;
				}
				tmp_action->next = action;
			}
			action = NULL;
		}
	}
#if 0
	debug(DEBUG_GENERAL,"rule_st.name[%s]",rule_st.name);
	debug(DEBUG_GENERAL,"rule_st.id[%d]",rule_st.id);
	debug(DEBUG_GENERAL,"rule_st.state[%d]",rule_st.state);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_sec[%d]",rule_st.create_time.tm_sec);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_min[%d]",rule_st.create_time.tm_min);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_hour[%d]",rule_st.create_time.tm_hour);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_mday[%d]",rule_st.create_time.tm_mday);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_mon[%d]",rule_st.create_time.tm_mon);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_year[%d]",rule_st.create_time.tm_year);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_wday[%d]",rule_st.create_time.tm_wday);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_yday[%d]",rule_st.create_time.tm_yday);

	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_sec[%d]",rule_st.last_triggered.tm_sec);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_min[%d]",rule_st.last_triggered.tm_min);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_hour[%d]",rule_st.last_triggered.tm_hour);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_mday[%d]",rule_st.last_triggered.tm_mday);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_mon[%d]",rule_st.last_triggered.tm_mon);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_year[%d]",rule_st.last_triggered.tm_year);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_wday[%d]",rule_st.last_triggered.tm_wday);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_yday[%d]",rule_st.last_triggered.tm_yday);
	
	debug(DEBUG_GENERAL,"rule_st.times_triggered[%d]",rule_st.times_triggered);
	debug(DEBUG_GENERAL,"rule_st.conditions_expression[%s]",rule_st.conditions_expression);

	rule_conditions_t *cond_tmp = rule_st.conditions;
	for(cond_tmp;cond_tmp != NULL;cond_tmp = cond_tmp->next)
	{
		debug(DEBUG_GENERAL,"cond_tmp->conditionIdx[%d]",cond_tmp->conditionIdx);
		debug(DEBUG_GENERAL,"cond_tmp->cond_type[%d]",cond_tmp->cond_type);
		
		if(cond_tmp->cond_type == 1)
		{
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_sec[%d]",cond_tmp->rule_cond.act_time.tm_sec);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_min[%d]",cond_tmp->rule_cond.act_time.tm_min);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_hour[%d]",cond_tmp->rule_cond.act_time.tm_hour);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_mday[%d]",cond_tmp->rule_cond.act_time.tm_mday);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_mon[%d]",cond_tmp->rule_cond.act_time.tm_mon);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_year[%d]",cond_tmp->rule_cond.act_time.tm_year);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_wday[%d]",cond_tmp->rule_cond.act_time.tm_wday);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_yday[%d]",cond_tmp->rule_cond.act_time.tm_yday);
		}
		else if(cond_tmp->cond_type == 2)
		{
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.ieeeAddr[%02x%02x%02x%02x%02x%02x%02x%02x]\n",\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[0],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[1],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[2],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[3],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[4],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[5],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[6],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[7]);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.endpointId[%d]",cond_tmp->rule_cond.triggered_t.endpointId);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.operater_type[%d]",cond_tmp->rule_cond.triggered_t.operater_type);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.attrName[%s]",cond_tmp->rule_cond.triggered_t.attrName);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.value[%s]",cond_tmp->rule_cond.triggered_t.value);
		}
		else
		{
			debug(DEBUG_GENERAL,"error cond_type[%d]",cond_tmp->cond_type);
		}
	}

	rule_actions_t *act_tmp = rule_st.actions;
	for(act_tmp;act_tmp != NULL;act_tmp = act_tmp->next)
	{
		debug(DEBUG_GENERAL,"act_tmp->actionIdx[%d]",act_tmp->actionIdx);
		debug(DEBUG_GENERAL,"act_tmp->delay_timeout[%d]",act_tmp->delay_timeout);
		debug(DEBUG_GENERAL,"act_tmp->target_type[%d]",act_tmp->target_type);
		if(act_tmp->target_type == 1)
		{
			debug(DEBUG_GENERAL,"act_tmp->target_id.ieeeAddr[%02x%02x%02x%02x%02x%02x%02x%02x]\n",\
				act_tmp->target_id.ieeeAddr[0],\
				act_tmp->target_id.ieeeAddr[1],\
				act_tmp->target_id.ieeeAddr[2],\
				act_tmp->target_id.ieeeAddr[3],\
				act_tmp->target_id.ieeeAddr[4],\
				act_tmp->target_id.ieeeAddr[5],\
				act_tmp->target_id.ieeeAddr[6],\
				act_tmp->target_id.ieeeAddr[7]);
		}
		else if(act_tmp->target_type == 2)
		{
			debug(DEBUG_GENERAL,"act_tmp->target_id.nwkAddr[%d]",act_tmp->target_id.nwkAddr);
		}
		else if(act_tmp->target_type == 3)
		{
			debug(DEBUG_GENERAL,"act_tmp->target_id.scene_id[%d]",act_tmp->target_id.scene_id);
		}
		debug(DEBUG_GENERAL,"act_tmp->endpointId[%d]",act_tmp->target_ep);
		debug(DEBUG_GENERAL,"act_tmp->attrName[%s]",act_tmp->attrName);
		debug(DEBUG_GENERAL,"act_tmp->value[%s]",act_tmp->value);
	}
#endif	
	rule_id = rule_create(&rule_st);
	debug(DEBUG_GENERAL,"rule_id[%d]",rule_id);
   	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b,"id",rule_id);
    ubus_send_reply(ctx, req, b.head);
	if(rule_id > 0)
	{
#ifndef DISABLE_REPORT
		extern node_info_s node_info;
		unsigned short int group_id = rule_id;

		cloud_rule_state_create_callback(&node_info,group_id,rule_st);
#endif
#ifndef	DISABLE_LOCAL_NOTIFY
		change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
		change_info.flag = RULE_DEL_ADD;
		change_info.device_info = NULL;
		change_info.group_info = NULL;
		change_info.scene_info = NULL;
		change_info.rule_info = NULL;
		local_notify(&change_info,client_head);
#endif
		return UBUS_STATUS_OK;
	}
	else
		return UBUS_STATUS_INVALID_ARGUMENT;
END:
	if(rule_st.conditions_expression)
	{
		free(rule_st.conditions_expression);
		rule_st.conditions_expression = NULL;
		debug(DEBUG_GENERAL,"free cond_exp");
	}
	if(condition != NULL)
	{
		free(condition);
		condition = NULL;
		debug(DEBUG_GENERAL,"free condition");
	}
	if(action != NULL)
	{
		free(action);
		action = NULL;
		debug(DEBUG_GENERAL,"free action");
	}
	
	tmp_condition = NULL;
	tmp_action = NULL;
	tmp_condition = rule_st.conditions;
	while(tmp_condition)
	{
		tmp_cond = tmp_condition->next;
		free(tmp_condition);
		tmp_condition = tmp_cond;
		debug(DEBUG_GENERAL,"free tmp_condition->next");
	}
	
	tmp_action = rule_st.actions;
	while(tmp_action)
	{
		tmp_act = tmp_action->next;
		free(tmp_action);
		tmp_action = tmp_act;
		debug(DEBUG_GENERAL,"free tmp_action->next");
	}
	return UBUS_STATUS_INVALID_ARGUMENT;
}


int zha_rule_change(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	rule_t_t *rule = NULL;
	rule_t_t *qRule = NULL;
	rule_conditions_t *condition = NULL;
	rule_conditions_t *tmp_condition = NULL;
	rule_conditions_t *tmp_cond = NULL;
	rule_actions_t *tmp_act = NULL;
	rule_actions_t *action = NULL;
	rule_actions_t *tmp_action = NULL;
	int result = UBUS_STATUS_OK;
	uint8_t i = 0;
	rule_t_t rule_st = {0};
	struct blob_attr *tb[__RULE_ATTR_MAX] = {NULL};
	struct blob_attr *pattr = NULL;
	struct blob_attr * subCondTb[__RULE_ATTR_COND_MAX] = {NULL};
	struct blob_attr * subActTb[__RULE_ATTR_ACT_MAX] = {NULL};
	uint16_t rule_id = 0;
	uint16_t group_id = 0;
	uint32_t value_tmp = 0;
	uint8_t tmp_uint8 = 0;
	struct tm tmp_time = {0};
	int change_flag = 0;

	blobmsg_parse(rule_attrs, __RULE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
	bzero(&rule_st,sizeof(rule_t_t));
	rule_st.actions = NULL;
	rule_st.conditions = NULL;
	rule_st.conditions_expression = NULL;

	if(tb[RULE_ATTR_ID])
	{
		rule_st.id = (uint8_t)blobmsg_get_u32(tb[RULE_ATTR_ID]);
		rule_id = rule_st.id;
	}
	else
	{
		debug(DEBUG_ERROR,"rule id isn't get");
    	goto END;
	}
	
	if(tb[RULE_ATTR_NAME])
	{
		if(strlen(blobmsg_get_string(tb[RULE_ATTR_NAME])) < MAX_NAME_LEN)
			strcpy(rule_st.name,blobmsg_get_string(tb[RULE_ATTR_NAME]));
		else
		{
			debug(DEBUG_ERROR,"name len is too large");
			goto END;
		}
	}
	else
	{
		debug(DEBUG_ERROR,"rule name isn't get");
    	goto END;
  	}
	if(tb[RULE_ATTR_STATE])
	{
		rule_st.state = (uint8_t)blobmsg_get_u32(tb[RULE_ATTR_STATE]);
	}
	else
	{
		rule_st.state = 1;
		debug(DEBUG_GENERAL,"rule state isn't get,set 1");
	}


	if(tb[RULE_ATTR_CREATETIME])
	{
		if(!strptime(blobmsg_get_string(tb[RULE_ATTR_CREATETIME]), date_time_format,&rule_st.create_time))
		{
			debug(DEBUG_ERROR,"strptime createtime error");
			goto END;
		}
	}
	else
	{
		debug(DEBUG_GENERAL,"create time isn't get");
	}

	if (tb[RULE_ATTR_LAST_TRIGGERED])
	{
		if(!strptime(blobmsg_get_string(tb[RULE_ATTR_LAST_TRIGGERED]), date_time_format,&rule_st.last_triggered))
		{
			debug(DEBUG_ERROR,"strptime createtime error");
			goto END;
		}
	}
	else
	{
		debug(DEBUG_GENERAL,"last triggered time isn't get");
	}

	if(tb[RULE_ATTR_TRIGGERED_COUNT])
	{
		rule_st.times_triggered = blobmsg_get_u32(tb[RULE_ATTR_TRIGGERED_COUNT]);
	}
	else
	{
		rule_st.times_triggered = 0;
		debug(DEBUG_GENERAL,"triggered count isn't get,set 0");
	}

	if (tb[RULE_ATTR_CONDITION_EXPRESSION])
	{
    	rule_st.conditions_expression = (char *)malloc(strlen(blobmsg_get_string(tb[RULE_ATTR_CONDITION_EXPRESSION]))+1);
		if(rule_st.conditions_expression == NULL)
		{
			debug(DEBUG_ERROR,"rule_st.conditions_expression malloc error");
			goto END;
		}
		memset(rule_st.conditions_expression,0,strlen(blobmsg_get_string(tb[RULE_ATTR_CONDITION_EXPRESSION]))+1);
    	strcpy(rule_st.conditions_expression, blobmsg_get_string(tb[RULE_ATTR_CONDITION_EXPRESSION]));
    	debug(DEBUG_GENERAL,"conditions_expression[%s]",rule_st.conditions_expression);
	}
	else
	{
		debug(DEBUG_ERROR,"condition expression isn't get");
		goto END;
	}


	if(tb[RULE_ATTR_CONDITIONS])
	{
		// free old rule condition
		group_id = blobmsg_len(tb[RULE_ATTR_CONDITIONS]);
		__blob_for_each_attr(pattr, blobmsg_data(tb[RULE_ATTR_CONDITIONS]), group_id)
		{

			blobmsg_parse(rule_cond_attrs, __RULE_ATTR_COND_MAX, subCondTb, blobmsg_data(pattr),(uint32_t)blobmsg_len(pattr));
			condition = (rule_conditions_t *)malloc(sizeof(rule_conditions_t));
			if(condition == NULL)
			{
				debug(DEBUG_ERROR,"condition isn't get");
				goto END;
			}
			memset(condition,0,sizeof(rule_conditions_t));
			condition->next = NULL;

			if(subCondTb[RULE_ATTR_COND_INDEX])
			{
				condition->conditionIdx = blobmsg_get_u32(subCondTb[RULE_ATTR_COND_INDEX]); 
				debug(DEBUG_GENERAL,"condition->conditionIdx[%d]",condition->conditionIdx);
			}
			else
			{
				debug(DEBUG_ERROR,"conditionIdx isn't get");
     			goto END;
			}

			if(subCondTb[RULE_ATTR_COND_REPEAT_TIMES])
			{
				condition->times_triggered = blobmsg_get_u32(subCondTb[RULE_ATTR_COND_REPEAT_TIMES]); 
				debug(DEBUG_GENERAL,"condition->times_triggered[%d]",condition->times_triggered);
			}
			else
			{
				debug(DEBUG_ERROR,"condition times_triggered isn't get");
     			goto END;
			}
			
			if(subCondTb[RULE_ATTR_COND_TYPE])
			{
		        condition->cond_type = blobmsg_get_u32(subCondTb[RULE_ATTR_COND_TYPE]);
				if((condition->cond_type != 1)&&(condition->cond_type != 2))
				{
		        	debug(DEBUG_ERROR,"condition type is wrong[%d]",condition->cond_type);
		            goto END;
		        }
			}
			else
			{
			    	debug(DEBUG_ERROR,"condition type isn't get");
		    		goto END;
			}

			switch(condition->cond_type)
			{
				case 1:
				{
					if(subCondTb[RULE_ATTR_COND_ACT_TIME])
					{
						char time_exp[50] = {0};
						int time_exp_len = strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_ACT_TIME]));

						if((time_exp_len > 50) || (time_exp_len <= 0))
						{
							debug(DEBUG_ERROR,"pare time_exp error");
		     				goto END;
						}
						else
						{
							strcpy(time_exp,blobmsg_get_string(subCondTb[RULE_ATTR_COND_ACT_TIME]));
						}

						if(0 == zha_time_exp_to_struct(time_exp,&(condition->rule_cond.act_time)))
						{
							debug(DEBUG_ERROR,"pare time_exp error");
		     				goto END;
						}
						
					}
					else
					{
						debug(DEBUG_ERROR,"condition act time isn't get");
		     			goto END;
					}
					break;
				}
				case 2:
				{
					if(subCondTb[RULE_ATTR_COND_ID])
					{
						sscanf(blobmsg_get_string(subCondTb[RULE_ATTR_COND_ID]), ieee_id,\
							condition->rule_cond.triggered_t.ieeeAddr + 0,\
							condition->rule_cond.triggered_t.ieeeAddr + 1,\
							condition->rule_cond.triggered_t.ieeeAddr + 2,\
							condition->rule_cond.triggered_t.ieeeAddr + 3,\
							condition->rule_cond.triggered_t.ieeeAddr + 4,\
							condition->rule_cond.triggered_t.ieeeAddr + 5,\
							condition->rule_cond.triggered_t.ieeeAddr + 6,\
							condition->rule_cond.triggered_t.ieeeAddr + 7);
					}
					else
					{
						debug(DEBUG_ERROR,"condition ieeeaddr isn't get");
		     			goto END;
					}

					if(subCondTb[RULE_ATTR_COND_EP])
					{
						condition->rule_cond.triggered_t.endpointId= (uint8_t)blobmsg_get_u32(subCondTb[RULE_ATTR_COND_EP]);
					}
					else
					{
						debug(DEBUG_ERROR,"condition endpoint id isn't get");
		     			goto END;
					}

					if(subCondTb[RULE_ATTR_COND_CMD])
					{
						if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"ctp",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"colortemp");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"nlux",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"now_lux");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"llux",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"level_status");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"pt",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"liftpercentage");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"sta",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"status");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"temp",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"temperature");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"humi",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"humidity");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"tlux",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"target_lux");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"voc",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"voc_level");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"zid",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"zoneid");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"type",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"zonetype");
						else if(memcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]),"raw",strlen(blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]))) == 0)
							strcpy(condition->rule_cond.triggered_t.attrName,"rawdata");
						else
							strcpy(condition->rule_cond.triggered_t.attrName, blobmsg_get_string(subCondTb[RULE_ATTR_COND_CMD]));
					}
					else
					{
						debug(DEBUG_ERROR,"condition attrName isn't get");
		     			goto END;
					}

					if(subCondTb[RULE_ATTR_COND_OP])
					{
				        if(strcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_OP]),"great") == 0)
						{
							condition->rule_cond.triggered_t.operater_type = 1;
			            }
						else if(strcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_OP]),"equal") == 0)
						{
							condition->rule_cond.triggered_t.operater_type = 0;
			            }
						else if(strcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_OP]),"less") == 0)
						{
							condition->rule_cond.triggered_t.operater_type = -1;
			            }
						else if(strcmp(blobmsg_get_string(subCondTb[RULE_ATTR_COND_OP]),"change") == 0)
						{
							condition->rule_cond.triggered_t.operater_type = 2;
			            }
						else
						{
							debug(DEBUG_ERROR,"condition option error");
			                goto END;
			            }

					}
					else
					{
						debug(DEBUG_ERROR,"condition option isn't get");
		        		goto END;
					}

					if(subCondTb[RULE_ATTR_COND_VALUE])
					{
						strcpy(condition->rule_cond.triggered_t.value,
		           		blobmsg_get_string(subCondTb[RULE_ATTR_COND_VALUE])); 
					}
					else
					{
						debug(DEBUG_ERROR,"condition value isn't get");
		     			goto END;
					}
					break;
				}
			}
			if(rule_st.conditions == NULL)
			{
				rule_st.conditions = condition;
			}
			else
			{
				tmp_condition = rule_st.conditions;
				while(tmp_condition->next)
				{
			  		tmp_condition = tmp_condition->next;
				}
				tmp_condition->next = condition;
			}
			condition = NULL;
		}
	}

	if(tb[RULE_ATTR_ACTIONS])
	{
		// free old rule action
		group_id = blobmsg_len(tb[RULE_ATTR_ACTIONS]);
		__blob_for_each_attr(pattr, blobmsg_data(tb[RULE_ATTR_ACTIONS]), group_id)
		{
			blobmsg_parse(rule_act_attrs, __RULE_ATTR_ACT_MAX, subActTb, blobmsg_data(pattr),(uint32_t)blobmsg_len(pattr));
			action = (rule_actions_t *)malloc(sizeof(rule_actions_t));

			if(action == NULL)
			{
				debug(DEBUG_ERROR,"action isn't get");
				goto END;
			}
			memset(action,0,sizeof(rule_actions_t));
			action->next = NULL;

			if(subActTb[RULE_ATTR_ACT_INDEX])
			{
				action->actionIdx = blobmsg_get_u32(subActTb[RULE_ATTR_ACT_INDEX]); 
				debug(DEBUG_GENERAL,"action->actionIdx[%d]",action->actionIdx);
			}
			else
			{
				debug(DEBUG_ERROR,"actionIdx isn't get");
     			goto END;
			}
			
			if(subActTb[RULE_ATTR_ACT_DELAY_TIMEOUT])
			{
				action->delay_timeout = blobmsg_get_u32(subActTb[RULE_ATTR_ACT_DELAY_TIMEOUT]); 
				debug(DEBUG_GENERAL,"action->delay_timeout[%d]",action->delay_timeout);
			}
			else
			{
				debug(DEBUG_ERROR,"delay_timeout isn't get");
     			goto END;
			}
					
			if(subActTb[RULE_ATTR_ACT_TARGET_TYPE])
			{
				action->target_type = (uint8_t)blobmsg_get_u32(subActTb[RULE_ATTR_ACT_TARGET_TYPE]);
				debug(DEBUG_GENERAL,"action->target_type[%d]",action->target_type);
				if(action->target_type == 1)//device
				{
					if(subActTb[RULE_ATTR_ACT_IEEEADDR])
					{
						sscanf(blobmsg_get_string(subActTb[RULE_ATTR_ACT_IEEEADDR]), ieee_id,\
							action->target_id.ieeeAddr + 0,\
							action->target_id.ieeeAddr + 1,\
							action->target_id.ieeeAddr + 2,\
							action->target_id.ieeeAddr + 3,\
							action->target_id.ieeeAddr + 4,\
							action->target_id.ieeeAddr + 5,\
							action->target_id.ieeeAddr + 6,\
							action->target_id.ieeeAddr + 7);
					}
					else
					{
						debug(DEBUG_ERROR,"action ieeeaddr isn't get");
		     			goto END;
					}
				}
				else if(action->target_type == 2)//group
				{
					if(subActTb[RULE_ATTR_ACT_GROUP_ID])
					{
						action->target_id.nwkAddr = (uint16_t)blobmsg_get_u32(subActTb[RULE_ATTR_ACT_GROUP_ID]);
					}
					else
					{
						debug(DEBUG_ERROR,"action group_id isn't get");
		     			goto END;
					}
				}
				else if(action->target_type == 3)//scene
				{
					
					if(subActTb[RULE_ATTR_ACT_SCENE_ID])
					{
						action->target_id.scene_id = (uint8_t)blobmsg_get_u32(subActTb[RULE_ATTR_ACT_SCENE_ID]);
					}
					else
					{
						debug(DEBUG_ERROR,"action scene_id isn't get");
		     			goto END;
					}
				}
				else
				{
					debug(DEBUG_ERROR,"action target_type error");
		     		goto END;
				}
			}
			else
			{
				debug(DEBUG_ERROR,"action target_type isn't get");
				goto END;
			}

			if (subActTb[RULE_ATTR_ACT_ENDPOINT_ID])
			{
				action->target_ep = (uint8_t)blobmsg_get_u32(subActTb[RULE_ATTR_ACT_ENDPOINT_ID]);
			}
			else
			{
				debug(DEBUG_GENERAL,"action target_ep isn't get");
			}
			if(subActTb[RULE_ATTR_ACT_CMD])
			{
				if(subActTb[RULE_ATTR_ACT_VALUE])
				{
					if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"on",strlen("on")) == 0)
					{
						strcpy(action->attrName,blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]));
						strcpy(action->value,blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE]));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"scene",strlen("scene")) == 0)
					{
						strcpy(action->attrName,blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]));
						if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE]),"store",strlen("store")) == 0)
							strcpy(action->value,"store");
						else
							strcpy(action->value,"recall");
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"pt",strlen("pt")) == 0)
					{
						strcpy(action->attrName,"liftpercentage");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if((0 == memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"bri",strlen("bri")))\
						|| (0 == memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"hue",strlen("hue")))\
						|| (0 == memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"sat",strlen("sat")))\
						|| (0 == memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"ctp",strlen("ctp"))))
					{
						if(0 == memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"ctp",strlen("ctp")))
							strcpy(action->attrName,"colortemp");
						else
							strcpy(action->attrName,blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]));	
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"raw",strlen("raw")) == 0)
					{
						strcpy(action->attrName,"rawdata");
						strcpy(action->value,blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE]));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"inle",strlen("inle")) == 0)
					{
						strcpy(action->attrName,"infraredlearn");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"inct",strlen("inct")) == 0)
					{
						strcpy(action->attrName,"infraredcontrol");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"incd",strlen("incd")) == 0)
					{
						strcpy(action->attrName,"infraredcode");
						strcpy(action->value,blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE]));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"ctrl",strlen("ctrl")) == 0)
					{
						if(atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])) == 0)
							strcpy(action->attrName,"downclose");
						else if(atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])) == 1)
							strcpy(action->attrName,"upopen");
						else
							strcpy(action->attrName,"stop");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"nlux",strlen("nlux")) == 0)
					{
						strcpy(action->attrName,"now_lux");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"llux",strlen("llux")) == 0)
					{
						strcpy(action->attrName,"level_status");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"sta",strlen("sta")) == 0)
					{
						strcpy(action->attrName,"status");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"temp",strlen("temp")) == 0)
					{
						strcpy(action->attrName,"temperature");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"humi",strlen("humi")) == 0)
					{
						strcpy(action->attrName,"humidity");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"tlux",strlen("tlux")) == 0)
					{
						strcpy(action->attrName,"target_lux");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"voc",strlen("voc")) == 0)
					{
						strcpy(action->attrName,"voc_level");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"zid",strlen("zid")) == 0)
					{
						strcpy(action->attrName,"zoneid");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else if(memcmp(blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]),"type",strlen("type")) == 0)
					{
						strcpy(action->attrName,"zonetype");
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
					else
					{
						strcpy(action->attrName,blobmsg_get_string(subActTb[RULE_ATTR_ACT_CMD]));
						sprintf(action->value,"%d",atoi(blobmsg_get_string(subActTb[RULE_ATTR_ACT_VALUE])));
					}
				}
				else
				{
					debug(DEBUG_ERROR,"action val null");
					goto END;
				}
			}
			else
			{
				debug(DEBUG_ERROR,"action cmd null");
				goto END;
			}
			if(rule_st.actions == NULL)
			{
				rule_st.actions = action;
			}
			else
			{
				tmp_action = rule_st.actions;
				while(tmp_action->next)
				{
					tmp_action = tmp_action->next;
				}
				tmp_action->next = action;
			}
			action = NULL;
		}
	}
#if 0
	debug(DEBUG_GENERAL,"rule_st.name[%s]",rule_st.name);
	debug(DEBUG_GENERAL,"rule_st.id[%d]",rule_st.id);
	debug(DEBUG_GENERAL,"rule_st.state[%d]",rule_st.state);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_sec[%d]",rule_st.create_time.tm_sec);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_min[%d]",rule_st.create_time.tm_min);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_hour[%d]",rule_st.create_time.tm_hour);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_mday[%d]",rule_st.create_time.tm_mday);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_mon[%d]",rule_st.create_time.tm_mon);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_year[%d]",rule_st.create_time.tm_year);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_wday[%d]",rule_st.create_time.tm_wday);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_yday[%d]",rule_st.create_time.tm_yday);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_isdst[%d]",rule_st.create_time.tm_isdst);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_gmtoff[%d]",rule_st.create_time.tm_gmtoff);

	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_sec[%d]",rule_st.last_triggered.tm_sec);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_min[%d]",rule_st.last_triggered.tm_min);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_hour[%d]",rule_st.last_triggered.tm_hour);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_mday[%d]",rule_st.last_triggered.tm_mday);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_mon[%d]",rule_st.last_triggered.tm_mon);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_year[%d]",rule_st.last_triggered.tm_year);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_wday[%d]",rule_st.last_triggered.tm_wday);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_yday[%d]",rule_st.last_triggered.tm_yday);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_isdst[%d]",rule_st.last_triggered.tm_isdst);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_gmtoff[%d]",rule_st.last_triggered.tm_gmtoff);
	
	debug(DEBUG_GENERAL,"rule_st.times_triggered[%d]",rule_st.times_triggered);
	debug(DEBUG_GENERAL,"rule_st.conditions_expression[%s]",rule_st.conditions_expression);

	rule_conditions_t *cond_tmp = rule_st.conditions;
	for(cond_tmp;cond_tmp != NULL;cond_tmp = cond_tmp->next)
	{
		debug(DEBUG_GENERAL,"cond_tmp->cond_type[%d]",cond_tmp->cond_type);
		if(cond_tmp->cond_type == 1)
		{
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_sec[%d]",cond_tmp->rule_cond.act_time.tm_sec);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_min[%d]",cond_tmp->rule_cond.act_time.tm_min);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_hour[%d]",cond_tmp->rule_cond.act_time.tm_hour);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_mday[%d]",cond_tmp->rule_cond.act_time.tm_mday);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_mon[%d]",cond_tmp->rule_cond.act_time.tm_mon);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_year[%d]",cond_tmp->rule_cond.act_time.tm_year);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_wday[%d]",cond_tmp->rule_cond.act_time.tm_wday);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_yday[%d]",cond_tmp->rule_cond.act_time.tm_yday);
		}
		else if(cond_tmp->cond_type == 2)
		{
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.ieeeAddr[%02x%02x%02x%02x%02x%02x%02x%02x]\n",\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[0],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[1],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[2],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[3],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[4],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[5],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[6],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[7]);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.endpointId[%d]",cond_tmp->rule_cond.triggered_t.endpointId);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.operater_type[%d]",cond_tmp->rule_cond.triggered_t.operater_type);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.attrName[%s]",cond_tmp->rule_cond.triggered_t.attrName);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.value[%s]",cond_tmp->rule_cond.triggered_t.value);
		}
		else
		{
			debug(DEBUG_GENERAL,"error cond_type[%d]",cond_tmp->cond_type);
		}
	}

	rule_actions_t *act_tmp = rule_st.actions;
	for(act_tmp;act_tmp != NULL;act_tmp = act_tmp->next)
	{
		debug(DEBUG_GENERAL,"act_tmp->target_type[%d]",act_tmp->target_type);
		if(act_tmp->target_type == 1)
		{
			debug(DEBUG_GENERAL,"act_tmp->target_id.ieeeAddr[%02x%02x%02x%02x%02x%02x%02x%02x]\n",\
				act_tmp->target_id.ieeeAddr[0],\
				act_tmp->target_id.ieeeAddr[1],\
				act_tmp->target_id.ieeeAddr[2],\
				act_tmp->target_id.ieeeAddr[3],\
				act_tmp->target_id.ieeeAddr[4],\
				act_tmp->target_id.ieeeAddr[5],\
				act_tmp->target_id.ieeeAddr[6],\
				act_tmp->target_id.ieeeAddr[7]);
		}
		else if(act_tmp->target_type == 2)
		{
			debug(DEBUG_GENERAL,"act_tmp->target_id.nwkAddr[%d]",act_tmp->target_id.nwkAddr);
		}
		else if(act_tmp->target_type == 3)
		{
			debug(DEBUG_GENERAL,"act_tmp->target_id.scene_id[%d]",act_tmp->target_id.scene_id);
		}
		debug(DEBUG_GENERAL,"act_tmp->endpointId[%d]",act_tmp->target_ep);
		debug(DEBUG_GENERAL,"act_tmp->attrName[%s]",act_tmp->attrName);
		debug(DEBUG_GENERAL,"act_tmp->value[%s]",act_tmp->value);
	}
#endif
	pthread_mutex_lock(&rule_mutex);
	avl_for_each_element_safe_sz(&(rule_mnt.hdr), rule, avl, qRule)
	{
		if(rule->id == rule_st.id)
		{
			change_flag = 1;
			struct avl_node avl = rule->avl;
			if(rule->conditions_expression)
			{
				free(rule->conditions_expression);
				rule->conditions_expression = NULL;
			}
			tmp_condition = NULL;
			tmp_action = NULL;
			tmp_condition = rule->conditions;
			while(tmp_condition)
			{
				tmp_cond = tmp_condition->next;
				free(tmp_condition);
				tmp_condition = tmp_cond;
			}
			
			tmp_action = rule->actions;
			while(tmp_action)
			{
				tmp_act = tmp_action->next;
				free(tmp_action);
				tmp_action = tmp_act;
			}

			*rule = rule_st;
			rule->avl = avl;
			debug(DEBUG_GENERAL,"rule->conditions_expression[%s]",rule->conditions_expression);
			break;
		}
		else
			continue;
	}
	pthread_mutex_unlock(&rule_mutex);
#if 0
	debug(DEBUG_GENERAL,"rule_st.name[%s]",rule->name);
	debug(DEBUG_GENERAL,"rule_st.id[%d]",rule->id);
	debug(DEBUG_GENERAL,"rule_st.state[%d]",rule->state);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_sec[%d]",rule->create_time.tm_sec);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_min[%d]",rule->create_time.tm_min);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_hour[%d]",rule->create_time.tm_hour);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_mday[%d]",rule->create_time.tm_mday);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_mon[%d]",rule->create_time.tm_mon);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_year[%d]",rule->create_time.tm_year);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_wday[%d]",rule->create_time.tm_wday);
	debug(DEBUG_GENERAL,"rule_st.create_time.tm_yday[%d]",rule->create_time.tm_yday);

	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_sec[%d]",rule->last_triggered.tm_sec);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_min[%d]",rule->last_triggered.tm_min);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_hour[%d]",rule->last_triggered.tm_hour);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_mday[%d]",rule->last_triggered.tm_mday);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_mon[%d]",rule->last_triggered.tm_mon);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_year[%d]",rule->last_triggered.tm_year);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_wday[%d]",rule->last_triggered.tm_wday);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_yday[%d]",rule->last_triggered.tm_yday);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_isdst[%d]",rule->last_triggered.tm_isdst);
	debug(DEBUG_GENERAL,"rule_st.last_triggered.tm_gmtoff[%d]",rule->last_triggered.tm_gmtoff);
	
	debug(DEBUG_GENERAL,"rule_st.times_triggered[%d]",rule->times_triggered);
	debug(DEBUG_GENERAL,"rule_st.conditions_expression[%s]",rule->conditions_expression);

	cond_tmp = rule->conditions;
	for(cond_tmp;cond_tmp != NULL;cond_tmp = cond_tmp->next)
	{
		debug(DEBUG_GENERAL,"cond_tmp->cond_type[%d]",cond_tmp->cond_type);
		debug(DEBUG_GENERAL,"cond_tmp->conditionIdx[%d]",cond_tmp->conditionIdx);
		if(cond_tmp->cond_type == 1)
		{
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_sec[%d]",cond_tmp->rule_cond.act_time.tm_sec);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_min[%d]",cond_tmp->rule_cond.act_time.tm_min);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_hour[%d]",cond_tmp->rule_cond.act_time.tm_hour);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_mday[%d]",cond_tmp->rule_cond.act_time.tm_mday);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_mon[%d]",cond_tmp->rule_cond.act_time.tm_mon);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_year[%d]",cond_tmp->rule_cond.act_time.tm_year);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_wday[%d]",cond_tmp->rule_cond.act_time.tm_wday);
			debug(DEBUG_GENERAL,"cond_tmp->rule_cond.act_time.tm_yday[%d]",cond_tmp->rule_cond.act_time.tm_yday);
		}
		else if(cond_tmp->cond_type == 2)
		{
			
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.ieeeAddr[%02x%02x%02x%02x%02x%02x%02x%02x]\n",\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[0],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[1],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[2],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[3],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[4],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[5],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[6],\
				cond_tmp->rule_cond.triggered_t.ieeeAddr[7]);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.endpointId[%d]",cond_tmp->rule_cond.triggered_t.endpointId);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.operater_type[%d]",cond_tmp->rule_cond.triggered_t.operater_type);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.attrName[%s]",cond_tmp->rule_cond.triggered_t.attrName);
			debug(DEBUG_GENERAL,"cond_tmp.rule_cond.triggered_t.value[%s]",cond_tmp->rule_cond.triggered_t.value);
		}
		else
		{
			debug(DEBUG_GENERAL,"error cond_type[%d]",cond_tmp->cond_type);
		}
	}

	act_tmp = rule->actions;
	for(act_tmp;act_tmp != NULL;act_tmp = act_tmp->next)
	{
		debug(DEBUG_GENERAL,"act_tmp->target_type[%d]",act_tmp->target_type);
		debug(DEBUG_GENERAL,"act_tmp->actionIdx[%d]",act_tmp->actionIdx);
		debug(DEBUG_GENERAL,"act_tmp->delay_timeout[%d]",act_tmp->delay_timeout);
		if(act_tmp->target_type == 1)
		{
			debug(DEBUG_GENERAL,"act_tmp->target_id.ieeeAddr[%02x%02x%02x%02x%02x%02x%02x%02x]\n",\
				act_tmp->target_id.ieeeAddr[0],\
				act_tmp->target_id.ieeeAddr[1],\
				act_tmp->target_id.ieeeAddr[2],\
				act_tmp->target_id.ieeeAddr[3],\
				act_tmp->target_id.ieeeAddr[4],\
				act_tmp->target_id.ieeeAddr[5],\
				act_tmp->target_id.ieeeAddr[6],\
				act_tmp->target_id.ieeeAddr[7]);
		}
		else if(act_tmp->target_type == 2)
		{
			debug(DEBUG_GENERAL,"act_tmp->target_id.nwkAddr[%d]",act_tmp->target_id.nwkAddr);
		}
		else if(act_tmp->target_type == 3)
		{
			debug(DEBUG_GENERAL,"act_tmp->target_id.scene_id[%d]",act_tmp->target_id.scene_id);
		}
		debug(DEBUG_GENERAL,"act_tmp->endpointId[%d]",act_tmp->target_ep);
		debug(DEBUG_GENERAL,"act_tmp->attrName[%s]",act_tmp->attrName);
		debug(DEBUG_GENERAL,"act_tmp->value[%s]",act_tmp->value);
	}
#endif
	rule_update(rule);
	if(change_flag == 1)
	{
#ifndef DISABLE_REPORT
		extern node_info_s node_info;
		unsigned short int group_id = rule_st.id;

		cloud_rule_state_create_callback(&node_info,group_id,rule_st);
#endif
	}
	debug(DEBUG_GENERAL,"rule_id[%d]",rule_id);
   	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b,"id",rule_id);
    ubus_send_reply(ctx, req, b.head);
	if(rule_id > 0)
	{
#ifndef	DISABLE_LOCAL_NOTIFY

		rule_t_t rule_if = {0};
		rule_if.id = rule_id;
		change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
		change_info.flag = RULE_STATE_CHANGE;
		change_info.device_info = NULL;
		change_info.group_info = NULL;
		change_info.scene_info = NULL;
		change_info.rule_info = &rule_if;
		local_notify(&change_info,client_head);
#endif
		return UBUS_STATUS_OK;
	}
	else
		return UBUS_STATUS_INVALID_ARGUMENT;

END:
	if(rule_st.conditions_expression)
	{
		free(rule_st.conditions_expression);
		rule_st.conditions_expression = NULL;
		debug(DEBUG_GENERAL,"free cond_exp");
	}
	if(condition != NULL)
	{
		free(condition);
		condition = NULL;
		debug(DEBUG_GENERAL,"free condition");
	}
	if(action != NULL)
	{
		free(action);
		action = NULL;
		debug(DEBUG_GENERAL,"free action");
	}
	
	tmp_condition = NULL;
	tmp_action = NULL;
	tmp_condition = rule_st.conditions;
	while(tmp_condition)
	{
		tmp_cond = tmp_condition->next;
		free(tmp_condition);
		tmp_condition = tmp_cond;
		debug(DEBUG_GENERAL,"free tmp_condition->next");
	}
	
	tmp_action = rule_st.actions;
	while(tmp_action)
	{
		tmp_act = tmp_action->next;
		free(tmp_action);
		tmp_action = tmp_act;
		debug(DEBUG_GENERAL,"free tmp_action->next");
	}
	return UBUS_STATUS_INVALID_ARGUMENT;

}


int zha_rule_enable(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__RULE_ATTR_MAX] = {NULL};
	struct blob_attr *pattr = NULL;
	struct blob_attr * subCondTb[__RULE_ATTR_COND_MAX] = {NULL};
	struct blob_attr * subActTb[__RULE_ATTR_ACT_MAX] = {NULL};
	uint16_t rule_id = 0;
	uint8_t status = 0;

	blobmsg_parse(rule_attrs, __RULE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));


	if(tb[RULE_ATTR_ID])
	{
		rule_id = (uint8_t)blobmsg_get_u32(tb[RULE_ATTR_ID]);
	}
	else
	{
		debug(DEBUG_ERROR,"rule id isn't get");
    	return UBUS_STATUS_INVALID_ARGUMENT;
	}
	
	if(tb[RULE_ATTR_STATE])
	{
		status = (uint8_t)blobmsg_get_u32(tb[RULE_ATTR_STATE]);
	}
	else
	{
		debug(DEBUG_ERROR,"rule state isn't get,set 1");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if(ZSUCCESS != rule_enableRule(rule_id,status))
		return UBUS_STATUS_INVALID_ARGUMENT;
	else
	{
#ifndef DISABLE_REPORT

		extern node_info_s node_info;
		unsigned short int group_id = rule_id;
		int status_set = status;

		cloud_rule_state_change_callback(&node_info,group_id,status_set);
#endif
#ifndef	DISABLE_LOCAL_NOTIFY

		rule_t_t rule_if = {0};
		rule_if.id = rule_id;
		change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
		change_info.flag = RULE_STATE_CHANGE;
		change_info.device_info = NULL;
		change_info.group_info = NULL;
		change_info.scene_info = NULL;
		change_info.rule_info = &rule_if;
		local_notify(&change_info,client_head);
#endif
		return UBUS_STATUS_OK;
	}

}

int zha_rule_get_info(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__RULE_ATTR_MAX] = {NULL};
	struct blob_attr *pattr = NULL;
	struct blob_attr * subCondTb[__RULE_ATTR_COND_MAX] = {NULL};
	struct blob_attr * subActTb[__RULE_ATTR_ACT_MAX] = {NULL};
	uint16_t rule_id = 0;
	void *l,*e,*el, *ell;
	uint8_t i,j;
	char time_buf[50];
	char id[17];
	char name[10];
	rule_conditions_t  *tmp_conditions;
	rule_actions_t	   *tmp_actions;

	blobmsg_parse(rule_attrs, __RULE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));


	if(tb[RULE_ATTR_ID])
	{
		rule_id = (uint8_t)blobmsg_get_u32(tb[RULE_ATTR_ID]);
	}
	else
	{
		debug(DEBUG_ERROR,"rule id isn't get");
    	return UBUS_STATUS_INVALID_ARGUMENT;
	}

	rule_t_t * rule = NULL;
	rule = rule_find(rule_id);
	
	if(rule)
	{
		blob_buf_init(&b, 0);
		e = blobmsg_open_table(&b,NULL);
		blobmsg_add_string(&b,"name",rule->name);
		blobmsg_add_u32(&b,"id",rule->id);
		blobmsg_add_u32(&b,"state",rule->state);
		strftime(time_buf, 50, date_time_format, &(rule->create_time));
		blobmsg_add_string(&b,"ct",time_buf);
		strftime(time_buf, 50, date_time_format, &(rule->last_triggered));
		blobmsg_add_string(&b,"ltrig",time_buf);
		blobmsg_add_u32(&b,"ctrig",rule->times_triggered);
		blobmsg_add_string(&b,"exp",rule->conditions_expression);
		el = blobmsg_open_array(&b, "cond");
		tmp_conditions = rule->conditions;
		while(tmp_conditions)
		{
			ell = blobmsg_open_table(&b, NULL);	

			blobmsg_add_u32(&b,"idx",tmp_conditions->conditionIdx);
			blobmsg_add_u32(&b,"trig",tmp_conditions->times_triggered);
			blobmsg_add_u32(&b,"type",tmp_conditions->cond_type);
			
			switch(tmp_conditions->cond_type)
			{
				case 1:
				{
					memset(time_buf,0,50);
					char tmp_buf[10] = {0};
					if(tmp_conditions->rule_cond.act_time.tm_year != 0xffff)
					{
						sprintf(tmp_buf,"%d",tmp_conditions->rule_cond.act_time.tm_year + 1900);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_mon + 1);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_mday);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_hour);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_min);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_sec);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%s","#");
						strcat(time_buf,tmp_buf);
					}
					else
					{
						sprintf(time_buf,"%s","#-#-#-");
						sprintf(tmp_buf,"%d",tmp_conditions->rule_cond.act_time.tm_hour);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_min);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d-",tmp_conditions->rule_cond.act_time.tm_sec);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						int ll = 0;
						for(ll = 0;ll < 7;ll++)
						{
							if((tmp_conditions->rule_cond.act_time.tm_wday>>ll)&0x01)
							{
								if(ll == 0)
								{
									sprintf(tmp_buf,"%d",ll+1);
									strcat(time_buf,tmp_buf);
									memset(tmp_buf,0,10);
									
								}
								else
								{
									sprintf(tmp_buf,",%d",ll+1);
									strcat(time_buf,tmp_buf);
									memset(tmp_buf,0,10);
								}
							}
							else
								continue;
						}
					}
				
					blobmsg_add_string(&b,"time",time_buf);
					break;
				}
				case 2:
				{
					snprintf(id, sizeof(id), ieee_id,\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[0],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[1],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[2],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[3],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[4],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[5],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[6],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[7]);
					blobmsg_add_string(&b, "id", id);
					blobmsg_add_u32(&b,"ep",tmp_conditions->rule_cond.triggered_t.endpointId);
					switch(tmp_conditions->rule_cond.triggered_t.operater_type)
					{
						case -1:
						{
							blobmsg_add_string(&b, "op", "less");
						 	break;
						}
						case 0:
						{
						    blobmsg_add_string(&b, "op", "equal");
							break;
						}
						case 1:
						{
						    blobmsg_add_string(&b, "op", "great");
							break;
						}
						case 2:
						{
						    blobmsg_add_string(&b, "op", "change");
							break;
						}
						default:
						{
						    blobmsg_add_string(&b, "op", "error");
							break;
						}
					}
					if(memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"on",strlen("on")) == 0)
					{
						if(memcmp(tmp_conditions->rule_cond.triggered_t.value,"true",strlen("true")) == 0)
							blobmsg_add_string(&b, "val","1");
						else 
							blobmsg_add_string(&b, "val","0");
						blobmsg_add_string(&b, "cmd",tmp_conditions->rule_cond.triggered_t.attrName);
					}
					else if((0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"bri",strlen("bri")))\
						|| (0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"hue",strlen("hue")))\
						|| (0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"sat",strlen("sat")))\
						|| (0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"colortemp",strlen("colortemp"))))
					{
						if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"colortemp",strlen("colortemp")))
							blobmsg_add_string(&b,"cmd","ctp");
						else
							blobmsg_add_string(&b,"cmd",tmp_conditions->rule_cond.triggered_t.attrName);
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"scene",strlen("scene")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd",tmp_conditions->rule_cond.triggered_t.attrName);
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"liftpercentage",strlen("liftpercentage")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","pt");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"status",strlen("status")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","sta");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"now_lux",strlen("now_lux")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","nlux");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"level_status",strlen("level_status")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","llux");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"temperature",strlen("temperature")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","temp");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"humidity",strlen("humidity")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","humi");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"target_lux",strlen("target_lux")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","tlux");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"voc_level",strlen("voc_level")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","voc");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"zoneid",strlen("zoneid")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","zid");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"zonetype",strlen("zonetype")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","type");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"rawdata",strlen("rawdata")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","raw");
					}
					else
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd",tmp_conditions->rule_cond.triggered_t.attrName);
					}
					break;
				}
				default:
					break;
			}

			blobmsg_close_table(&b, ell);
			tmp_conditions = tmp_conditions->next;
		}

		blobmsg_close_array(&b, el);

		el = blobmsg_open_array(&b, "act");
		tmp_actions = rule->actions;
		while(tmp_actions)
		{
			ell = blobmsg_open_table(&b, NULL);
			blobmsg_add_u32(&b,"idx",tmp_actions->actionIdx);
			blobmsg_add_u32(&b,"delay",tmp_actions->delay_timeout);
			blobmsg_add_u32(&b,"type",tmp_actions->target_type);
			if(tmp_actions->target_type == 1)
			{
				memset(id,0,17);
				snprintf(id, sizeof(id), ieee_id,\
							tmp_actions->target_id.ieeeAddr[0],\
							tmp_actions->target_id.ieeeAddr[1],\
							tmp_actions->target_id.ieeeAddr[2],\
							tmp_actions->target_id.ieeeAddr[3],\
							tmp_actions->target_id.ieeeAddr[4],\
							tmp_actions->target_id.ieeeAddr[5],\
							tmp_actions->target_id.ieeeAddr[6],\
							tmp_actions->target_id.ieeeAddr[7]);
				blobmsg_add_string(&b,"id",id);
			}
			else if(tmp_actions->target_type == 2)
			{
				blobmsg_add_u32(&b,"gid",tmp_actions->target_id.nwkAddr);
			}
			else if(tmp_actions->target_type == 3)
			{
				blobmsg_add_u32(&b,"sid",tmp_actions->target_id.scene_id);
			}
			else
			{
				debug(DEBUG_ERROR,"target_type error");
			}
			blobmsg_add_u32(&b,"ep",tmp_actions->target_ep);
			if(memcmp(tmp_actions->attrName,"on",strlen("on")) == 0)
			{
				if(memcmp(tmp_actions->value,"true",strlen("true")))
					blobmsg_add_u8(&b,"val",1);
				else
					blobmsg_add_u8(&b,"val",0);
				blobmsg_add_string(&b,"cmd",tmp_actions->attrName);
			}
			else if((0 == memcmp(tmp_actions->attrName,"bri",strlen("bri")))\
				|| (0 == memcmp(tmp_actions->attrName,"hue",strlen("hue")))\
				|| (0 == memcmp(tmp_actions->attrName,"sat",strlen("sat")))\
				|| (0 == memcmp(tmp_actions->attrName,"colortemp",strlen("colortemp"))))
			{
				if(0 == memcmp(tmp_actions->attrName,"colortemp",strlen("colortemp")))
					blobmsg_add_string(&b,"cmd","ctp");
				else
					blobmsg_add_string(&b,"cmd",tmp_actions->attrName);
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
			}
			else if(0 == memcmp(tmp_actions->attrName,"scene",strlen("scene")))
			{
				/*if(memcmp(tmp_conditions->rule_cond.triggered_t.value,"store",strlen("store")))
					blobmsg_add_u32(&b,"val",1);
				else
					blobmsg_add_u32(&b,"val",2);*/
				blobmsg_add_string(&b,"val",tmp_actions->value);
				blobmsg_add_string(&b,"cmd","scene");
				
			}
			else if(0 == memcmp(tmp_actions->attrName,"liftpercentage",strlen("liftpercentage")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","pt");
			}
			else if(0 == memcmp(tmp_actions->attrName,"now_lux",strlen("now_lux")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","nlux");
			}
			else if(0 == memcmp(tmp_actions->attrName,"rawdata",strlen("rawdata")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","raw");
			}
			else if(0 == memcmp(tmp_actions->attrName,"infraredlearn",strlen("infraredlearn")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","inle");
			}
			else if(0 == memcmp(tmp_actions->attrName,"infraredcontrol",strlen("infraredcontrol")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","inct");
			}
			else if(0 == memcmp(tmp_actions->attrName,"infraredcode",strlen("infraredcode")))
			{
				blobmsg_add_string(&b,"val",tmp_actions->value);
				blobmsg_add_string(&b,"cmd","incd");
			}
			else if(0 == memcmp(tmp_actions->attrName,"downclose",strlen("downclose")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","ctrl");
			}
			else if(0 == memcmp(tmp_actions->attrName,"upopen",strlen("upopen")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","ctrl");
			}
			else if(0 == memcmp(tmp_actions->attrName,"stop",strlen("stop")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","ctrl");
			}
			else if(0 == memcmp(tmp_actions->attrName,"level_status",strlen("level_status")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","llux");
			}
			else if(0 == memcmp(tmp_actions->attrName,"status",strlen("status")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","sta");
			}
			else if(0 == memcmp(tmp_actions->attrName,"temperature",strlen("temperature")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","temp");
			}
			else if(0 == memcmp(tmp_actions->attrName,"humidity",strlen("humidity")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","humi");
			}
			else if(0 == memcmp(tmp_actions->attrName,"target_lux",strlen("target_lux")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","tlux");
			}
			else if(0 == memcmp(tmp_actions->attrName,"voc_level",strlen("voc_level")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","voc");
			}
			else if(0 == memcmp(tmp_actions->attrName,"zoneid",strlen("zoneid")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","zid");
			}
			else if(0 == memcmp(tmp_actions->attrName,"zonetype",strlen("zonetype")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","type");
			}
			else
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd",tmp_actions->attrName);
			}
			blobmsg_close_table(&b, ell);
			tmp_actions = tmp_actions->next;
		}
		blobmsg_close_array(&b, el);
		blobmsg_close_table(&b,e);
	}
	
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;

}



/**********************************************************************************
 * @brief	Get the rule list. Include all content of all rules.
 */
int zha_rule_list(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
#if 1
	rule_t_t *rule = NULL;
	rule_t_t *qRule = NULL;
	void *l,*e,*el, *ell;
	uint8_t i,j;
	int ret = 0;
	char time_buf[50];
	char id[17];
	char name[10];
	rule_conditions_t  *tmp_conditions;
	rule_actions_t	   *tmp_actions;
	blob_buf_init(&b, 0);
	l = blobmsg_open_array(&b,"rules");
	pthread_mutex_lock(&rule_mutex);
	avl_for_each_element_safe_sz(&(rule_mnt.hdr), rule, avl, qRule)
	{
		e = blobmsg_open_table(&b,NULL);
		blobmsg_add_string(&b,"name",rule->name);
		blobmsg_add_u32(&b,"id",rule->id);
		blobmsg_add_u32(&b,"state",rule->state);
		strftime(time_buf, 50, date_time_format, &(rule->create_time));
		blobmsg_add_string(&b,"ct",time_buf);
		strftime(time_buf, 50, date_time_format, &(rule->last_triggered));
		blobmsg_add_string(&b,"ltrig",time_buf);
		blobmsg_add_u32(&b,"ctrig",rule->times_triggered);
		blobmsg_add_string(&b,"exp",rule->conditions_expression);
		el = blobmsg_open_array(&b, "cond");
		tmp_conditions = rule->conditions;
		while(tmp_conditions)
		{
			ell = blobmsg_open_table(&b, NULL);	

			blobmsg_add_u32(&b,"idx",tmp_conditions->conditionIdx);
			blobmsg_add_u32(&b,"trig",tmp_conditions->times_triggered);
			blobmsg_add_u32(&b,"type",tmp_conditions->cond_type);
			
			switch(tmp_conditions->cond_type)
			{
				case 1:
				{
					memset(time_buf,0,50);
					char tmp_buf[10] = {0};
					if(tmp_conditions->rule_cond.act_time.tm_year != 0xffff)
					{
						sprintf(tmp_buf,"%d",tmp_conditions->rule_cond.act_time.tm_year + 1900);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_mon + 1);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_mday);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_hour);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_min);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_sec);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%s","#");
						strcat(time_buf,tmp_buf);
					}
					else
					{
						sprintf(time_buf,"%s","#-#-#-");
						sprintf(tmp_buf,"%d",tmp_conditions->rule_cond.act_time.tm_hour);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d",tmp_conditions->rule_cond.act_time.tm_min);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						sprintf(tmp_buf,"-%d-",tmp_conditions->rule_cond.act_time.tm_sec);
						strcat(time_buf,tmp_buf);
						memset(tmp_buf,0,10);
						int ll = 0;
						for(ll = 0;ll < 7;ll++)
						{
							if((tmp_conditions->rule_cond.act_time.tm_wday>>ll)&0x01)
							{
								if(ll == 0)
								{
									sprintf(tmp_buf,"%d",ll+1);
									strcat(time_buf,tmp_buf);
									memset(tmp_buf,0,10);
									
								}
								else
								{
									sprintf(tmp_buf,",%d",ll+1);
									strcat(time_buf,tmp_buf);
									memset(tmp_buf,0,10);
								}
							}
							else
								continue;
						}
					}
				
					blobmsg_add_string(&b,"time",time_buf);
					break;
				}
				case 2:
				{
					snprintf(id, sizeof(id), ieee_id,\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[0],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[1],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[2],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[3],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[4],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[5],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[6],\
							tmp_conditions->rule_cond.triggered_t.ieeeAddr[7]);
					blobmsg_add_string(&b, "id", id);
					blobmsg_add_u32(&b,"ep",tmp_conditions->rule_cond.triggered_t.endpointId);
					switch(tmp_conditions->rule_cond.triggered_t.operater_type)
					{
						case -1:
						{
							blobmsg_add_string(&b, "op", "less");
						 	break;
						}
						case 0:
						{
						    blobmsg_add_string(&b, "op", "equal");
							break;
						}
						case 1:
						{
						    blobmsg_add_string(&b, "op", "great");
							break;
						}
						case 2:
						{
						    blobmsg_add_string(&b, "op", "change");
							break;
						}
						default:
						{
						    blobmsg_add_string(&b, "op", "error");
							break;
						}
					}
					if(memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"on",strlen("on")) == 0)
					{
						if(memcmp(tmp_conditions->rule_cond.triggered_t.value,"true",strlen("true")) == 0)
							blobmsg_add_string(&b, "val","1");
						else 
							blobmsg_add_string(&b, "val","0");
						blobmsg_add_string(&b, "cmd",tmp_conditions->rule_cond.triggered_t.attrName);
					}
					else if((0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"bri",strlen("bri")))\
						|| (0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"hue",strlen("hue")))\
						|| (0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"sat",strlen("sat")))\
						|| (0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"colortemp",strlen("colortemp"))))
					{
						if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"colortemp",strlen("colortemp")))
							blobmsg_add_string(&b,"cmd","ctp");
						else
							blobmsg_add_string(&b,"cmd",tmp_conditions->rule_cond.triggered_t.attrName);
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"scene",strlen("scene")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd",tmp_conditions->rule_cond.triggered_t.attrName);
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"liftpercentage",strlen("liftpercentage")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","pt");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"status",strlen("status")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","sta");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"now_lux",strlen("now_lux")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","nlux");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"level_status",strlen("level_status")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","llux");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"temperature",strlen("temperature")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","temp");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"humidity",strlen("humidity")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","humi");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"target_lux",strlen("target_lux")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","tlux");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"voc_level",strlen("voc_level")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","voc");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"zoneid",strlen("zoneid")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","zid");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"zonetype",strlen("zonetype")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","type");
					}
					else if(0 == memcmp(tmp_conditions->rule_cond.triggered_t.attrName,"rawdata",strlen("rawdata")))
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd","raw");
					}
					else
					{
						blobmsg_add_string(&b,"val",tmp_conditions->rule_cond.triggered_t.value);
						blobmsg_add_string(&b, "cmd",tmp_conditions->rule_cond.triggered_t.attrName);
					}
					break;
				}
				default:
					break;
			}

			blobmsg_close_table(&b, ell);
			tmp_conditions = tmp_conditions->next;
		}

		blobmsg_close_array(&b, el);

		el = blobmsg_open_array(&b, "act");
		tmp_actions = rule->actions;
		while(tmp_actions)
		{
			ell = blobmsg_open_table(&b, NULL);
			blobmsg_add_u32(&b,"idx",tmp_actions->actionIdx);
			blobmsg_add_u32(&b,"delay",tmp_actions->delay_timeout);
			blobmsg_add_u32(&b,"type",tmp_actions->target_type);
			if(tmp_actions->target_type == 1)
			{
				memset(id,0,17);
				snprintf(id, sizeof(id), ieee_id,\
							tmp_actions->target_id.ieeeAddr[0],\
							tmp_actions->target_id.ieeeAddr[1],\
							tmp_actions->target_id.ieeeAddr[2],\
							tmp_actions->target_id.ieeeAddr[3],\
							tmp_actions->target_id.ieeeAddr[4],\
							tmp_actions->target_id.ieeeAddr[5],\
							tmp_actions->target_id.ieeeAddr[6],\
							tmp_actions->target_id.ieeeAddr[7]);
				blobmsg_add_string(&b,"id",id);
			}
			else if(tmp_actions->target_type == 2)
			{
				blobmsg_add_u32(&b,"gid",tmp_actions->target_id.nwkAddr);
			}
			else if(tmp_actions->target_type == 3)
			{
				blobmsg_add_u32(&b,"sid",tmp_actions->target_id.scene_id);
			}
			else
			{
				debug(DEBUG_ERROR,"target_type error");
			}
			blobmsg_add_u32(&b,"ep",tmp_actions->target_ep);
			if(memcmp(tmp_actions->attrName,"on",strlen("on")) == 0)
			{
				if(memcmp(tmp_actions->value,"true",strlen("true")) == 0)
					blobmsg_add_u8(&b,"val",1);
				else
					blobmsg_add_u8(&b,"val",0);
				blobmsg_add_string(&b,"cmd",tmp_actions->attrName);
			}
			else if((0 == memcmp(tmp_actions->attrName,"bri",strlen("bri")))\
				|| (0 == memcmp(tmp_actions->attrName,"hue",strlen("hue")))\
				|| (0 == memcmp(tmp_actions->attrName,"sat",strlen("sat")))\
				|| (0 == memcmp(tmp_actions->attrName,"colortemp",strlen("colortemp"))))
			{
				if(0 == memcmp(tmp_actions->attrName,"colortemp",strlen("colortemp")))
					blobmsg_add_string(&b,"cmd","ctp");
				else
					blobmsg_add_string(&b,"cmd",tmp_actions->attrName);
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
			}
			else if(0 == memcmp(tmp_actions->attrName,"scene",strlen("scene")))
			{
				/*if(memcmp(tmp_conditions->rule_cond.triggered_t.value,"store",strlen("store")))
					blobmsg_add_u32(&b,"val",1);
				else
					blobmsg_add_u32(&b,"val",2);*/
				blobmsg_add_string(&b,"val",tmp_actions->value);
				blobmsg_add_string(&b,"cmd","scene");
				
			}
			else if(0 == memcmp(tmp_actions->attrName,"liftpercentage",strlen("liftpercentage")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","pt");
			}
			else if(0 == memcmp(tmp_actions->attrName,"now_lux",strlen("now_lux")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","nlux");
			}
			else if(0 == memcmp(tmp_actions->attrName,"rawdata",strlen("rawdata")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","raw");
			}
			else if(0 == memcmp(tmp_actions->attrName,"infraredlearn",strlen("infraredlearn")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","inle");
			}
			else if(0 == memcmp(tmp_actions->attrName,"infraredcontrol",strlen("infraredcontrol")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","inct");
			}
			else if(0 == memcmp(tmp_actions->attrName,"infraredcode",strlen("infraredcode")))
			{
				blobmsg_add_string(&b,"val",tmp_actions->value);
				blobmsg_add_string(&b,"cmd","incd");
			}
			else if(0 == memcmp(tmp_actions->attrName,"downclose",strlen("downclose")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","ctrl");
			}
			else if(0 == memcmp(tmp_actions->attrName,"upopen",strlen("upopen")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","ctrl");
			}
			else if(0 == memcmp(tmp_actions->attrName,"stop",strlen("stop")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","ctrl");
			}
			else if(0 == memcmp(tmp_actions->attrName,"level_status",strlen("level_status")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","llux");
			}
			else if(0 == memcmp(tmp_actions->attrName,"status",strlen("status")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","sta");
			}
			else if(0 == memcmp(tmp_actions->attrName,"temperature",strlen("temperature")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","temp");
			}
			else if(0 == memcmp(tmp_actions->attrName,"humidity",strlen("humidity")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","humi");
			}
			else if(0 == memcmp(tmp_actions->attrName,"target_lux",strlen("target_lux")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","tlux");
			}
			else if(0 == memcmp(tmp_actions->attrName,"voc_level",strlen("voc_level")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","voc");
			}
			else if(0 == memcmp(tmp_actions->attrName,"zoneid",strlen("zoneid")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","zid");
			}
			else if(0 == memcmp(tmp_actions->attrName,"zonetype",strlen("zonetype")))
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd","type");
			}
			else
			{
				blobmsg_add_u32(&b,"val",atoi(tmp_actions->value));
				blobmsg_add_string(&b,"cmd",tmp_actions->attrName);
			}
			blobmsg_close_table(&b, ell);
			tmp_actions = tmp_actions->next;
		}
		blobmsg_close_array(&b, el);
		blobmsg_close_table(&b,e);
	}
	pthread_mutex_unlock(&rule_mutex);
	blobmsg_close_array(&b, l);
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;
#endif
	return UBUS_STATUS_OK;
}


int zha_rule_delete(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
#if 1
	int result = UBUS_STATUS_OK;
	uint16_t rule_id;
	struct blob_attr *tb[__RULE_ATTR_MAX];


	blobmsg_parse(rule_attrs, __RULE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if(tb[RULE_ATTR_ID])
	{
		rule_id = blobmsg_get_u32(tb[RULE_ATTR_ID]);
		if(rule_del(rule_id) ==ZSUCCESS)
		{
      		result = UBUS_STATUS_OK;
#ifndef DISABLE_REPORT
			extern node_info_s node_info;
			short int group_id = rule_id;
			cloud_rule_state_del_callback(&node_info,group_id);
#endif
#ifndef	DISABLE_LOCAL_NOTIFY
		change_info_t change_info = {0,NULL,NULL,NULL,NULL,NULL};
		change_info.flag = RULE_DEL_ADD;
		change_info.device_info = NULL;
		change_info.group_info = NULL;
		change_info.scene_info = NULL;
		change_info.rule_info = NULL;
		local_notify(&change_info,client_head);
#endif

    	}
		else
		{
      		result = UBUS_STATUS_INVALID_ARGUMENT;
    	}
	}
	return result;
#endif
}


int	zha_time_set(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
	struct blob_attr *tb[__ZHA_REAL_TIME_MAX];
	struct timeval tv; 
	time_t sec;
	struct tm my_tm = {0};
	time_t now;  
	struct tm *timenow;

	time(&now);
	debug(DEBUG_USER,"now[%ld]\n",now);
	timenow = localtime(&now);
	debug(DEBUG_USER,"Local time is %s",asctime(timenow)); 
	
	blobmsg_parse(real_time, __ZHA_REAL_TIME_MAX, tb, blob_data(msg), blob_len(msg));

	if(tb[ZHA_REAL_TIME])
	{
		if(!strptime(blobmsg_get_string(tb[ZHA_REAL_TIME]), date_time_format,&my_tm))
		{
			debug(DEBUG_USER,"strptime createtime error");
			return UBUS_STATUS_INVALID_ARGUMENT;
		}
	}
	else
	{
		debug(DEBUG_USER,"don't get real time");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	sec = mktime(&my_tm);
	debug(DEBUG_USER,"sec[%ld]\n",sec);
	
	tv.tv_sec = sec;	
	tv.tv_usec = 0;	
	if(settimeofday (&tv,(struct timezone *) 0) < 0)  
	{  
		debug(DEBUG_USER,"Set system datatime error!");	
		return UBUS_STATUS_INVALID_ARGUMENT;  
	} 

	
	
	time(&now);
	debug(DEBUG_USER,"now[%ld]\n",now);
	timenow = localtime(&now);
	debug(DEBUG_USER,"Local time is %s",asctime(timenow)); 

	return UBUS_STATUS_OK;
}


int zha_set_coord_heart_interval(unsigned short interval)
{
	extern uint16_t nwk_coordHeartBeatInterval;
	
	if(interval < 0)
		return ZFAILURE;
	
	nwk_coordHeartBeatInterval = interval;
	
	return ZSUCCESS;
}

int	zha_coord_heart_Interval(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
		struct blob_attr *tb[__ZHA_NWKMGR_ATTR_MAX];
		unsigned short interval = 0;
		
		blobmsg_parse(zha_nwkmgr_attrs, __ZHA_NWKMGR_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
		if(tb[ZHA_PERMITJOIN_TIME_ATTR_SET])
		{
			interval = (uint16_t)blobmsg_get_u32(tb[ZHA_PERMITJOIN_TIME_ATTR_SET]);
			if(ZSUCCESS == zha_set_coord_heart_interval(interval))
 				return UBUS_STATUS_OK;
			else
				return UBUS_STATUS_INVALID_ARGUMENT;
		}
		else
			return UBUS_STATUS_INVALID_ARGUMENT;

}

int zha_set_min_heart_interval(unsigned short interval)
{
	extern uint16_t minReportInterval;
	
	if(interval < 0)
		return ZFAILURE;
	
	minReportInterval = interval;
	
	return ZSUCCESS;
}

int	zha_min_heart_interval(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
		struct blob_attr *tb[__ZHA_NWKMGR_ATTR_MAX];
		unsigned short interval = 0;
		
		blobmsg_parse(zha_nwkmgr_attrs, __ZHA_NWKMGR_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
		if(tb[ZHA_PERMITJOIN_TIME_ATTR_SET])
		{
			interval = (uint16_t)blobmsg_get_u32(tb[ZHA_PERMITJOIN_TIME_ATTR_SET]);
			if(ZSUCCESS == zha_set_min_heart_interval(interval))
 				return UBUS_STATUS_OK;
			else
				return UBUS_STATUS_INVALID_ARGUMENT;
		}
		else
			return UBUS_STATUS_INVALID_ARGUMENT;

}


int zha_set_max_heart_interval(unsigned short interval)
{
	extern uint16_t maxReportInterval;
	
	if(interval < 0)
		return ZFAILURE;
	
	maxReportInterval = interval;
	
	return ZSUCCESS;
}

int	zha_max_heart_interval(struct ubus_context *ctx, struct ubus_object *obj, 
		struct ubus_request_data *req, const char *method, 
		struct blob_attr *msg)
{
		struct blob_attr *tb[__ZHA_NWKMGR_ATTR_MAX];
		unsigned short interval = 0;
		
		blobmsg_parse(zha_nwkmgr_attrs, __ZHA_NWKMGR_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
		if(tb[ZHA_PERMITJOIN_TIME_ATTR_SET])
		{
			interval = (uint16_t)blobmsg_get_u32(tb[ZHA_PERMITJOIN_TIME_ATTR_SET]);
			if(ZSUCCESS == zha_set_max_heart_interval(interval))
 				return UBUS_STATUS_OK;
			else
				return UBUS_STATUS_INVALID_ARGUMENT;
		}
		else
			return UBUS_STATUS_INVALID_ARGUMENT;

}



int zha_get_heart(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	extern uint16_t nwk_coordHeartBeatInterval;
	extern uint16_t minReportInterval;
	extern uint16_t maxReportInterval;
	void *e;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b,"coord_heart",nwk_coordHeartBeatInterval);
	blobmsg_add_u32(&b,"min_heart",minReportInterval);
	blobmsg_add_u32(&b,"max_heart",maxReportInterval);
	
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;

}

 
 void moduleUpdate(char *zigbeeModuleBin);

 void *testddddd(void *arg)
{
  moduleUpdate("/tmp/cc2530.bin");
}

int zha_get_ver(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
  pthread_t osal_tid;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b,"versions",CLOUD_VER);
  

   pthread_create(&osal_tid,NULL,testddddd,(void *)NULL);
	
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;

}

int zha_get_cloud_state(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	extern int cloud_connect_state;
	
	blob_buf_init(&b, 0);
	if(cloud_connect_state == 0)
		blobmsg_add_string(&b,"cloud_state","disconnect");
	else
		blobmsg_add_string(&b,"cloud_state","connected");
	
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;

}

int zha_debug(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	extern int debug_level;
	struct blob_attr *tb[__ZHA_DEBUG_MAX];
	
	DEBUG_LOCK;
	blobmsg_parse(cloud_debug, __ZHA_DEBUG_MAX, tb, blob_data(msg), blob_len(msg));
	if(tb[ZHA_DEBUG])
	{
		debug_level = (uint16_t)blobmsg_get_u32(tb[ZHA_DEBUG]);
	}
	DEBUG_UNLOCK;
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b,"debug_level",debug_level);
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;

}

int zha_cloud_addr_changed(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	extern int cloud_address_changed;
	struct blob_attr *tb[__CLOUD_ADDR_MAX];
	
	blobmsg_parse(cloud_addr_changed, __CLOUD_ADDR_MAX, tb, blob_data(msg), blob_len(msg));
	if(tb[CLOUD_ADDR])
	{
		CLOUD_ADDR_LOCK;
		cloud_address_changed = (uint16_t)blobmsg_get_u32(tb[CLOUD_ADDR]);
		CLOUD_ADDR_UNLOCK;
		return UBUS_STATUS_OK;
	}
	
	return UBUS_STATUS_INVALID_ARGUMENT;

}

int zha_get_cloud_addr(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	extern cloud_info_s cloud_info;
	
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b,"port",cloud_info.port);
	blobmsg_add_string(&b,"key",cloud_info.key);
	blobmsg_add_u32(&b,"verify",cloud_info.verify);
	blobmsg_add_u32(&b,"encryption",cloud_info.encryption);
	blobmsg_add_string(&b,"server_addr",cloud_info.server_addr);
	ubus_send_reply(ctx, req, b.head);
	
	return UBUS_STATUS_OK;

}

int zha_sha_256(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	extern int cloud_address_changed;
	struct blob_attr *tb[__SHA256_MAX];
	
  shuncom_test123();
	blobmsg_parse(sha256, __SHA256_MAX, tb, blob_data(msg), blob_len(msg));
	if(tb[SHA256_TIME] && tb[SHA256_ID] && tb[SHA256_MAC])
	{
		char key[33] = {0};
		
  		cloud_generate_key(blobmsg_get_u32(tb[SHA256_TIME]),blobmsg_get_string(tb[SHA256_ID]),blobmsg_get_string(tb[SHA256_MAC]),key);
		key[32] = 0x00;
		
		blob_buf_init(&b, 0);
		blobmsg_add_string(&b,"key",key);
		ubus_send_reply(ctx, req, b.head);
	}
	else
	{
		/*long timestamp_e = 1414569197;	
		char gw_id[40] = "0x00124b0004207950";	
		char gw_mac[40] = "84:7b:eb:00:fc:7f";
		char key[33] = {0};
		
  		cloud_generate_key(timestamp_e,gw_id,gw_mac,key);
		key[32] = 0x00;
		blob_buf_init(&b, 0);
		blobmsg_add_string(&b,"key",key);
		ubus_send_reply(ctx, req, b.head);*/
		#define AES_128 128
		#define AES_LEN (AES_128/8)

		#define DATA_SIZE 1000

		long timestamp_e = 1414569197;
		char gw_id[40] = {"0x00124b0004207950"};
		char gw_mac[40] = {"84:7b:eb:00:fc:7f"};
		char d[100];
		
		SHA256_CTX c;
		unsigned char m[SHA256_DIGEST_LENGTH];
		int i;
		int d_len;
		char temp_string[70];
		int n = 0;
		uint64_t longaddr;

		int ret = 0;
		//uint8_t iv[AES_LEN];
		char data[DATA_SIZE] = { "{ \"code\": 101, \"gateway\": { \"id\": \"0x00124b0009094bdd\", \"mac\": \"00:03:7f:11:55:5f\" }, \"device\": [ { \"id\": \"0x00124b00033a8495\", \"online\": true, \"endpointid\": 8, \"profileid\": 260, \"deviceid\": 9, \"state\": { \"on\": true } }, { \"id\": \"0x00124b00033a84d6\", \"online\": true, \"endpointid\": 8, \"profileid\": 260, \"deviceid\": 9, \"state\": { \"on\": true } }, { \"id\": \"0x00124b00033a860a\", \"online\": true, \"endpointid\": 8, \"profileid\": 260, \"deviceid\": 9, \"state\": { \"on\": false } }, { \"id\": \"0x00124b00033a861c\", \"online\": true, \"endpointid\": 8, \"profileid\": 260, \"deviceid\": 9, \"state\": { \"on\": false } } ] }" };
		char dataOut[DATA_SIZE];
		int dataLen = strlen(data);// ***** the being encrypted data length ******

		struct timeval tv;

		SHA256_Init(&c);

		d_len = sprintf(temp_string, "%lx", timestamp_e >> 5);

		memcpy(d, temp_string, d_len);
		n += d_len;

		longaddr = strtoll(gw_id, NULL, 16);

		printf("longaddr[%lld]\n",longaddr);
		printf("longaddr[%lld]\n",longaddr >> 32);
		printf("longaddr[%llx]\n",longaddr >> 32);
		printf("longaddr[%lx]\n",longaddr >> 32);
		printf("longaddr[%lx]\n",(long int)(longaddr >> 32));
			
		d_len = sprintf(temp_string, "%llx", longaddr >> 32);

		printf("temp_string[%s]\n",temp_string);

		memcpy(d+n, temp_string, d_len);
		n += d_len;

		d_len = sprintf(temp_string, "%lx", timestamp_e >> 3);

		memcpy(d+n, temp_string, d_len);
		n += d_len;

		d_len = sprintf(temp_string, "%llx", longaddr & 0xFFFFFFFF);

		memcpy(d+n, temp_string, d_len);
		n += d_len;

		d_len = sprintf(temp_string, "%lx", timestamp_e >> 1);

		memcpy(d+n, temp_string, d_len);
		n += d_len;

		d_len = sprintf(temp_string, "%s", gw_mac);

		memcpy(d+n, temp_string, d_len);
		n += d_len;

		for(i = 0; i< n; i ++)
		{
			printf("%02x ", d[i]);
		}
		printf("\n");

		SHA256_Update(&c, d, n);
		SHA256_Final(m, &c);				// time spend may be 60us
		//OPENSSL_cleanse(&c, sizeof(c));
		for(i=0;i < SHA256_DIGEST_LENGTH; i++)
		{
			printf("%02x ", m[i]);
		}
		printf("\n");

		gettimeofday(&tv, NULL);
		printf("en start time %ld\n", tv.tv_usec);

		ret = device_aes_encrypt(m, KEY_LEN, m+KEY_LEN, IV_LEN, data, dataLen, dataOut, DATA_SIZE);	// time spend may be 41us
		printf("en result len %d:\n", ret);
		for(i = 0;i < ret; i ++)
		{
			printf("%02x ", (uint8_t)dataOut[i]);
		}
		printf("\n");

		gettimeofday(&tv, NULL);
		printf("en end time %ld\n", tv.tv_usec);

		ret = device_aes_decrypt(m, AES_128, m+AES_128, IV_LEN, dataOut, ret, data, DATA_SIZE);		// time spend may be 13us
		printf("dn result len %d:\n", ret);
		for(i = 0;i < ret; i ++)
		{
			printf("%c", data[i]);
		}
		printf("\n");

		gettimeofday(&tv, NULL);
		printf("de end time %ld\n", tv.tv_usec);
	}
	
	return UBUS_STATUS_OK;

}

#endif

