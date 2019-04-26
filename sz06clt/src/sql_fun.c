#include <stdio.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>


#include "sql_fun.h"
#include "sz06_info.h"
#include "sz_printf.h"
#include "sz_connect_drive.h"
#include "recmqtt.h"
//#include "device_sql_fun.h"

int sz_init_device_db(sqlite3 *db);
int device_mana_inset_device(sz_device_info device);
int device_mana_inset_device(sz_device_info device);
void sz_recover_device_info(void);
void sz_upData_device_info(unsigned char *upDataId);



sqlite3 *db = NULL;
sz_device_info device_header;
 pthread_mutex_t device_man_lock;

/*
*
*	0:finded
*	1:could not finded
*	2:sql error
*
*/
int sz_is_table_exist(unsigned char * tablename)
{
	char sql[200] = {0};
	int rc = 0;
  	char *zErrMsg = NULL;
	char **dbResult = NULL;
	int nRow, nColumn;
	int index;
	int i, j;

	sprintf(sql,"SELECT name FROM sqlite_master WHERE type = 'table' AND name = '%s';",tablename);
	
    //��ʹ�ûص�������ѯ���ݿ�
    
    rc = sqlite3_get_table(db,sql, &dbResult, &nRow,&nColumn, &zErrMsg);
    if (rc == SQLITE_OK)
    {
        index = nColumn;
        //debug("find %d record\n", nRow);

		if(nRow == 0)
		{
			debug("could not find table[%s]",tablename);
			sqlite3_free_table(dbResult);
			return 1;
		}
		else
		{
        	debug("table[%s] finded record[%d]",tablename,nColumn);
			sqlite3_free_table(dbResult);
			return 0;
		}
        /*for (i = 0; i < nRow; i++)
        {
            for (j = 0; j < nColumn; j++)
            {
            	debug("%s:%s",dbResult[j],dbResult[index]);
				index++;
            }
            debug("----------------------------------------------------------\n");
        }*/
    }
	else
	{
		err_debug("SQL error: %s\n", zErrMsg);
		sqlite3_free_table(dbResult);
		return 2;
	}
}

/*
*
*	0:finded
*	1:could not finded
*	2:sql error
*
*/
int sz_is_columnName_exist(unsigned char *tb_name,unsigned char *device_name)
{
	char sql[200] = {0};
	int rc = 0;
	int inset_result = 0;
	char *zErrMsg = NULL;
	char **dbResult = NULL;
	int nRow, nColumn;
	int index;
	int i = 0;
	int j = 0;
	int finded = 1;

	sprintf(sql,"SELECT %s FROM %s;",device_name,tb_name);
	debug("sql[%s]",sql);
	//��ʹ�ûص�������ѯ���ݿ�

	rc = sqlite3_get_table(db,sql, &dbResult, &nRow,&nColumn, &zErrMsg);
	if (rc == SQLITE_OK)
		finded = 0;
	else
	{
		err_debug("SQL error: %s\n", zErrMsg);
	}

	sqlite3_free_table(dbResult);
	//debug("device_index[%d]heart_step[%d]nRow[%d]heart_count[%d]",device_index,heart_step,nRow,heart_count);

	return  finded;
}



/*
*
*	0:success
*	1:failure
*/
int sz_inset_columnName(unsigned char *tb_name,unsigned char *column_name,unsigned char *columntype)
{
	char sql[200] = {0};
	int rc = 0;
  	char *zErrMsg = NULL;
	char **dbResult = NULL;
	int id = 0;

	sprintf(sql,"ALTER TABLE %s ADD '%s' %s ;",tb_name,column_name,columntype);

	rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		err_debug("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		return 1;
	} 
	else 
	{
		return 0;
		;//debug("Table INSERT device_tb successfully\n");
	}
	
}



int sz_init_db(void)
{
	
	char *zErrMsg = 0;
	int rc;
	char *sql;
	

/***************create or open database**************/ 
    rc = sqlite3_open("/etc/config/db/sz06.db", &db);
	//rc = sqlite3_open(":memory:", &db);
	if (rc)
	{
		err_debug("Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}

	sz_init_device_db(db);
	
	sz_recover_device_info();

//    unsigned char id[21];
//    strcpy(id,"03026f00551001000048");
//    debug("search:%d",srne_is_device_exist(id));
		
	return 0;
}


int sz_init_device_db(sqlite3 *db)
{
	
	char *zErrMsg = 0;
	int rc;
	char *sql;
	

/************create device table*****************/
	/* Create SQL statement */
	sql = "CREATE TABLE device_tb("	\
			"date  				DATETIME 							NOT NULL," \
			"ieee  				CHAR(21)	 						NOT NULL," \
			"addr				CHAR(9)										," \
			"rawdata           	CHAR(256)                                   ," \
			"ep    				INT		 							NOT NULL," \
			"status				INT 								NOT NULL," \
			"did				INT									NOT NULL);" ;

	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		err_debug("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	else 
	{
		debug("Table created device_tb successfully\n");
	}
	return 0;
}


void sz_recover_device_info(void)
{
	char sql[200] = {0};
	int rc = 0;
	int inset_result = 0;
  	char *zErrMsg = NULL;
	char **dbResult = NULL;
	int nRow, nColumn;
	int index;
	int i = 0;
	int j = 0, epCount;

	debug("--------recover device info-----------");

	sprintf(sql,"SELECT * FROM device_tb;");
	debug("sql[%s]",sql);
	//��ʹ�ûص�������ѯ���ݿ�

	rc = sqlite3_get_table(db,sql, &dbResult, &nRow,&nColumn, &zErrMsg);
	if (rc == SQLITE_OK)
	{
//		debug("nRow[%d]nColumn[%d]",nRow,nColumn);
		index = nColumn;
		for (i; i < nRow; i++)
		{
			unsigned char ieee[21] = {0};
			unsigned char addr[9] = {0};
			unsigned char rawdata[256] = {0};
			unsigned int ep = 0xffffffff;
			unsigned int pid = 0xffffffff;
			unsigned int did = 0xffffffff;
			unsigned int status = 0xffffffff;
			unsigned char dsp[40] = {0};
			int rawdataIsNull = 0;

//			debug("i[%d] nRow[%d]",i,nRow);
			for (j = 0; j < nColumn; j++)
			{
				if((strlen("ieee") == strlen(dbResult[j])) && (memcmp("ieee",dbResult[j],strlen("ieee")) == 0))
				{
					if(strlen(dbResult[index]) > 20)
						memcpy(ieee,dbResult[index],20);
					else
						strcpy(ieee,dbResult[index]);
				}
				else if((strlen("ep") == strlen(dbResult[j])) && (memcmp("ep",dbResult[j],strlen("ep")) == 0))
				{
					if(dbResult[index] == NULL)
					{
						err_debug("ep is NULL");
					}
					else
						ep = atoi(dbResult[index]);
				}
				else if((strlen("addr") == strlen(dbResult[j])) && (memcmp("addr",dbResult[j],strlen("addr")) == 0))
				{
					if(strlen(dbResult[index]) > 9)
						memcpy(addr,dbResult[index],9);
					else
						strcpy(addr,dbResult[index]);

				}
				else if((strlen("did") == strlen(dbResult[j])) && (memcmp("did",dbResult[j],strlen("did")) == 0))
				{
					if(dbResult[index] == NULL)
					{
						err_debug("did is NULL");
					}
					else
						did = atoi(dbResult[index]);
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
				else if((strlen("dsp") == strlen(dbResult[j])) && (memcmp("dsp",dbResult[j],strlen("dsp")) == 0))
				{
					if(strlen(dbResult[index]) > 40)
						memcpy(dsp,dbResult[index],40);
					else
						strcpy(dsp,dbResult[index]);
				}
				else if((strlen("rawdata") == strlen(dbResult[j])) && (memcmp("rawdata",dbResult[j],strlen("rawdata")) == 0))
				{	
					if(dbResult[index] == NULL)
					{
						err_debug("rawdata is NULL");
						rawdataIsNull = 1;
					}
					else
						strcpy(rawdata,dbResult[index]);
				}
				index++;
			}
			
//			debug("%s", rawdata);
			for(epCount = 1; epCount < 17; epCount++)
			{	
				collect_data device;
				strncpy(device.id, ieee, 21);
				strncpy(device.addr, addr, 9);
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
			}
			
			if(!rawdataIsNull)
			{
				int rawdata_string_len = strlen(rawdata);
				unsigned char rawdata_hex[rawdata_string_len/2];
	    		hexStr2bytes(rawdata,rawdata_hex,rawdata_string_len/2);
				int dataStart = 6;
				int dataType = rawdata_hex[dataStart];
				double collectValue;
				int boolData, dec_pl;
				
				for(dataStart; dataStart < rawdata_string_len/2;)
				{
					//debug("updata data");
					ep = rawdata_hex[dataStart++] + 1;
					
					switch (rawdata_hex[dataStart++])
					{
						case 0:
							//debug("/0/");
							boolData = rawdata_hex[dataStart++];
							sz06_update_elelev(ieee, boolData, ep);
							break;
						case 1:
							//debug("/1/");
							boolData = rawdata_hex[dataStart++];
							sz06_update_digidal(ieee, boolData, ep);
							break;
						case 4:
							//debug("/4/");
							boolData = rawdata_hex[dataStart++];
							sz06_update_eleout(ieee, boolData, ep);
							break;					
						case 5:
							//debug("/5/");
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
							sz06_update_anal420(ieee, collectValue, ep);
							break;
						case 7:
							//debug("/7/");
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
						    sz06_update_volt3_3(ieee, collectValue, ep);
							break;		
						case 8:
							//debug("/8/");
							collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
							sz06_update_volt5_0(ieee, collectValue, ep);
							break;	
						case 9:
							//debug("/9/");
							if(rawdata_hex[dataStart++]){
								collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
								sz06_update_dstemp(ieee, collectValue, ep);
							}
							else{
								collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0);
								sz06_update_dstemp(ieee, collectValue, ep);
							}
							break;
						case 10:
							//debug("/10/");
							if(rawdata_hex[dataStart++]){
								collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
								sz06_update_pttemp(ieee, collectValue, ep);
							}
							else{
								collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0);
								sz06_update_pttemp(ieee, collectValue, ep);

							}
							break;
						case 11:
							//debug("/11/");
							if(rawdata_hex[dataStart++]){
								collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
								sz06_update_colltemp(ieee, collectValue, ep);
								collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
								sz06_update_collhumi(ieee, collectValue, ep);
							}
							else{
								collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0);
								sz06_update_colltemp(ieee, collectValue, ep);
								collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
								sz06_update_collhumi(ieee, collectValue, ep);
							}
							break;
						default:
							break;
					}
				}
		//	break;
		//	}
			}
			
/*			sz_device_info tmp_device = {0};

			strcpy(tmp_device.id,ieee);
			strcpy(tmp_device.addr, addr);
			tmp_device.status = status;
			tmp_device.ep = ep;
			tmp_device.did = did;
			tmp_device.pid = pid;
			tmp_device.next = NULL;*/

//			debug("--------------------");
//			debug("addr[%s]",tmp_device.addr);
//			debug("id[%s]",tmp_device.id);
//			debug("status[%d]",tmp_device.status);
//			debug("ep[%d]",tmp_device.ep);
//			debug("did[%d]",tmp_device.did);
//			debug("pid[%d]",tmp_device.pid);

//			inset_result = device_mana_inset_device(tmp_device);
//			debug("inset_result[%d]",inset_result);

		}
	}
	else
	{
		err_debug("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}

	sqlite3_free_table(dbResult);
	//debug("device_index[%d]heart_step[%d]nRow[%d]heart_count[%d]",device_index,heart_step,nRow,heart_count);

	return ;
}


int device_mana_inset_device(sz_device_info device)
{
 //   debug("device join");
    DEVICE_MAN_UNLOCK;
	DEVICE_MAN_LOCK;
	sz_device_info *tmp_device = device_header.next;
	sz_device_info *device_info = (sz_device_info *)sz_malloc(sizeof(sz_device_info));

	if(device_info == NULL)
	{
		err_debug("device_info sz_malloc failure");
		DEVICE_MAN_UNLOCK;
		return 1;
	}
	else
	{

		memcpy((unsigned char *)device_info,(unsigned char *)&device,sizeof(sz_device_info));
		device_info->next = NULL;
	}


	while(tmp_device != NULL)
	{
		if((memcmp(device_info->id,tmp_device->id,20) == 0) && (device_info->ep == tmp_device->ep))
		{
			debug("device already in list");
			tmp_device->status = device_info->status;
			sz_free((void *)device_info);
			DEVICE_MAN_UNLOCK;
			return 2;
		}
		tmp_device = tmp_device->next;
	}

	device_info->next = device_header.next;
	device_header.next = device_info;
	DEVICE_MAN_UNLOCK;
    debug("device_info:id:[%s]",device_info->id);
	return 3;
}

int device_mana_get_device(unsigned char *id,int ep,sz_device_info *device)
{
	if(id == NULL)
	{
		err_debug("id is NULL");
		return FAILURE;
	}
	DEVICE_MAN_LOCK;

	int i = 0;
	sz_device_info *find_device[10] = {NULL};
	sz_device_info *tmp_device = device_header.next;
	while(tmp_device != NULL)
	{
		if((memcmp(id,tmp_device->id,20) == 0) && (ep == tmp_device->ep))
		{
			if(device != NULL)
				memcpy(device,tmp_device,sizeof(sz_device_info));
			DEVICE_MAN_UNLOCK;
			return SUCCESS;
		}
		tmp_device = tmp_device->next;
	}
	DEVICE_MAN_UNLOCK;

	return FAILURE;
}




void sz_upData_device_info(unsigned char *upDataId)
{
	char sql[200] = {0};
	int rc = 0;
	int inset_result = 0;
  	char *zErrMsg = NULL;
	char **dbResult = NULL;
	int nRow, nColumn;
	int index;
	int i = 0;
	int j = 0, epCount;

	debug("--------recover device info-----------");

	sprintf(sql,"SELECT * FROM device_tb;");
	debug("sql[%s]",sql);
	//��ʹ�ûص�������ѯ���ݿ�

	rc = sqlite3_get_table(db,sql, &dbResult, &nRow,&nColumn, &zErrMsg);
	if (rc == SQLITE_OK)
	{
//		debug("nRow[%d]nColumn[%d]",nRow,nColumn);
		index = nColumn;
		for (i; i < nRow; i++)
		{
			unsigned char ieee[21] = {0};
			unsigned char addr[9] = {0};
			unsigned char rawdata[256] = {0};
			unsigned int ep = 0xffffffff;
			unsigned int pid = 0xffffffff;
			unsigned int did = 0xffffffff;
			unsigned int status = 0xffffffff;
			unsigned char dsp[40] = {0};
			int rawdataIsNull = 0;

//			debug("i[%d] nRow[%d]",i,nRow);
			for (j = 0; j < nColumn; j++)
			{
				if((strlen("ieee") == strlen(dbResult[j])) && (memcmp("ieee",dbResult[j],strlen("ieee")) == 0))
				{
					if(strlen(dbResult[index]) > 20)
						memcpy(ieee,dbResult[index],20);
					else
						strcpy(ieee,dbResult[index]);
				}
				else if((strlen("ep") == strlen(dbResult[j])) && (memcmp("ep",dbResult[j],strlen("ep")) == 0))
				{
					if(dbResult[index] == NULL)
					{
						err_debug("ep is NULL");
					}
					else
						ep = atoi(dbResult[index]);
				}
				else if((strlen("addr") == strlen(dbResult[j])) && (memcmp("addr",dbResult[j],strlen("addr")) == 0))
				{
					if(strlen(dbResult[index]) > 9)
						memcpy(addr,dbResult[index],9);
					else
						strcpy(addr,dbResult[index]);

				}
				else if((strlen("did") == strlen(dbResult[j])) && (memcmp("did",dbResult[j],strlen("did")) == 0))
				{
					if(dbResult[index] == NULL)
					{
						err_debug("did is NULL");
					}
					else
						did = atoi(dbResult[index]);
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
				else if((strlen("dsp") == strlen(dbResult[j])) && (memcmp("dsp",dbResult[j],strlen("dsp")) == 0))
				{
					if(strlen(dbResult[index]) > 40)
						memcpy(dsp,dbResult[index],40);
					else
						strcpy(dsp,dbResult[index]);
				}
				else if((strlen("rawdata") == strlen(dbResult[j])) && (memcmp("rawdata",dbResult[j],strlen("rawdata")) == 0))
				{	
					if(dbResult[index] == NULL)
					{
						err_debug("rawdata is NULL");
						rawdataIsNull = 1;
					}
					else
						strcpy(rawdata,dbResult[index]);
				}
				index++;
			}
			if(memcmp(upDataId, ieee, 20) == 0){
				sz06_delete_device(ieee);
				
	//			debug("%s", rawdata);
				for(epCount = 1; epCount < 17; epCount++)
				{	
					collect_data device;
					strncpy(device.id, ieee, 21);
					strncpy(device.addr, addr, 9);
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
				}
				
				if(!rawdataIsNull)
				{
					int rawdata_string_len = strlen(rawdata);
					unsigned char rawdata_hex[rawdata_string_len/2];
		    		hexStr2bytes(rawdata,rawdata_hex,rawdata_string_len/2);
					int dataStart = 6;
					int dataType = rawdata_hex[dataStart];
					double collectValue;
					int boolData, dec_pl;
					
					for(dataStart; dataStart < rawdata_string_len/2;)
					{
						//debug("updata data");
						ep = rawdata_hex[dataStart++] + 1;
						
						switch (rawdata_hex[dataStart++])
						{
							case 0:
								//debug("/0/");
								boolData = rawdata_hex[dataStart++];
								sz06_update_elelev(ieee, boolData, ep);
								break;
							case 1:
								//debug("/1/");
								boolData = rawdata_hex[dataStart++];
								sz06_update_digidal(ieee, boolData, ep);
								break;
							case 4:
								//debug("/4/");
								boolData = rawdata_hex[dataStart++];
								sz06_update_eleout(ieee, boolData, ep);
								break;					
							case 5:
								//debug("/5/");
								collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
								sz06_update_anal420(ieee, collectValue, ep);
								break;
							case 7:
								//debug("/7/");
								collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
							    sz06_update_volt3_3(ieee, collectValue, ep);
								break;		
							case 8:
								//debug("/8/");
								collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
								sz06_update_volt5_0(ieee, collectValue, ep);
								break;	
							case 9:
								//debug("/9/");
								if(rawdata_hex[dataStart++]){
									collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
									sz06_update_dstemp(ieee, collectValue, ep);
								}
								else{
									collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0);
									sz06_update_dstemp(ieee, collectValue, ep);
								}
								break;
							case 10:
								//debug("/10/");
								if(rawdata_hex[dataStart++]){
									collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
									sz06_update_pttemp(ieee, collectValue, ep);
								}
								else{
									collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0);
									sz06_update_pttemp(ieee, collectValue, ep);

								}
								break;
							case 11:
								//debug("/11/");
								if(rawdata_hex[dataStart++]){
									collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
									sz06_update_colltemp(ieee, collectValue, ep);
									collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
									sz06_update_collhumi(ieee, collectValue, ep);
								}
								else{
									collectValue = 0 - (rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0);
									sz06_update_colltemp(ieee, collectValue, ep);
									collectValue = rawdata_hex[dataStart++] + rawdata_hex[dataStart++]/10.0;
									sz06_update_collhumi(ieee, collectValue, ep);
								}
								break;
							default:
								break;
						}
					}
				}
			}

		}
	}
	else
	{
		err_debug("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}

	sqlite3_free_table(dbResult);
	//debug("device_index[%d]heart_step[%d]nRow[%d]heart_count[%d]",device_index,heart_step,nRow,heart_count);

	return ;
}


