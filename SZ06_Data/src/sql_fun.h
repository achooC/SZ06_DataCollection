#ifndef _SQL_FUN_H_
#define _SQL_FUN_H_

#include "sqlite3.h"
#include "sz06_info.h"


extern sqlite3 *db;

#define DEVICE_MAN_LOCK						pthread_mutex_lock(&device_man_lock)
#define DEVICE_MAN_UNLOCK					pthread_mutex_unlock(&device_man_lock)


/*
*
*	0:finded
*	1:could not finded
*	2:sql error
*
*/
int sz_is_table_exist(unsigned char * tablename);

/*
*
*	0:finded
*	1:could not finded
*	2:sql error
*
*/
int sz_is_columnName_exist(unsigned char *tb_name,unsigned char *device_name);

/*
*
*	0:success
*	1:failure
*/
int sz_inset_columnName(unsigned char *tb_name,unsigned char *column_name,unsigned char *columntype);

int sz_init_db(void);
extern int sz_init_device_db(sqlite3 *db);
extern int device_mana_inset_device(sz_device_info device);
extern int device_mana_inset_device(sz_device_info device);



#endif

