#ifndef _SZ_TIME_H_
#define _SZ_TIME_H_

#include <pthread.h>


#define SZ_TIME(a)						sz_get_time(a)

#define SZ_TIME_LOCK						pthread_mutex_lock(&sz_time_mutex)
#define SZ_TIME_UNLOCK					pthread_mutex_unlock(&sz_time_mutex)


typedef int (*sz_time_cb)(void);


#pragma pack(1)

typedef struct time_cb_info{
	//struct time_cb_info *prev;
	sz_time_cb fun_time_cb;
	int interval;
	//struct time_cb_info *next;
}time_cb_info_t;

#pragma pack()


extern pthread_mutex_t sz_time_mutex;


void print_time_curr(void);

int sz_get_time(void *para);

void sz_time_init(void);

void sz_time_thread(time_cb_info_t *p);



#endif


