#ifndef _SZ_MALLOC_H_
#define _SZ_MALLOC_H_

#include <pthread.h>



#define PTR_MANAGE_LOCK						pthread_mutex_lock(&ptr_manage_lock)
#define PTR_MANAGE_UNLOCK						pthread_mutex_unlock(&ptr_manage_lock)

typedef struct ptr{
	struct ptr *prev;
	struct ptr *next;
	char *p;
}ptr_t;


extern ptr_t ptr_head;
extern pthread_mutex_t ptr_manage_lock;

void ptr_init(void);

void print_ptr(void);

#ifdef MEMERY_TEST

#define sz_malloc(size)					sz_malloc_t(size,__FILE__,__FUNCTION__, __LINE__)
#define sz_free(ptr)					sz_free_t(ptr,__FILE__,__FUNCTION__, __LINE__)


void *sz_malloc_t(int size,const char *file,const char * func,const int line);

void sz_free_t(void *ptr,const char *file,const char * func,const int line);

#else

void *sz_malloc(int size);

void sz_free(void *ptr);

#endif


#endif

