#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>


#include "sz_time.h"
#include "sz_printf.h"
#include "sz_malloc.h"
#include "sz_connect_drive.h"

pthread_mutex_t ptr_manage_lock;
ptr_t ptr_head;

void ptr_init(void)
{
	ptr_head.next = &ptr_head;
	ptr_head.prev = &ptr_head;
	ptr_head.p = NULL;

	return ;
}

static void inset_ptr(char *p)
{
	PTR_MANAGE_LOCK;
	ptr_t* ptr_next = ptr_head.next;
	ptr_t *tmp_ptr = (ptr_t *)malloc(sizeof(ptr_t));
	if(tmp_ptr != NULL)
	{
		tmp_ptr->prev = NULL;
		tmp_ptr->next = NULL;
		tmp_ptr->p = p;

		tmp_ptr->next = ptr_next;
		ptr_head.next = tmp_ptr;

		tmp_ptr->prev = &ptr_head;
		ptr_next->prev = tmp_ptr;
	}
	PTR_MANAGE_UNLOCK;
	return ;
}

static void del_ptr(char *p)
{
	if(p == NULL)
	{
		return ;
	}
	
	PTR_MANAGE_LOCK;
	ptr_t *prev_ptr = &ptr_head;
	ptr_t *next_ptr = NULL;
	ptr_t * tmp_ptr = ptr_head.next;
	while(tmp_ptr != &ptr_head)
	{
		next_ptr = tmp_ptr->next;
		if(tmp_ptr->p == p)
		{
			prev_ptr->next = next_ptr;
			next_ptr->prev = prev_ptr;
			
			free(tmp_ptr);
			tmp_ptr = NULL;
			PTR_MANAGE_UNLOCK;
			return ;
		}
		prev_ptr = tmp_ptr;
		tmp_ptr = next_ptr;
	}
	PTR_MANAGE_UNLOCK;
	return ;
}


void print_ptr(void)
{
	if(SZ_TIME(NULL)%20 != 1)
	{
		return ;
	}
	
	PTR_MANAGE_LOCK;
	debug("---------ptr start---------");
	int i = 0;
	ptr_t * tmp_ptr = ptr_head.next;
	while(tmp_ptr != &ptr_head)
	{
		debug("p[%d:%p]",i++,tmp_ptr->p);
		tmp_ptr = tmp_ptr->next;
	}
	debug("---------ptr end---------");
	PTR_MANAGE_UNLOCK;
	return ;
}


#ifdef MEMERY_TEST
void *sz_malloc_t(int size,const char *file,const char * func,const int line)
{
	void *p = malloc(size);
	if(p != NULL)
	{
		inset_ptr(p);
		printf(LIGHT_GRAY"[%s][%s][%d]",file,func,line);
		printf("malloc[%p]",p); 
		printf("\n"NONEC);
	}
	return p;
}

void sz_free_t(void *ptr,const char *file,const char * func,const int line)
{
	if(ptr == NULL)
		return ;
	printf(LIGHT_GRAY"[%s][%s][%d]",file,func,line);
	printf("free[%p]",ptr); 
	printf("\n"NONEC);
	del_ptr(ptr);
	free(ptr);
	return ;
}

#else


void *sz_malloc(int size)
{
	void *p = malloc(size);	
	return p;
}

void sz_free(void *ptr)
{
	if(ptr == NULL)
		return ;
	free(ptr);
	return ;
}

#endif





