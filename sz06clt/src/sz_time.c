#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <unistd.h>

#include "sz_time.h"
#include "sz_printf.h"
#include "sz_connect_drive.h"

int sz_time = 0;
pthread_mutex_t sz_time_mutex;


int sz_get_time(void *para)
{
	return sz_time;
}

void sz_time_init(void)
{
	pthread_t sz_time_thread_t;
	int ret = -1;
	int stacksize = 20480; /*thread 堆栈设置为10K，stacksize以字节为单位。*/
	pthread_attr_t attr;
	
	if(0 != pthread_mutex_init(&sz_time_mutex,NULL))
	{
		err_debug("--------------------> sz_time_mutex init error");
		exit(1);
	}
	
	sz_time = 0;

	return ;
}

void print_time_curr(void)
{
	time_t	nowTime;
	struct	tm * timeNow;
	struct timeval tv;

	/* get the system time */
	time(&nowTime);
	timeNow = localtime(&nowTime);

	gettimeofday( &tv, NULL );

	printf("[%04d-%02d-%02d %02d:%02d:%02d.%03d]", timeNow->tm_year + 1900, 
	timeNow->tm_mon + 1, timeNow->tm_mday,
	timeNow->tm_hour, timeNow->tm_min, timeNow->tm_sec,
	(int)(tv.tv_usec / 1000));
}

void sz_time_thread(time_cb_info_t *p)
{
	struct epoll_event ev, events[5];
	int nfds = -1;
	int epfd = -1;
	int epoll_count = 0;
	int time_cb_time = 0;

	while(1)
	{
		sleep(1);
		if(epfd < 0)
		{			
			if((epfd = epoll_create(5)) < 0)
			{
				err_debug("epoll_create failure");
				continue;
			}
		}

		while(1)
		{
			if(sz_time >= (time_cb_time + p->interval))
			{
				time_cb_time = sz_time;
				if((p != NULL) && (p->fun_time_cb != NULL))
					p->fun_time_cb();
			}
			nfds = epoll_wait(epfd,events,5,100);
			if(nfds == 0)
			{
				epoll_count = epoll_count + 1;
				if(epoll_count >= 10)
				{
					epoll_count = 0;
					SZ_TIME_LOCK;
					sz_time = sz_time + 1;
					SZ_TIME_UNLOCK;	
					debug("sz_time[%d]",sz_time);
				}
			}
			else if(nfds > 0)
			{
				err_debug("epoll_waite success");	
			}
			else
			{
				err_debug("epoll_waite failure[%s]",strerror(errno));
			}
		}
	}
}




