#include <stdio.h>
#include <unistd.h>
#include <libubus.h>
#include <libubox/utils.h>
#include <math.h>
#include <time.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/crypto.h> 
#include <openssl/sha.h> 
#include <openssl/opensslv.h> 
#include <sys/stat.h>
#include <sys/wait.h>  
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h> 
#include <sys/timeb.h>
#include <mosquitto.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "cJSON.h"
#include "sz_connect_drive.h"
#include "sz_printf.h"
#include "sz_time.h"






void sz_client_connect_init(void)
{
	while(1)
	{
		sleep(1);
		if(MOSQ_ERR_SUCCESS != mosquitto_lib_init())
		{
			err_debug("mosquitto_lib_init failure");
			continue;
		}
		else
			break;
	}
}


int cloud_is_ip_add(char *add,int add_len)
{
	int i = 0;

	for(i = 0;i < add_len;i++)
	{
		if(((add[i] > '9')||(add[i] < '0'))&&(add[i] != '.'))
			return FAILURE;
	}
	return SUCCESS;
}

void cloud_disconnect(cloud_info_s *p)
{
	p->heart_count = p->heart_count + 1;
	if(p->heart_count >= HEART_LOST_CONNECT_COUNT)
	{
		debug("\n\n\n");
		debug("server no response ...");
		debug("\n\n\n");
		if(p->connect_type == 0)
		{
			close(p->cloud_client.tcp_client.fd);
			p->cloud_client.tcp_client.fd = -1;
			close(p->cloud_client.tcp_client.epfd);
			p->cloud_client.tcp_client.epfd = -1;
			p->verify = 0;
		}
		else if(p->connect_type == 1)
		{
			mosquitto_destroy(p->cloud_client.mqtt_client.mosq);
			p->cloud_client.mqtt_client.mosq = NULL;	
			p->verify = 0;
		}
	}
	return ;
}


void cloud_fresh_heartcount(cloud_info_s *p)
{
	p->heart_count = 0;
	return ;
}


int mqtt_client_init_mosq(cloud_info_s *client_info)
{
	mqtt_clinet_t *mqtt_client = &client_info->cloud_client.mqtt_client;
	//char *client_id = "g:nx4ibw:Chinotech_GW_SZ_BA:PG_Hall_Demo_GW_01";
	//debug("client_id[%s]",client_id);

	client_info->verify = 0;
	
	if(mqtt_client->mosq)
	{
		mosquitto_destroy(mqtt_client->mosq);
		mqtt_client->mosq = NULL;
	}
	mqtt_client->mosq = mosquitto_new(NULL, true, NULL);
	if(mqtt_client->mosq == NULL)
	{
		err_debug("mosq init error");
		return FAILURE;
	}
	else
	{
		debug("mosq init success");
		client_info->verify = 0;
		memset(client_info->key,0,32);
		return SUCCESS;	
	}
	
}

struct in_addr cloud_get_addr(char *add,int add_len)
{	
	struct hostent *host;	
	struct in_addr sin_add;	
	sin_add.s_addr = 0xffffffff;	
	char str[32] = {0};
	int i = 0;
	debug("addr is[%s]",add);		

	if(SUCCESS == cloud_is_ip_add(add,add_len))	
	{		
		if(0 == inet_aton(add,&sin_add))			
			err_debug("ip addr format error");		
		else			
			debug("get ip[%s]",inet_ntoa(sin_add));	
	}	
	else	
	{		
		if((host=gethostbyname(add))==NULL)			
			err_debug("gethostbyname error");		
		else		
		{			
			if(host->h_addrtype == AF_INET)			
			{				
				for (i = 0; host->h_addr_list[i]; i++)
				{
					debug("\t%s\n", inet_ntop(host->h_addrtype,  host->h_addr_list[i], str, sizeof(str)-1));
				}
				sin_add = *((struct in_addr *)host->h_addr); 				
				debug("get ip by hostname[%s]",inet_ntoa(sin_add));			
			}			
			else				
				err_debug("conn`t get ipv4");		
		}	
	}	
	return sin_add;
}


int mqtt_client_init_duty(cloud_info_s *client_info)
{
	int i = 0;
	int rc;
	unsigned char err_msg[100] = {0};
	mqtt_clinet_t *mqtt_client = &client_info->cloud_client.mqtt_client;
	mqtt_client_cb *mqtt_callback = &client_info->cloud_callback.mqtt_callback;
	server_info_t *server_info = &client_info->server_info;
	
	mosquitto_connect_callback_set(mqtt_client->mosq,mqtt_callback->connect_callback);
	mosquitto_disconnect_callback_set(mqtt_client->mosq,mqtt_callback->disconnect_callback);
	mosquitto_publish_callback_set(mqtt_client->mosq,NULL);
	mosquitto_message_callback_set(mqtt_client->mosq,mqtt_callback->mosqtt_message_callback);

	struct in_addr host_addr;
	host_addr = cloud_get_addr(server_info->server_addr,strlen(server_info->server_addr));
	if(host_addr.s_addr == 0xffffffff)
	{
		err_debug("get sin_add error");
		return FAILURE;
	}

	if(mqtt_client->login_need == 1)
	{
		rc = mosquitto_username_pw_set(mqtt_client->mosq,mqtt_client->name,mqtt_client->password);
		if(rc != MOSQ_ERR_SUCCESS)
		{
			err_debug("mosquitto_username_pw_set rc[%d] error[%s]",rc,strerror(rc));
			return FAILURE;
		}
	}
	
    	rc = mosquitto_connect(mqtt_client->mosq,(const char *)inet_ntoa(host_addr),server_info->port, 60);
	if(rc != MOSQ_ERR_SUCCESS)
	{
		err_debug("\n\nconnect[%s:%d] socket init success\n\n",client_info->server_info.server_addr,client_info->server_info.port);
		err_debug("mosquitto_connect rc[%d] error[%s]",rc,strerror(rc));
		return FAILURE;
	}

	for(i = 0;i < mqtt_client->sub_topic_count;i++)
	{
		debug("mqtt_client->sub_topic[%s]",mqtt_client->sub_topic[i]);
		rc = mosquitto_subscribe(mqtt_client->mosq, NULL,mqtt_client->sub_topic[i],0);//"#", 0);
		if(rc != MOSQ_ERR_SUCCESS)
		{
			err_debug("mosquitto_subscribe rc[%d] error[%s]",rc,strerror(rc));
			return FAILURE;
		}
	}

	return SUCCESS;
}


int mqtt_client_loop(cloud_info_s *client_info)
{
	int rc = 0;
	int heartbeat_time = 0;
	int last_feed_dog_time = 0;
	unsigned char err_msg[100] = {0};
	mqtt_clinet_t *mqtt_client = &client_info->cloud_client.mqtt_client;
	mqtt_client_cb *mqtt_callback = &client_info->cloud_callback.mqtt_callback;

	heartbeat_time = SZ_TIME(NULL) - mqtt_client->heart_interval + 6;
	while(1)
	{
		if((heartbeat_time == 0) || (SZ_TIME(NULL) - heartbeat_time >= mqtt_client->heart_interval))
		{
			if(mqtt_callback->mosqtt_heartbeat_callback)
			{
				if(SUCCESS == mqtt_callback->mosqtt_heartbeat_callback(client_info))
				{
					if(heartbeat_time == 0)
						heartbeat_time = 1;
					else
						heartbeat_time = SZ_TIME(NULL);
				}
			}
			else
				heartbeat_time = SZ_TIME(NULL);
		}

		if(SZ_TIME(NULL) - last_feed_dog_time >= client_info->watch_dog_time)
		{
			if(client_info->connect_type == 0)// tcp
			{
				if(client_info->cloud_callback.tcp_callback.feed_watch_dog != NULL)
					client_info->cloud_callback.tcp_callback.feed_watch_dog(client_info->watch_dog_time);
			}
			else if(client_info->connect_type == 1)//mqtt
			{
				if(client_info->cloud_callback.mqtt_callback.feed_watch_dog != NULL)
					client_info->cloud_callback.mqtt_callback.feed_watch_dog(client_info->watch_dog_time);
			}

			last_feed_dog_time = SZ_TIME(NULL);
		}
		
		rc = mosquitto_loop(mqtt_client->mosq,2000, 1);
		if(rc)
		{
			err_debug("mosquitto rc[%d] error[%s]  sleep 1s........",rc,strerror(rc));
			sleep(1);
			return FAILURE;			
		}
	}
}


int tcp_client_loop(cloud_info_s *client_info)
{
	int i = 0;
	struct epoll_event ev, events[20];
	int nfds = -1;
	int heartbeat_time = 0;
	int last_feed_dog_time = 0;
	tcp_clinet_t *tcp_client = &client_info->cloud_client.tcp_client;
	tcp_client_cb *tcp_callback = &client_info->cloud_callback.tcp_callback;
	
	ev.data.fd = tcp_client->fd;
	ev.events= EPOLLIN|EPOLLHUP|EPOLLERR|EPOLLONESHOT|EPOLLPRI;
	if(0 != epoll_ctl(tcp_client->epfd,EPOLL_CTL_ADD,tcp_client->fd,&ev))
	{
		err_debug("epoll_ctl error");
		return FAILURE;
	}

	if(tcp_callback->sz_connect_callback)
		tcp_callback->sz_connect_callback(client_info);

	while(1)
	{
		if((heartbeat_time == 0) || (SZ_TIME(NULL) - heartbeat_time >= tcp_client->heart_interval))
		{
			if(tcp_callback->heartbeat_callback)
			{
				if(SUCCESS == tcp_callback->heartbeat_callback(client_info))
				{
					if(heartbeat_time == 0)
						heartbeat_time = 1;
					else
						heartbeat_time = SZ_TIME(NULL);
				}
			}
			else
				heartbeat_time = SZ_TIME(NULL);
		}

		if(SZ_TIME(NULL) - last_feed_dog_time >= client_info->watch_dog_time)
		{
			if(client_info->connect_type == 0)// tcp
			{
				if(client_info->cloud_callback.tcp_callback.feed_watch_dog != NULL)
					client_info->cloud_callback.tcp_callback.feed_watch_dog(client_info->watch_dog_time);
			}
			else if(client_info->connect_type == 1)//mqtt
			{
				if(client_info->cloud_callback.mqtt_callback.feed_watch_dog != NULL)
					client_info->cloud_callback.mqtt_callback.feed_watch_dog(client_info->watch_dog_time);
			}

			last_feed_dog_time = SZ_TIME(NULL);
		}

		if(client_info->status == CONNECT_STEP_RECONNECT)
		{
			client_info->status = CONNECT_STEP_GETED_SERVERINFO;
			return FAILURE;
		}
		
		if((tcp_client->epfd <= 0) || (tcp_client->fd < 0))
			return FAILURE;
		nfds=epoll_wait(tcp_client->epfd,events,20,1000);
		for(i = 0;i < nfds;i++)
		{
			if(events[i].data.fd == tcp_client->fd)
			{
				if(events[i].events&(EPOLLPRI | EPOLLIN))
				{
					int temp_len = recv(tcp_client->fd,client_info->recv_buf + client_info->recv_len,MAX_RECV_SIZE - client_info->recv_len - 1, 0);
					print_time_curr();
					debug("->>recv len[%d]",temp_len);
					if(temp_len< 0)
					{
						err_debug("\n\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&\n\n");
						err_debug("&&&&&&&&&&&&&&&&&&&&&&recv data error[%d:%s]&&&&&&&&&&&&&&&&&&&&&&&&",errno,strerror(errno));
						err_debug("\n\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&\n\n");
						return FAILURE;
					}
					else if(temp_len == 0)
					{
						err_debug("server close tcp");
						return FAILURE;
					}
					else
					{
						int j = 0;
						printf("tcp recv:");
						for(j = 0;j < temp_len;j++)
						{
							if(j%25 == 0)
								printf("\n");
							printf("%02x ",(unsigned char)client_info->recv_buf[j + client_info->recv_len]);
						}
						printf("\n");
						
						client_info->recv_len = client_info->recv_len + temp_len;
						if(tcp_callback->recive_callback)
							tcp_callback->recive_callback(client_info);
						memset(client_info->recv_buf,0,MAX_RECV_SIZE);
						client_info->recv_len = 0;
						ev.data.fd = tcp_client->fd;
						ev.events= EPOLLIN|EPOLLHUP|EPOLLERR|EPOLLONESHOT|EPOLLPRI;
					    if(0 != epoll_ctl(tcp_client->epfd,EPOLL_CTL_MOD,tcp_client->fd,&ev))
					    {
					    	err_debug("epoll_ctl error");
						return FAILURE;
					    }
					}
				}
				if(events[i].events&EPOLLHUP)
				{
					err_debug("tcp has been hang up");
					return FAILURE;
				}
				if(events[i].events&EPOLLERR)
				{
					err_debug("tcp error");
					return FAILURE;
				}
			}
		}
	}
}


int tcp_init_socket(cloud_info_s *p)
{
	const unsigned int chOpt = 1;
	struct sockaddr_in server_addr;
	struct in_addr sin_add;
	int sockfd = -1;
	int flags;	 
	server_info_t *server_info = &p->server_info;
	tcp_clinet_t *tcp_client = &p->cloud_client.tcp_client;

	sin_add = cloud_get_addr(server_info->server_addr,strlen(server_info->server_addr));
	if(sin_add.s_addr == 0xffffffff)
	{
		err_debug("get sin_add error");
		return FAILURE;
	}
	debug("port[%d]",server_info->port);
	bzero(&server_addr,sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_info->port);
	server_addr.sin_addr = sin_add;

	if((sockfd=socket(AF_INET,SOCK_STREAM,0)) < 0) // AF_INET:Internet;SOCK_STREAM:TCP
	{
		err_debug("Socket create Error");
		return FAILURE;
	}
	if
(setsockopt(sockfd,IPPROTO_TCP,TCP_NODELAY,&chOpt,sizeof(int)) == -1)
	{
		close(sockfd);
		err_debug("set socket opt error");
		return FAILURE;
	}
	/*if(fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0)|O_NONBLOCK) == -1)
	{ 
        close(sockfd);
		debug(DEBUG_ERROR,"set socket fcntl error");
		return FAILURE; 
    }*/
	
	   	
	    
	flags = fcntl(sockfd, F_GETFL, 0);	  
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);	
	
	if(connect(sockfd,(struct sockaddr *)(&server_addr),sizeof(struct sockaddr)) < 0)
	{
		int error;
		int code;
		fd_set wset;	 
		struct timeval tval;
		tval.tv_sec = 3;
		tval.tv_usec = 0;
		socklen_t len = sizeof(error);
		FD_ZERO(&wset);
		FD_SET(sockfd, &wset);
		if(select(sockfd+1, NULL, &wset, NULL, &tval) > 0)
		{
			
			if (FD_ISSET(sockfd, &wset)) 
			{	   
				len = sizeof(error); 	
				code = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);	  
				/* �����������Solarisʵ�ֵ�getsockopt����-1��   
				* ��pending error���ø�errno. Berkeleyʵ�ֵ�   
				* getsockopt����0, pending error���ظ�error.	
				* ������Ҫ������������� */    
				if(error == 0) 
				{
					fcntl(sockfd, F_SETFL, flags);  /* restore file status flags */    
					tcp_client->fd = sockfd;
					return SUCCESS;
				}
				else 
				{
					close(sockfd);
					err_debug("Connect Error");
					return FAILURE;
				}
			} 
			else 
			{
				close(sockfd);
				err_debug("Connect Error");
				return FAILURE;
			}
		} 
		else 
		{
			close(sockfd);
			err_debug("Connect Error");
			return FAILURE;
		}
	}
	else
	{
		fcntl(sockfd, F_SETFL, flags);  /* restore file status flags */ 
		tcp_client->fd = sockfd;
		return SUCCESS;
	}
}



int tcp_client_init_socket(cloud_info_s *client_info)
{
	tcp_clinet_t *tcp_client = &client_info->cloud_client.tcp_client;

	client_info->verify = 0;

	if(tcp_client->fd > 0)
	{
		close(tcp_client->fd);
		tcp_client->fd = -1;
	}
	
	if((tcp_client->fd < 0) && (FAILURE == tcp_init_socket(client_info)))
	{
		err_debug("socket init error");
		return FAILURE;
	}
	else
	{
		debug("\n\nconnect[%s:%d] socket init success\n\n",client_info->server_info.server_addr,client_info->server_info.port);
		client_info->verify = 0;
		memset(client_info->key,0,32);
		return SUCCESS;	
	}
}


int tcp_client_init_epoll(cloud_info_s *client_info)
{
	tcp_clinet_t *tcp_client = &client_info->cloud_client.tcp_client;

	if(tcp_client->epfd > 0)
	{
		close(tcp_client->epfd);
		tcp_client->epfd = -1;
	}
	
	if((tcp_client->epfd < 0) && ((tcp_client->epfd = epoll_create(5)) < 0))
	{
		err_debug("epoll init error");
		return FAILURE;
	}
	else
	{
		debug("epoll init success");
		return SUCCESS;
	}
}


void *cloud_client_thread(void *p)
{
	int ret = FAILURE;
	cloud_info_s *client_info = (cloud_info_s *)p;
	server_info_t *server_info = &client_info->server_info;

	while(1)
	{
		if(client_info->connect_type == 0)// tcp
		{
			if(client_info->cloud_callback.tcp_callback.feed_watch_dog != NULL)
				client_info->cloud_callback.tcp_callback.feed_watch_dog(client_info->watch_dog_time);
		}
		else if(client_info->connect_type == 1)//mqtt
		{
			if(client_info->cloud_callback.mqtt_callback.feed_watch_dog != NULL)
				client_info->cloud_callback.mqtt_callback.feed_watch_dog(client_info->watch_dog_time);
		}
		
		switch(client_info->step)
		{
			case CLIENT_STEP_SOCKET_INIT:
			{
				if(client_info->connect_type == 0)// tcp
					ret = tcp_client_init_socket(client_info);
				else if(client_info->connect_type == 1)//mqtt
					ret = mqtt_client_init_mosq(client_info);
				else
				{
					err_debug("unknown connect type[%d]",client_info->connect_type);
					sleep(5);
				}
				if(ret == SUCCESS)
					client_info->step = CLIENT_STEP_EPOLL_INIT;
				else
				{
					if(client_info->connect_type == 0)// tcp
					{
						if(client_info->cloud_callback.tcp_callback.sz_disconnect_callback)
							client_info->cloud_callback.tcp_callback.sz_disconnect_callback(client_info);
						sleep(client_info->cloud_client.tcp_client.reconnect_interval);
					}
					else if(client_info->connect_type == 1)//mqtt
						sleep(client_info->cloud_client.mqtt_client.reconnect_interval);
					else 
					{
						err_debug("unknown connect type[%d] sleep 5s...",client_info->connect_type);
						sleep(5);
					}
				}
				break;
			}
			case CLIENT_STEP_EPOLL_INIT:
			{
				if(client_info->connect_type == 0)// tcp
					ret = tcp_client_init_epoll(client_info);
				else if(client_info->connect_type == 1)//mqtt
					ret = mqtt_client_init_duty(client_info);
				else 
					err_debug("unknown connect type[%d]",client_info->connect_type);
				if(ret == SUCCESS)
					client_info->step = CLIENT_STEP_LOOP;
				else
				{
					client_info->step = CLIENT_STEP_SOCKET_INIT;
					if(client_info->connect_type == 0)// tcp
						sleep(client_info->cloud_client.tcp_client.reconnect_interval);
					else if(client_info->connect_type == 1)//mqtt
						sleep(client_info->cloud_client.mqtt_client.reconnect_interval);
					else 
					{
						err_debug("unknown connect type[%d] sleep 5s...",client_info->connect_type);
						sleep(5);
					}
				}
				break;
			}
			case CLIENT_STEP_LOOP:
			{
				if(client_info->connect_type == 0)// tcp
				{
					tcp_client_loop(client_info);
					if(client_info->cloud_callback.tcp_callback.sz_disconnect_callback)
						client_info->cloud_callback.tcp_callback.sz_disconnect_callback(client_info);
				}
				else if(client_info->connect_type == 1)//mqtt
					mqtt_client_loop(client_info);
				else 
					err_debug("unknown connect type[%d]",client_info->connect_type);
				if(client_info->connect_type == 0)// tcp
					sleep(client_info->cloud_client.tcp_client.reconnect_interval);
				else if(client_info->connect_type == 1)//mqtt
					sleep(client_info->cloud_client.mqtt_client.reconnect_interval);
				else 
				{
					err_debug("unknown connect type[%d] sleep 5s...",client_info->connect_type);
					sleep(5);
				}
				client_info->step = CLIENT_STEP_SOCKET_INIT;
				break;
			}
			default:
			{
				err_debug("unknown connect step[%d]",client_info->step);
				break;
			}
		}
	}
}





void cloud_init(cloud_info_s *cloud_info)
{
	pthread_t cloud_thread_t;
	int ret = -1;	
	int stacksize = 40960; /*thread ��ջ����Ϊ20K��stacksize���ֽ�Ϊ��λ��*/
	pthread_attr_t attr;
	
	ret = pthread_attr_init(&attr); /*��ʼ���߳�����*/
	if (ret != 0)
	{
		err_debug("pthread_attr_init failure");
		exit(1);
	}
	
	ret = pthread_attr_setstacksize(&attr, stacksize);
	if(ret != 0)
	{
		err_debug("ptread_attr_setstacksize failure");
		exit(1);
	}	

	ret = pthread_create(&cloud_thread_t,&attr,cloud_client_thread,(void *)cloud_info);
	if(ret != 0)
	{
		err_debug(" pthread type[%d] creates error:%s ",cloud_info->connect_type,strerror(errno)); 
		exit(1);
	}
	else
		debug(" pthread type[%d] creates successfully ",cloud_info->connect_type); 

	ret = pthread_attr_destroy(&attr); /*����ʹ���߳����ԣ���������*/
	if(ret != 0)
	{
		err_debug("pthread_attr_destroy failure");
		return;
	}

	return ;
}






