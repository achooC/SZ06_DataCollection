#ifndef _SZ_CONNECT_DRIVE_H_
#define _SZ_CONNECT_DRIVE_H_

#include <mosquitto.h>
#include <sys/socket.h>
#include <string.h>
#include "cJSON.h"
#include <pthread.h>


#define MAX_RECV_SIZE		10240

#define HEART_LOST_CONNECT_COUNT		4

#define	SUCCESS				0
#define	FAILURE				1
#define	CMDSTOP			2
#define	CMDCLOUD			3
#define	CMDLOCAL			4

#define CLIENT_STEP_SOCKET_INIT				0
#define CLIENT_STEP_EPOLL_INIT				1
#define CLIENT_STEP_LOOP						2

#define CONNECT_STEP_GETING_INIT			0
#define CONNECT_STEP_GETING_SERVERINFO		1
#define CONNECT_STEP_GETED_SERVERINFO		2
#define CONNECT_STEP_RECONNECT				3

#define DEFAULT_CONNECT_WITH_DEVICE		1
#define DEFAULT_CONNECT_WITHOUT_DEVICE	0


#define MQTT_ADMIN_NAME_MAX_LEN			100
#define MQTT_PASSWORD_MAX_LEN			100
#define MQTT_SUBSCRIBE_TOPIC_MAX_COUNT	10
#define MQTT_SUBSCRIBE_TOPIC_MAX_LEN		100
#define MQTT_PUBLISH_TOPCI_MAX_LEN			100


typedef struct cloud_s cloud_info_s;

typedef int (*sz_connect_cb)(cloud_info_s*);
typedef int (*sz_disconnect_cb)(cloud_info_s*);
typedef int (*sz_recv_cb)(cloud_info_s*);
typedef int (*sz_heartbeat_cb)(cloud_info_s*);
typedef int (*sz_heartbeat_timeout_cb)(cloud_info_s*);
typedef int (*sz_feed_watch_dog)(int);

typedef void (*mosqtt_connect_cb)(struct mosquitto *,void *,int);
typedef void (*mosqtt_disconnect_cb)(struct mosquitto *,void *,int);
typedef void (*mosqtt_message_cb)(struct mosquitto *,void *,const struct mosquitto_message *);
typedef int (*mosqtt_heartbeat_cb)(cloud_info_s*);

#pragma pack(1)

typedef struct {
	int fd;//connect socket fd
	int epfd;//epoll fd
	int heart_interval;// heart interval
	int reconnect_interval;// s
}tcp_clinet_t;

typedef struct {
	struct mosquitto *mosq;//connect socket fd
	int heart_interval;// heart interval
	int login_need;//0--don`t need;other valure is need
	int reconnect_interval;// s
	unsigned char name[MQTT_ADMIN_NAME_MAX_LEN];
	unsigned char password[MQTT_PASSWORD_MAX_LEN];
	int sub_topic_count;
	unsigned char sub_topic[MQTT_SUBSCRIBE_TOPIC_MAX_COUNT][MQTT_SUBSCRIBE_TOPIC_MAX_LEN];
	unsigned char pub_topic[MQTT_PUBLISH_TOPCI_MAX_LEN];
}mqtt_clinet_t;

typedef union{
    tcp_clinet_t tcp_client;
	mqtt_clinet_t mqtt_client;
}cloud_client_t;

typedef struct{
	mosqtt_connect_cb connect_callback;
	mosqtt_disconnect_cb disconnect_callback;
	mosqtt_message_cb mosqtt_message_callback;
	mosqtt_heartbeat_cb mosqtt_heartbeat_callback;
	sz_feed_watch_dog feed_watch_dog;
}mqtt_client_cb;

typedef struct{
	sz_connect_cb sz_connect_callback;
	sz_disconnect_cb sz_disconnect_callback;
	sz_recv_cb recive_callback;
	sz_heartbeat_cb heartbeat_callback;
	sz_heartbeat_timeout_cb heartbeat_timeout_callback;
	sz_feed_watch_dog feed_watch_dog;
}tcp_client_cb;

typedef union{
    	tcp_client_cb tcp_callback;
	mqtt_client_cb mqtt_callback;
}cloud_callback_t;

typedef struct{
	unsigned char mac_flag;// mac ok flag
	unsigned char ieee_flag;// ieee ok flag
	unsigned char ieee[21];// ieee address
	unsigned char mac[18];// mac address
}gw_info_t;

typedef struct{
	char server_addr[100];// cloud server address
	unsigned short port;// cloud server port
}server_info_t;

struct cloud_s{
	int connect_type;// 0 -- tcp;1 -- mqtt;
	server_info_t server_info;
	char key[32];// encryption key
	int version;//0--json no header;1--json header;2--aes;4--compress
	int verify;//
	int encryption;//need verify 0--no aes;1--aes;2--compress
	int heart_count;// if heart_count > 3,then shoutdown connect
	int watch_dog_time;//
	int step;//0---SOCKET_INIT;1---EPOLL_INIT;2---LOOP
	int status;//0---get service info;1---connecting
	int reqheart;//0---without device;1---with device
	int devcount;//device count in heart package
	int getserverct;//get server info count
	int gwregisted;//0--nuknown;1--not registed;2--registed
	cloud_client_t cloud_client;
	cloud_callback_t cloud_callback;
	gw_info_t gw_info;
	unsigned char *recv_buf;
	int recv_len;
};

#pragma pack()

void sz_client_connect_init(void);

int cloud_is_ip_add(char *add,int add_len);

void cloud_disconnect(cloud_info_s *p);

void cloud_fresh_heartcount(cloud_info_s *p);

int mqtt_client_init_mosq(cloud_info_s *client_info);

struct in_addr cloud_get_addr(char *add,int add_len);

int mqtt_client_init_duty(cloud_info_s *client_info);

int mqtt_client_loop(cloud_info_s *client_info);

int tcp_client_loop(cloud_info_s *client_info);

int tcp_init_socket(cloud_info_s *p);

int tcp_client_init_socket(cloud_info_s *client_info);

int tcp_client_init_epoll(cloud_info_s *client_info);

void *cloud_client_thread(void *p);

void cloud_init(cloud_info_s *cloud_info);




#endif

