#ifndef _recmqtt_H_
#define _recmqtt_H_

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct collect_data_s{
	unsigned char id[21];
//	bool status;
	int ep;
	int elelev;//高低电平采集
	int digidal;//开关量采集
	int eleout;
	double anal420;
	double volt3_3;
	double volt5_0;
	double dstemp;
	double pttemp;
	double colltemp;
	double collhumi;
	struct collect_data_s *next;
}collect_data;


#define DEVICE_MANAGE_LOCK						pthread_mutex_lock(&device_manage_lock)
#define DEVICE_MANAGE_UNLOCK					pthread_mutex_unlock(&device_manage_lock)


int sz_mq_package_handle(unsigned char* topic,int len,unsigned char* payload);

int sz_mq_send_data_by_topic(char *topic,int data_len,unsigned char *data);

extern int register_device(unsigned char *id);

extern void sz06_collectDataInit(void);
extern int sz06_insetDevice(collect_data data);
extern int sz06_delete_device(unsigned char *id);
extern int sz06_update_elelev(unsigned char *id,int elelev, int ep);
extern int sz06_update_digidal(unsigned char *id,int digidal, int ep);
extern int sz06_update_eleout(unsigned char *id,int eleout, int ep);
extern int sz06_update_anal420(unsigned char *id,double anal420, int ep);
extern int sz06_update_volt3_3(unsigned char *id,double volt3_3, int ep);
extern int sz06_update_volt5_0(unsigned char *id,double volt5_0, int ep);
extern int sz06_update_dstemp(unsigned char *id,double dstemp, int ep);
extern int sz06_update_pttemp(unsigned char *id,double pttemp, int ep);
extern int sz06_update_colltemp(unsigned char *id,double colltemp, int ep);
extern int sz06_update_collhumi(unsigned char *id,double collhumi, int ep);

extern void heartbeat_thread_init(void);


#ifdef __cplusplus
}
#endif


#endif
