#ifndef _SZ_PRINTF_H_
#define _SZ_PRINTF_H_


#define NONEC 			"\033[m" 

#define RED 				"\033[0;32;31m" 

#define LIGHT_RED 		"\033[1;31m" 

#define GREEN 			"\033[0;32;32m" 

#define LIGHT_GREEN 		"\033[1;32m" 

#define BLUE 				"\033[0;32;34m" 

#define LIGHT_BLUE		"\033[1;34m" 

#define DARY_GRAY 		"\033[1;30m" 

#define CYAN 			"\033[0;36m" 

#define LIGHT_CYAN 		"\033[1;36m" 

#define PURPLE 			"\033[0;35m" 

#define L_PURPLE             	"\e[1;35m"

#define LIGHT_PURPLE 	"\033[1;35m" 

#define BROWN 			"\033[0;33m" 

#define YELLOW 			"\033[1;33m" 

#define LIGHT_GRAY 		"\033[0;37m" 

#define WHITE 			"\033[1;37m"






#define cs_debug(format,...)		do{	\
											printf(RED"[%s][%d]", __FILE__, __LINE__);	\
											printf(format, ##__VA_ARGS__); \
											printf("\n"NONEC);	\
										}while(0)

#define cr_debug(format,...)		do{	\
											printf(LIGHT_RED"[%s][%d]", __FILE__, __LINE__);	\
											printf(format, ##__VA_ARGS__); \
											printf("\n"NONEC);	\
										}while(0)


#define ls_debug(format,...)		do{	\
											printf(BLUE"[%s][%d]", __FILE__, __LINE__);	\
											printf(format, ##__VA_ARGS__); \
											printf("\n"NONEC);	\
										}while(0)
												
#define lr_debug(format,...)		do{	\
											printf(LIGHT_BLUE"[%s][%d]", __FILE__, __LINE__);	\
											printf(format, ##__VA_ARGS__); \
											printf("\n"NONEC);	\
										}while(0)


#define ms_debug(format,...)		do{	\
											printf(GREEN"[%s][%d]", __FILE__, __LINE__);	\
											printf(format, ##__VA_ARGS__); \
											printf("\n"NONEC);	\
										}while(0)
										

#define mr_debug(format,...)		do{	\
											printf(LIGHT_GREEN"[%s][%d]", __FILE__, __LINE__);	\
											printf(format, ##__VA_ARGS__); \
											printf("\n"NONEC);	\
										}while(0)

#define cls_debug(format,...)		do{	\
											printf(PURPLE"[%s][%d]", __FILE__, __LINE__);	\
											printf(format, ##__VA_ARGS__); \
											printf("\n"NONEC);	\
										}while(0)
										

#define clr_debug(format,...)		do{	\
											printf(LIGHT_PURPLE"[%s][%d]", __FILE__, __LINE__);	\
											printf(format, ##__VA_ARGS__); \
											printf("\n"NONEC);	\
										}while(0)


#define dis_debug(format,...)		do{	\
											printf(BROWN"[%s][%d]", __FILE__, __LINE__);	\
											printf(format, ##__VA_ARGS__); \
											printf("\n"NONEC);	\
										}while(0)


#define war_debug(format,...)		do{	\
												printf(YELLOW"[%s][%d]", __FILE__, __LINE__);	\
												printf(format, ##__VA_ARGS__); \
												printf("\n"NONEC);	\
											}while(0)


#define debug(format,...)			do{	\
											printf(LIGHT_GRAY"[%s][%d]", __FILE__, __LINE__);	\
											printf(format, ##__VA_ARGS__); \
											printf("\n"NONEC);	\
									}while(0)


#define err_debug(format,...)			do{	\
												printf(CYAN"[%s][%d]", __FILE__, __LINE__);	\
												printf(format, ##__VA_ARGS__); \
												printf("\n"NONEC);	\
										}while(0)





#endif

