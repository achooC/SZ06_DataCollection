#build Makefile for SZO6DataAcquisition

MY_OBJECTS = main.o cJSON.o mqtt.o sz_connect_drive.o sz_time.o sz_malloc.o reciveMQTTmessage_handle.o ubus.o sz06_info.o sql_fun.o

MY_INCLUDE = -I$(CURDIR)

export MY_CFLAGS += -lmosquitto -lubus -lubox -lsqlite3 -lblobmsg_json -lssl -lcrypto -pthread -lm -ldl ${CFLAGS} -fPIC -g

MY_LIBS = -L./

SZ06_Data: $(MY_OBJECTS)
	$(CC) -o SZ06_Data $(MY_OBJECTS) $(MY_LIBS) $(LDFLAGS) $(MY_CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(MY_CFLAGS) $(MY_INCLUDES) $(LDFLAGS)

clean:
	rm *.o SZ06_Data

.PHONY : clean
