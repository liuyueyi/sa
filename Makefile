PROGRAM = kmc kmd
OBJS_KM = main.o config.o rsa.o encrypt.o
OBJS_KMD = kmd.o server.o
CC = gcc
CFLAGS = -Wall -g

all : $(PROGRAM)

kmc : $(OBJS_KM)
	$(CC) ${CFLAGS} -o kmc $(OBJS_KM) -lcrypto 

kmd : $(OBJS_KMD)
	$(CC) ${CFLAGS} -o kmd $(OBJS_KMD)

.c.o:
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: clean	
clean:
	-rm $(OBJS_KM) $(OBJS_KMD) *~
	-rm $(PROGRAM)
