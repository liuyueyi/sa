PROGRAM = kmc kmd
OBJS_KM = main.o config.o encrypt.o rsa.o
OBJS_KMD = kmd.o server.o encrypt.o rsa.o
CC = gcc
CFLAGS = -Wall -g
# Where to install
INSTDIR = /usr/local/bin

all : $(PROGRAM)

kmc : $(OBJS_KM)
	$(CC) ${CFLAGS} -o kmc $(OBJS_KM) -lcrypto

kmd : $(OBJS_KMD)
	$(CC) ${CFLAGS} -o kmd $(OBJS_KMD) -lcrypto

.c.o:
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: clean	
clean:
	-rm $(OBJS_KM) $(OBJS_KMD) *~
	-rm $(PROGRAM)


.PHONY: install
install: kmc
	install -m 0755 kmc $(INSTDIR)/
	install -m 0755 kmd $(INSTDIR)/
	install -m 0755 kmd.sh $(INSTDIR)/kmd.sh
	
.PHONY: uninstall
uninstall:
	-rm $(INSTDIR)/kmc $(INSTDIR)/kmd $(INSTDIR)/kmd_init
