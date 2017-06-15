CC=gcc
LIBS=-lpcap -lndpi
DEBUG=-g
all:main

main:main.c regroup.c
	$(CC) -o $@ $^ $(LIBS)
debug:main.c regroup.c
	$(CC) $(DEBUG) -o main $^ $(LIBS)
clean:
	rm -rf main
	
