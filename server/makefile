server: socket_server.c DH_server.o aes_server.o
	gcc -w -O socket_server.c DH_server.o aes_server.o -lgmp -o server
DH_server.o: DH_server.c DH.h
	gcc -c DH_server.c -lgmp -o DH_server.o
aes_server.o: aes_server.c
	gcc -c aes_server.c -o aes_server.o
clean:
	rm *.o server
