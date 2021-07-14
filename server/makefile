server: socket_server.c DH_server.o
	gcc socket_server.c DH_server.o -lgmp -o server
DH_server.o: DH_server.c DH.h
	gcc -c DH_server.c -lgmp -o DH_server.o
clean:
	rm *.o server
