client: socket_client.c DH_client.o
	gcc socket_client.c DH_client.o -lgmp -o client   
dh_client.o: DH_client.c DH.h
	gcc -c DH_client.c -o DH_client.o
clean:
	rm *.o client
