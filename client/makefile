client: socket_client.c DH_client.o aes_client.o
	gcc -w -O socket_client.c DH_client.o aes_client.o -lgmp -o client   
dh_client.o: DH_client.c DH.h
	gcc -c DH_client.c -o DH_client.o
aes_client.o: aes_client.c aes_client.h
	gcc -c aes_client.c -o aes_client.o
clean:
	rm *.o client
