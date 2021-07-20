middle: socket_middle.c DH_middle.o aes_middle.o
	gcc -w -O socket_middle.c DH_middle.o aes_middle.o -lgmp -lpcap -o middle
DH_middle.o: DH_middle.c DH.h
	gcc -c DH_middle.c -o DH_middle.o
aes_middle.o: aes_middle.c aes_middle.h
	gcc -c aes_middle.c -o aes_middle.o
clean:
	rm *.o middle