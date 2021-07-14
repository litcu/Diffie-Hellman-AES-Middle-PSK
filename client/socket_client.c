#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "DH.h"
#include "aes_client.h"

#define MAX 1024

void exchange_dh_key(int sockfd, mpz_t s);

int main(int argc, char **argv)
{
    if (3 != argc)
    {
        printf("USAGE: ./client ServerIP ServerPort\nExample: ./client 127.0.0.1 8888");
        return 0;
    }
    int sockfd, connfd;
    struct sockaddr_in serv_addr, cli;
    // create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("Socket Failed!\n");
        exit(-1);
    }
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    // connect to server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("Connect to server failed!\n");
        exit(-1);
    }
    else
        printf("Connect to server success!\n");

    mpz_t dh_s;
    mpz_init(dh_s);
    exchange_dh_key(sockfd, dh_s);
    gmp_printf("s1 = %Zd\n", dh_s);
    mpz_clear(dh_s);

    return 0;
}

// exchange msg and get the AES secert key
// by Diffie Hellman protocol
void exchange_dh_key(int sockfd, mpz_t s)
{
    DH_key client_dh_key;
    mpz_t server_pub_key; // publick key(B) from server
    char buf[MAX];
    mpz_inits(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
              client_dh_key.pub_key, client_dh_key.s, server_pub_key, NULL);
    generate_p(client_dh_key.p);
    // gmp_printf("p = %Zd\n", client_dh_key.p);
    mpz_set_ui(client_dh_key.g, (unsigned long int)5); // base g = 5
    // send p to server
    bzero(buf, MAX);
    mpz_get_str(buf, 16, client_dh_key.p);
    write(sockfd, buf, sizeof(buf));

    // generate private key(a) of client
    generate_pri_key(client_dh_key.pri_key);
    // gmp_printf("a = %Zd\n", client_dh_key.pri_key);

    // calc public key A of client
    mpz_powm(client_dh_key.pub_key, client_dh_key.g, client_dh_key.pri_key,
             client_dh_key.p);
    // gmp_printf("A = %Zd\n", client_dh_key.pub_key);
    // recv public key(B) form server
    bzero(buf, MAX);
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(server_pub_key, buf, 16);
    // gmp_printf("B = %Zd\n", server_pub_key);

    // send public key(A) to server
    bzero(buf, MAX);
    mpz_get_str(buf, 16, client_dh_key.pub_key);
    write(sockfd, buf, sizeof(buf));

    // calc key s
    mpz_powm(client_dh_key.s, server_pub_key, client_dh_key.pri_key,
             client_dh_key.p);
    // gmp_printf("s = %Zd\n", client_dh_key.s);
    mpz_set(s, client_dh_key.s);

    mpz_clears(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
               client_dh_key.pub_key, client_dh_key.s, server_pub_key, NULL);
}