#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "DH.h"

#define MAX 1024

void exchange_dh_key(int sockfd, mpz_t s);

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("USAGE: ./server ListenPort\nExample: ./server 8888");
        return 0;
    }
    int sockfd, connfd, len;
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
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));

    if ((bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) != 0)
    {
        printf("Bind Failed\n");
        exit(-1);
    }

    if ((listen(sockfd, 5)) != 0)
    {
        printf("Listen Failed!\n");
        exit(-1);
    }
    len = sizeof(cli);

    connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
    if (connfd < 0)
    {
        printf("Scccept Failed!\n");
        exit(-1);
    }

    // Function for chatting between client and server
    mpz_t dh_s;
    mpz_init(dh_s);
    exchange_dh_key(connfd, dh_s);
    gmp_printf("%Zd\n", dh_s);
    mpz_clear(dh_s);

    // After chatting close the socket
    close(sockfd);
}

void exchange_dh_key(int sockfd, mpz_t s)
{
    DH_key server_dh_key;
    mpz_t client_pub_key; // publick key(A) from client
    char buf[MAX];
    mpz_inits(server_dh_key.p, server_dh_key.g, server_dh_key.pri_key,
              server_dh_key.pub_key, server_dh_key.s, client_pub_key, NULL);
    mpz_set_ui(server_dh_key.g, (unsigned long int)5); // g = 5
    // recv p form client
    bzero(buf, MAX);
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(server_dh_key.p, buf, 16);
    // gmp_printf("p = %Zd\n", server_dh_key.p);

    // generate private key(b) of server
    generate_pri_key(server_dh_key.pri_key);
    // gmp_printf("b = %Zd\n", server_dh_key.pri_key);
    // calc the public key B of server
    mpz_powm(server_dh_key.pub_key, server_dh_key.g, server_dh_key.pri_key,
             server_dh_key.p);

    // send public key(B) of server to client
    bzero(buf, MAX);
    mpz_get_str(buf, 16, server_dh_key.pub_key);
    write(sockfd, buf, sizeof(buf));
    // gmp_printf("B = %Zd\n", server_dh_key.pub_key);

    // recv A form server
    bzero(buf, MAX);
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(client_pub_key, buf, 16);
    // gmp_printf("A = %Zd\n", client_pub_key);

    // calc key s
    mpz_powm(server_dh_key.s, client_pub_key, server_dh_key.pri_key,
             server_dh_key.p);
    // gmp_printf("s = %Zd\n", server_dh_key.s);
    mpz_set(s, server_dh_key.s);

    mpz_clears(server_dh_key.p, server_dh_key.g, server_dh_key.pri_key,
               server_dh_key.pub_key, server_dh_key.s, client_pub_key, NULL);
}