#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "aes_client.h"
#include "DH.h"

#define MAX 1024

void exchange_dh_key(int sockfd, mpz_t s);
void trans_msg(int sockfd, unsigned char *key);

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

    // 声明AES加密解密及通信所需要的变量
    unsigned char key[33];
    mpz_get_str(key, 16, dh_s); // 将dh_s写入key
    gmp_printf("DH协议商讨出的密钥为：%Zd\n", dh_s);
    mpz_clear(dh_s); // 清除dh_s

    trans_msg(sockfd, key);

    return 0;
}

// 通过Diffie Hellman协议商讨出一个密钥s
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

void trans_msg(int sockfd, unsigned char *key)
{
    unsigned char text[33];
    unsigned char expansion_key[15 * 16];
    // 密钥扩展，生成轮密钥
    ScheduleKey(key, expansion_key, AES256_KEY_LENGTH, AES256_ROUND);
    while (1)
    {
        // 输入要发送的明文
        bzero(text, 33);
        printf("要发送的明文: ");
        scanf("%s", text);
        // AES256加密
        AesEncrypt(text, expansion_key, AES256_ROUND);
        printf("密文为:\n");
        for (int i = 0; i < 32; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        // 发送密文
        write(sockfd, text, sizeof(text));
        printf("发送成功！\n等待服务器回复...\n");
        // 接收服务器发送的密文
        bzero(text, 33);
        read(sockfd, text, sizeof(text));
        printf("服务器端发送的密文：\n");
        for (int i = 0; i < 32; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        // AES256解密
        Contrary_AesEncrypt(text, expansion_key, AES256_ROUND);
        printf("解密后的明文：");
        for (int i = 0; i < 32; ++i)
            printf("%c", text[i]);
        printf("\n\n\n");
    }
}