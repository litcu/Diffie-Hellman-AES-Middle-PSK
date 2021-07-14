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
void msg_to_pt(char *plain_text);
void send_encryp_msg(int sockfd, unsigned char *cipher_text);
void recv_encryp_msg(int sockfd, unsigned char *cipher_text);

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
    unsigned char plain_text[MAX], key[32];
    unsigned char cipher_text[MAX + EVP_MAX_BLOCK_LENGTH], tag[100];
    unsigned char pt[MAX + EVP_MAX_BLOCK_LENGTH];
    unsigned char iv[16];
    unsigned char aad[16] = "abcdefghijklmnop";
    int rst;
    mpz_get_str(key, 16, dh_s); // 将dh_s写入key
    gmp_printf("DH协议商讨出的密钥为：%Zd\n", dh_s);
    mpz_clear(dh_s); // 清除dh_s
    if (!PKCS5_PBKDF2_HMAC_SHA1(key, strlen(key), NULL, 0, 1000, 32, key))
    {
        printf("AES密钥生成错误！\n");
        exit(-1);
    }
    printf("处理后的AES密钥为：%s\n", key);

    while (!RAND_bytes(iv, sizeof(iv)))
        ;

    while (1)
    {
        bzero(plain_text, MAX);
        printf("要发送的明文: ");
        scanf("%s", plain_text);
        // AES加密，密文存储爱cipher_text
        bzero(cipher_text, MAX + EVP_MAX_BLOCK_LENGTH);
        encrypt(plain_text, strlen(plain_text), aad,
                sizeof(aad), key, iv, cipher_text, tag);
        write(sockfd, cipher_text, sizeof(cipher_text)); // 发送密文
        printf("发送的密文：%s\n\n", cipher_text);

        // 接收服务器发送的密文
        bzero(cipher_text, MAX + EVP_MAX_BLOCK_LENGTH);
        read(sockfd, cipher_text, sizeof(cipher_text));
        printf("接收到的密文：%s\n", cipher_text);

        // 解密
        bzero(pt, MAX + EVP_MAX_BLOCK_LENGTH);
        int rst = decrypt(cipher_text, sizeof(cipher_text), aad,
                          sizeof(aad), tag, key, iv, pt);
        if (rst > 0)
        {
            pt[rst] = '\0';
            printf("解密后的明文：%s\n", pt);
        }
        else
            printf("解密失败！\n");
        printf("\n\n");
    }

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
