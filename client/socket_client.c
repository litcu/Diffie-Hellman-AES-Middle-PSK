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
        printf("连接服务器失败!\n");
        exit(-1);
    }
    else
        printf("成功连接服务器！!\n");
    
    printf("***************************************DH***************************************\n");
    mpz_t dh_s;
    mpz_init(dh_s);
    exchange_dh_key(sockfd, dh_s);

    // 声明AES加密解密及通信所需要的变量
    unsigned char key[33];
    mpz_get_str(key, 16, dh_s); // 将dh_s写入key
    gmp_printf("DH得出密钥为：%Zd\n\n", dh_s);
    mpz_clear(dh_s); // 清除dh_s
    printf("*************************************DH结束*************************************\n\n\n");
    printf("**************************************AES**************************************\n");

    trans_msg(sockfd, key);

    return 0;
}

// 通过Diffie Hellman协议商讨出一个密钥s
void exchange_dh_key(int sockfd, mpz_t s)
{
    DH_key client_dh_key; // 客户端生成的密钥
    mpz_t server_pub_key; // 服务器公钥
    char buf[MAX];
    // 初始化mpz_t类型的变量
    mpz_inits(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
              client_dh_key.pub_key, client_dh_key.s, server_pub_key, NULL);
    printf("将生成大素数p并发送(回车继续)...\n");
    getchar();
    generate_p(client_dh_key.p);
    gmp_printf("p = %Zd\n\n", client_dh_key.p);
    mpz_set_ui(client_dh_key.g, (unsigned long int)5); // base g = 5
    // 将p发送给服务器
    bzero(buf, MAX);
    mpz_get_str(buf, 16, client_dh_key.p);
    write(sockfd, buf, sizeof(buf));

    // 生成客户端的私钥a
    printf("即将生成客户端私钥与公钥（回车继续）...\n");
    getchar();
    generate_pri_key(client_dh_key.pri_key);
    gmp_printf("客户端的私钥为%Zd\n\n", client_dh_key.pri_key);

    // 计算客户端的公钥A
    mpz_powm(client_dh_key.pub_key, client_dh_key.g, client_dh_key.pri_key,
             client_dh_key.p);
    gmp_printf("客户端的公钥为%Zd\n\n", client_dh_key.pub_key);
    // 接收服务器的公钥B
    bzero(buf, MAX);
    printf("等待接收服务器的公钥, 并发送客户端公钥...\n\n");
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(server_pub_key, buf, 16); // 按16进制将buf传递给server_pub_key
    gmp_printf("服务器的公钥为%Zd\n\n", server_pub_key);

    // 将客户端公钥发送给服务器
    bzero(buf, MAX);
    mpz_get_str(buf, 16, client_dh_key.pub_key); // 按16进制将公钥传递给buf
    write(sockfd, buf, sizeof(buf));

    // 客户端计算DH协议得到的密钥s
    printf("按下回车计算客户端经过DH协议得到的密钥...\n");
    getchar();
    mpz_powm(client_dh_key.s, server_pub_key, client_dh_key.pri_key,
             client_dh_key.p);
    mpz_set(s, client_dh_key.s); // 将密钥传递给s

    // 清除mpz_t变量
    mpz_clears(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
               client_dh_key.pub_key, client_dh_key.s, server_pub_key, NULL);
}

void trans_msg(int sockfd, unsigned char *key)
{
    unsigned char text[33];
    unsigned char expansion_key[15 * 16];
    // 密钥扩展，生成轮密钥
    ScheduleKey(key, expansion_key, AES256_KEY_LENGTH, AES256_ROUND);
    printf("初始化轮密钥完成！\n\n");
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