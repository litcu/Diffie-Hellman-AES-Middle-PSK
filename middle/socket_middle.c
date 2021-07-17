#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "DH.h"
#include "aes.h"

void exchange_dh_key()
{

}

int main(int argc, char *argv)
{
    if (argc != 3)
    {
        printf("USAGE: ./middle ClientIP ServerIP");
        return 0;
    }

    Middle_DH_Key dh2server, dh2client; // 与服务器/客户端进行DH通信的结构体
    pcap_t *descr = NULL;        // 指向网络设备的指针
    int i = 0, cnt = 0;
    char errbuf[PCAP_ERRBUF_SIZE]; // 存放错误信息
    bzero(errbuf, PCAP_ERRBUF_SIZE);
    struct bpf_program filter;
    mpz_inits()
}