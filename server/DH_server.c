#include <stdio.h>
#include "DH.h"

/* 接收客户端发送的数据 */
int rece_data()
{
    int data;
    printf("接收到的数据为:");
    scanf("%d", &data);
    return data;
}

/* 生成一个随机数 */
void get_random_int(mpz_t z, mp_bitcnt_t n)
{
    mpz_t temp;                                 // 临时mpz_t变量，用于生成随机数，用完即废弃
    gmp_randstate_t grt;                        // gmp状态，用于生成随机数
    gmp_randinit_default(grt);                  // 使用默认算法初始化状态
    gmp_randseed_ui(grt, (mp_bitcnt_t)clock()); //将时间作为种子传入状态grt中
    mpz_rrandomb(z, grt, n);                    // 生成2^(n-1)到2^n-1之间一个随机数
    mpz_init(temp);
    gmp_randinit_default(grt);
    gmp_randseed_ui(grt, (mp_bitcnt_t)clock());
    do
    {
        mpz_urandomb(temp, grt, n); // 生成一个在0~2^n-1之间的随机数，有可能为0
    } while (mpz_cmp_ui(temp, (unsigned long int)0) <= 0);
    mpz_mul(z, z, temp); // 两个随机数相乘
    mpz_clear(temp);
    //gmp_printf("%Zd\n%Zd\n", temp, z);
}

/* 实现模运算 */
int fun_mod(int a, int b)
{
    //TODO:完成模运算的代码
    int c;
    printf("模运算结果为:");
    scanf("%d", &c);
}

/* generate private key of server */
void generate_pri_key(mpz_t pri_key)
{
    get_random_int(pri_key, (unsigned long int)128);
}

/* 向客户端发送数据 */
int send_data()
{
    return 0;
}

int main()
{
    DH_key dh_key;
    mpz_t client_pub_key; // publick key(B) from server
    mpz_inits(dh_key.p, dh_key.g, dh_key.pri_key, dh_key.pub_key, dh_key.s, client_pub_key, NULL);
    // TODO: recv p and g form client, and response ACK
    // gmp_printf("p = %Zd\n", dh_key.p);

    generate_pri_key(dh_key.pri_key);
    gmp_printf("a = %Zd\n", dh_key.pri_key);
    // calc the public key B of server
    mpz_powm(dh_key.pub_key, dh_key.g, dh_key.pri_key, dh_key.p);
    // TODO: rece A form server
    // mpz_set(server_pub_key, B)

    mpz_clears(dh_key.p, dh_key.g, dh_key.pri_key, dh_key.pub_key, dh_key.s, client_pub_key, NULL);

    return 0;
}
