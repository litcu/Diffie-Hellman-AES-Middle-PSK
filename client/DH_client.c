#include <stdio.h>
#include <time.h>
#include "DH.h"

/* 实现模运算 */
int fun_mod(int a, int b)
{
    //TODO:完成模运算的代码
    int c;
    printf("模运算结果为:");
    scanf("%d", &c);
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

// 检测一个数是否为素数，是则返回2，
// 可能是返回1，不是返回0
int check_prime(mpz_t prime)
{
    return mpz_probab_prime_p(prime, 30);
}

/* 生成客户端初始的大素数p */
void generate_p(mpz_t prime)
{
    get_random_int(prime, (mp_bitcnt_t)256);
    while (!check_prime(prime))
    {
        // 得到比当前prime大的下一个素数
        // 并赋值给prime
        mpz_nextprime(prime, prime);
    }
}

/* 将生成的p和g发送给服务器告知，并接收ACK */
int send_pubkey()
{
    //TODO: 完成发送公钥pg的代码
}

/* generate private key of client */
void generate_pri_key(mpz_t pri_key)
{
    get_random_int(pri_key, (unsigned long int)128);
}

/* 向服务器发送数据 */
int send_data(int data)
{
    //TODO: 将A发送给服务器
    return 0;
}

/* 接收服务器返回 */
int rece_data()
{
    int B;
    //TODO: 接收服务器返回的数据
    printf("B = ");
    scanf("%d", &B);
    return B;
}

int main()
{
    DH_key dh_key;
    mpz_t server_pub_key; // publick key(B) from server
    mpz_inits(dh_key.p, dh_key.g, dh_key.pri_key, dh_key.pub_key, dh_key.s, server_pub_key, NULL);
    generate_p(dh_key.p);
    gmp_printf("p = %Zd\n", dh_key.p);
    mpz_set_ui(dh_key.g, (unsigned long int)5); // base g = 5
    // TODO: send p and g to server and rece ACK

    generate_pri_key(dh_key.pri_key);
    gmp_printf("a = %Zd\n", dh_key.pri_key);
    // generate public key A of client
    mpz_powm(dh_key.pub_key, dh_key.g, dh_key.pri_key, dh_key.p);
    gmp_printf("A = %Zd\n", dh_key.pub_key);
    // TODO: rece B form server
    // mpz_set(server_pub_key, B)

    mpz_clears(dh_key.p, dh_key.g, dh_key.pri_key, dh_key.pub_key, dh_key.s, server_pub_key, NULL);

    return 0;
}
