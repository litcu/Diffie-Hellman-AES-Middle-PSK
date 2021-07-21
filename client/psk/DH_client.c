#include <stdio.h>
#include <time.h>
#include "DH.h"

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
    get_random_int(prime, (mp_bitcnt_t)128);
    while (!check_prime(prime))
    {
        // 得到比当前prime大的下一个素数
        // 并赋值给prime
        mpz_nextprime(prime, prime);
    }
}

/* generate private key of client */
void generate_pri_key(mpz_t pri_key)
{
    get_random_int(pri_key, (unsigned long int)64);
}
