#include <stdio.h>

struct {
    int p; //大素数p
    int g; //g是p的一个原根
}pub_key;

/* 实现模运算 */
int fun_mod(int a, int b)
{
    //TODO:完成模运算的代码
    int c;
    printf("模运算结果为:");
    scanf("%d", &c);
}

/* 生成客户端初始的大素数p */
int generate_p()
{
    int p;
    printf("p = ");
    scanf("%d", &p);
    return p;
}

/* 生成p的原根g */
int generate_g(int p)
{
    int g;
    scanf("%d", &g);
    return g;
}

/* 将生成的p和g发送给服务器告知，并接收ACK */
int send_pubkey()
{
    //TODO: 完成发送公钥pg的代码
}

/* 生成A的私钥a */
int generate_a()
{
    int a;
    printf("a = ");
    scanf("%d", &a);
    return a;
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
    int a, A, B, s;
    pub_key.p = generate_p();
    pub_key.g = generate_g(pub_key.p);
    a = generate_a();
    A = fun_mod(pub_key.g, a);
    send_data(A);
    int B = rece_data();
    int s = fun_mod(B, a);
    printf("%d", s);

    return 0;
}
