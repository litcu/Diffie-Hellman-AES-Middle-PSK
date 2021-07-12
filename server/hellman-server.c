#include <stdio.h>

/* 接收客户端发送的数据 */
int rece_data()
{
    int data;
    printf("接收到的数据为:");
    scanf("%d", &data);
    return data;
}

/* 实现模运算 */
int fun_mod(int a, int b)
{
    //TODO:完成模运算的代码
    int c;
    printf("模运算结果为:");
    scanf("%d", &c);
}

/* 生成服务器私钥b */
int generate_b()
{
    int b;
    printf("b = ");
    scanf("%d", &b);
    return b;
}

/* 向客户端发送数据 */
int send_data()
{
    return 0;
}

int main()
{
    int p, g, b, A, B, s;
    // TODO: 
    p = rece_data();
    g = rece_data();
    b = generate_b();
    B = fun_mod(g, b);
    send_data();
    A = rece_data();
    s = fun_mod(A, b);
    printf("%d", s);

    return 0;
}
