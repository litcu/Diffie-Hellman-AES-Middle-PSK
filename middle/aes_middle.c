#include <stdio.h>
#include "aes_middle.h"

// 有限域*2乘法
static unsigned char x2time(unsigned char x)
{
    if (x & 0x80)
        return (((x << 1) ^ 0x1B) & 0xFF);
    return x << 1;
}

// 有限域*3乘法
static unsigned char x3time(unsigned char x)
{
    return (x2time(x) ^ x);
}

// 有限域*4乘法
static unsigned char x4time(unsigned char x)
{
    return (x2time(x2time(x)));
}

// 有限域*8乘法
static unsigned char x8time(unsigned char x)
{
    return (x2time(x2time(x2time(x))));
}

// 有限域9乘法
static unsigned char x9time(unsigned char x) //9:1001
{
    return (x8time(x) ^ x);
}

// 有限域*B乘法
static unsigned char xBtime(unsigned char x) //B:1011
{
    return (x8time(x) ^ x2time(x) ^ x);
}

// 有限域*D乘法
static unsigned char xDtime(unsigned char x) //D:1101
{
    return (x8time(x) ^ x4time(x) ^ x);
}

// 有限域*E乘法
static unsigned char xEtime(unsigned char x) //E:1110
{
    return (x8time(x) ^ x4time(x) ^ x2time(x));
}

// AES列混合
static void MixColumns(unsigned char *col) //列混合
{
    unsigned char tmp[4];
    int i;
    // col代表一列的基地址，col+4为下一列的基地址
    for (i = 0; i < 4; i++, col += 4)
    {
        tmp[0] = x2time(col[0]) ^ x3time(col[1]) ^ col[2] ^ col[3];
        tmp[1] = col[0] ^ x2time(col[1]) ^ x3time(col[2]) ^ col[3];
        tmp[2] = col[0] ^ col[1] ^ x2time(col[2]) ^ x3time(col[3]);
        tmp[3] = x3time(col[0]) ^ col[1] ^ col[2] ^ x2time(col[3]);
        // 保存列混合完成后的值
        col[0] = tmp[0];
        col[1] = tmp[1];
        col[2] = tmp[2];
        col[3] = tmp[3];
    }
}

// AES逆向列混合
static void Contrary_MixColumns(unsigned char *col)
{
    unsigned char tmp[4];
    int x;
    for (x = 0; x < 4; x++, col += 4)
    {
        tmp[0] = xEtime(col[0]) ^ xBtime(col[1]) ^ xDtime(col[2]) ^ x9time(col[3]);
        tmp[1] = x9time(col[0]) ^ xEtime(col[1]) ^ xBtime(col[2]) ^ xDtime(col[3]);
        tmp[2] = xDtime(col[0]) ^ x9time(col[1]) ^ xEtime(col[2]) ^ xBtime(col[3]);
        tmp[3] = xBtime(col[0]) ^ xDtime(col[1]) ^ x9time(col[2]) ^ xEtime(col[3]);
        col[0] = tmp[0];
        col[1] = tmp[1];
        col[2] = tmp[2];
        col[3] = tmp[3];
    }
}

// AES行移位
static void ShiftRows(unsigned char *col)
{
    unsigned char t;
    // 左移1位
    t = col[1];
    col[1] = col[5];
    col[5] = col[9];
    col[9] = col[13];
    col[13] = t;
    //左移2位，交换2次数字来实现
    t = col[2];
    col[2] = col[10];
    col[10] = t;
    t = col[6];
    col[6] = col[14];
    col[14] = t;
    //左移3位，相当于右移1次
    t = col[15];
    col[15] = col[11];
    col[11] = col[7];
    col[7] = col[3];
    col[3] = t;
}

// AES逆向行移位
static void Contrary_ShiftRows(unsigned char *col)
{
    unsigned char t;
    // 1位
    t = col[13];
    col[13] = col[9];
    col[9] = col[5];
    col[5] = col[1];
    col[1] = t;
    // 2位
    t = col[2];
    col[2] = col[10];
    col[10] = t;
    t = col[6];
    col[6] = col[14];
    col[14] = t;
    // 3位
    t = col[3];
    col[3] = col[7];
    col[7] = col[11];
    col[11] = col[15];
    col[15] = t;
}

// AES S-box字节替换
static void SubBytes(unsigned char *col)
{
    int x;
    for (x = 0; x < 16; x++)
        col[x] = sbox[col[x]];
}

//逆向AES S-box字节代换
static void Contrary_SubBytes(unsigned char *col)
{
    int x;
    for (x = 0; x < 16; x++)
        col[x] = contrary_sbox[col[x]];
}

// AES轮密钥加
static void AddRoundKey(unsigned char *col, unsigned char *expansionkey, int round) //密匙加
{
    int x;
    for (x = 0; x < 16; x++) //每1轮操作：4*32bit密钥 = 16个字节密钥
        col[x] ^= expansionkey[(round << 4) + x];
}

// AES加密总函数
// text: 明文，并保存加密后的密文
// expansionkey: 轮密钥
// en_round: 加密轮数，AES256建议14
void AesEncrypt(unsigned char *text, unsigned char *expansionkey, int en_round) //加密一个区块
{
    int round;
    //第1轮之前：轮密钥加
    AddRoundKey(text, expansionkey, 0);
    //第1-9轮：4类操作：字节代换、行移位、列混合、轮密钥加
    for (round = 1; round <= (en_round - 1); round++)
    {
        SubBytes(text);   //输入16字节数组，直接在原数组上修改
        ShiftRows(text);  //输入16字节数组，直接在原数组上修改
        MixColumns(text); //输入16字节数组，直接在原数组上修改
        AddRoundKey(text, expansionkey, round);
    }
    // 最后一轮，不进行列混合
    SubBytes(text);
    ShiftRows(text);
    AddRoundKey(text, expansionkey, en_round);
}

//AES 解密总函数
void Contrary_AesEncrypt(unsigned char *text, unsigned char *expansionkey, int en_round)
{
    int x;
    AddRoundKey(text, expansionkey, en_round);
    Contrary_ShiftRows(text);
    Contrary_SubBytes(text);
    for (x = (en_round - 1); x >= 1; x--)
    {
        AddRoundKey(text, expansionkey, x);
        Contrary_MixColumns(text);
        Contrary_ShiftRows(text);
        Contrary_SubBytes(text);
    }
    AddRoundKey(text, expansionkey, 0);
}

// AES密钥扩展
void ScheduleKey(unsigned char *key, unsigned char *expansion_key, int key_col, int en_round)
{
    unsigned char temp[4], t;
    int x, i;

    // 第0组：[0-3]直接拷贝
    for (i = 0; i < (4 * key_col); i++)
        expansion_key[i] = key[i];

    i = key_col;
    // 1次循环生成1个字节扩展密钥，4次循环生成一个WORD
    while (i < (4 * (en_round + 1)))
    {
        // i不是4的倍数的时候
        for (x = 0; x < 4; x++)
            temp[x] = expansion_key[(4 * (i - 1)) + x];
        // i是4的倍数的时候
        if (i % key_col == 0)
        {
            // 字循环：循环左移1字节
            t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // 字节代换
            for (x = 0; x < 4; x++)
                temp[x] = sbox[temp[x]];
            // 轮常量异或
            temp[0] ^= Rcon[(i / key_col) - 1];
        }
        else if (key_col > 6 && (i % key_col) == 4)
            for (x = 0; x < 4; x++)
                temp[x] = sbox[temp[x]];
        for (x = 0; x < 4; x++)
            expansion_key[(4 * i) + x] = expansion_key[(4 * (i - key_col)) + x] ^ temp[x];
        ++i;
    }
}
