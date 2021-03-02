#ifndef _RSA
#define _RSA

#define OPENSSLKEY "test.key"
#define PUBLICKEY "test_pub.key"
#define BUFFSIZE 1024
char* my_encrypt(char *str);//加密
char* my_decrypt(char *str);//解密
void my_free(char* ptr);//free memory

#endif