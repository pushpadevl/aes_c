#ifndef AES_H
#define AES_H

void _AES_encrypt(UCH *state, UCH *expandedKey);
void _AES_decrypt(UCH *state, UCH *expandedKey);
void _AES_expandKey(UCH *secretKey, UCH *expandedKey);

#endif