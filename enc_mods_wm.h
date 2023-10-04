#ifndef ENC_MODS_WM_H
#define ENC_MODS_WM_H

UCH*  _CTR_Encrypt(UCH *pstate, UL sizeOfData, UCH *secKey,  UCH *IV);
void  _CTR_Decrypt(UCH *cipherText, UL noOfBlocks, UCH *secKey, UCH *IV);

UCH*  _ECB_Encrypt(UCH *pstate, UL sizeOfData, UCH *secKey);
void  _ECB_Decrypt(UCH *cipherText, UL noOfBlocks, UCH *secKey);

UCH*  _CBC_Encrypt(UCH *pstate, UL sizeOfData, UCH *secKey, UCH *IV);
void  _CBC_Decrypt(UCH *cipherText, UL noOfBlocks, UCH *secKey, UCH *IV);

#endif