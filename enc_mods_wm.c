#include<stdlib.h>
#ifndef Nk                      // give -DNk=4,6,8 for aes128,192,256 resp. in command line argument with gcc
#define Nk 4
#endif
#define UL unsigned long
#include "aes.c"          // included after Nk macro as Nk is not def in aes file
#define BLOCK_SIZE 16

#define PRINTBLOCK(NAME, SIZE, VAR) {\
        printf("\n%s\n", NAME);\
        for(int i=0;i<SIZE;i++) printf("%02x",*(VAR+i));\
        printf("\n");\
    }
#include "enc_mods_wm.h"
    ///*
void pad(UCH *state, UL sizeOfData){     //padding ISO-IEC 7816-4

    UL numBytesToAdd = BLOCK_SIZE - sizeOfData%BLOCK_SIZE;
    state[sizeOfData] = 0x80;
    for(int i=sizeOfData+1; i<sizeOfData+numBytesToAdd; i++)
        state[i] = 0x00;
    //PRINTBLOCK("PADDDED",sizeOfData+numBytesToAdd,state);

}

    //*/
void genIV(){
    // CTR size is 12 bytes, rest are intitialized to zero 
    // CBC size is 16 bytes
}
void  _CTR_incrementIV(UCH *IV){      // for use with  _CTR_ mode
    IV[BLOCK_SIZE-1]++;
    
    for(int i=1;i<4;i++){
        if(IV[BLOCK_SIZE-i] == 0x00){
            IV[BLOCK_SIZE-(i+1)]++;
        }else {
            break;
        }
    }
    //PRINTBLOCK("IV",BLOCK_SIZE,IV);
    
}
void  _CTR_Utility(UCH *state, UCH *expandedKey, UCH *IV, UL noOfBlocks){

    UL step=0;
    //UCH *encIV = (UCH*)malloc(BLOCK_SIZE);
    UCH encIV[BLOCK_SIZE];                  //this works, dyn all doesn't. why
    PRINTBLOCK("DATA",noOfBlocks*BLOCK_SIZE, state);
    
    for(UL j=0; j<noOfBlocks; j++){                         //for each block (16B state)
        memcpy(encIV,IV,BLOCK_SIZE);
        _AES_encrypt(encIV, expandedKey);      // encIV is used outside scope          
        for(int i=0;i<BLOCK_SIZE;i++) state[i+step] ^= encIV[i];
        step += BLOCK_SIZE;             
        _CTR_incrementIV(IV);
    }
}
UCH*  _CTR_Encrypt(UCH *pstate, UL sizeOfData, UCH *secKey,  UCH *IV){
    //AES key expansion
    //UCH *expandedKey = (UCH*)malloc(4*EKSIZE); 
    UCH expandedKey[4*EKSIZE];
     _AES_expandKey(secKey, expandedKey);
    
    //PADDING
    UL noOfBlocks = sizeOfData/BLOCK_SIZE +1;     //step1, assuming state is 16bytes for now
    UCH *state = (UCH *)malloc(noOfBlocks*BLOCK_SIZE);
    if(state == NULL) { 
        fprintf(stderr,"State Memory allocation fault.\n");
        free(state);
        return NULL;
    }
    memcpy(state,pstate,sizeOfData);
    pad(state,  sizeOfData);

    //CTR encrypt
    _CTR_Utility(state,expandedKey,IV,noOfBlocks);

    return state;
} 
void  _CTR_Decrypt(UCH *cipherText, UL noOfBlocks, UCH *secKey, UCH *IV){
     // Key expansion
    UCH *expandedKey = (UCH*)malloc(4*EKSIZE); 
    if(expandedKey == NULL) { 
        fprintf(stderr,"Memory allocation fault in AES-KEXP\n");
        free(expandedKey);
        return;
    }
     _AES_expandKey(secKey, expandedKey);
    
    // CTR decrypt
     _CTR_Utility(cipherText,expandedKey,IV, noOfBlocks);

    
     UL step = noOfBlocks*BLOCK_SIZE;
    
    while(cipherText[--step]==0x00);
     //UCH *plaintext = (UCH*)malloc(step);
    UCH plaintext[step];
    if(cipherText[step]!=0x80) {
        printf("Invalid message. Padding not correct.\n");
       // return NULL;
    }else{
        
        memcpy(plaintext,cipherText,step);
        PRINTBLOCK("PLAINTEXT",step, plaintext);
        //return plaintext;
    }
} 

UCH*  _ECB_Encrypt(UCH *pstate, UL sizeOfData, UCH *secKey){
    
    //AES key expansion
    UCH expandedKey[4*EKSIZE]; // no of bytes in EKSIZE 4byte-words
     _AES_expandKey(secKey, expandedKey);
    
    //PADDING
    UL noOfBlocks = sizeOfData/BLOCK_SIZE +1;     //step1, assuming state is 16bytes for now
    UCH *state = (UCH *)malloc(noOfBlocks*BLOCK_SIZE);
    if(state == NULL) { 
        fprintf(stderr,"State Memory allocation fault.\n");
        free(state);
        return NULL;
    }
    memcpy(state,pstate,sizeOfData);
    pad(state,  sizeOfData);

    //ECB encrypt
    UL step=0;
    // UL gives error inside the loop, so using int
    for(int i=0;i<noOfBlocks;i++){                         //for each block (16B state)
        _AES_encrypt((state+step), expandedKey);               
        step = step+ BLOCK_SIZE;      
    }
    return state;
}
void  _ECB_Decrypt(UCH *cipherText, UL noOfBlocks, UCH *secKey){
    
    //UCH expandedKey[4*EKSIZE]; // no of bytes in EKSIZE 4byte-words
    UCH *expandedKey = (UCH*)malloc(4*EKSIZE); 
    /* Error diagnosis :
     * ExpandedKey is static allocated(in first case), means it is on stack
     * so when AES_expandKey is called, it amounts to error
     * Malloc allows dynamic allocation, on heap, so can be shared outside
     * the scope of this function
    */ 
    if(expandedKey == NULL) { 
        fprintf(stderr,"Memory allocation fault in AES-KEXP\n");
        free(expandedKey);
        return;
    }
     _AES_expandKey(secKey, expandedKey);
    PRINTBLOCK("CIPHERTEXT",noOfBlocks*BLOCK_SIZE, cipherText);
    
    UL step=0;
    for(int j=0; j<noOfBlocks; j++){                         //for each block (16B state)
        _AES_decrypt(cipherText+step, expandedKey);
        step += BLOCK_SIZE;             
    }
    
    while(cipherText[--step]==0x00);

    //UCH *plaintext = (UCH*)malloc(step);
    UCH plaintext[step];
    if(cipherText[step]!=0x80) {
        printf("Invalid message. Padding not correct.\n");
       // return NULL;
    }else{
        
        memcpy(plaintext,cipherText,step);
        PRINTBLOCK("PLAINTEXT",step, plaintext);
        //return plaintext;
    }
}

UCH*  _CBC_Encrypt(UCH *pstate, UL sizeOfData, UCH *secKey, UCH *IV){
    
    // AES Key expansion
    UCH expandedKey[4*EKSIZE];
    /* Dynamic alloc below gives malloc() corrupt top error, but not when used in
    UCH *expandedKey = (UCH*)calloc(4*EKSIZE,1); // no of bytes in EKSIZE 4byte-words
    if(expandedKey == NULL) { 
        fprintf(stderr,"Memory allocation fault in AES-KEXP\n");
        free(expandedKey);
        return NULL;
    }
    */
    _AES_expandKey(secKey, expandedKey);

    //PADDING
    UL noOfBlocks = sizeOfData/BLOCK_SIZE +1;     //step1, assuming state is 16bytes for now
    UCH *state = (UCH *)malloc(noOfBlocks*BLOCK_SIZE);
    if(state == NULL) { 
        fprintf(stderr,"State Memory allocation fault.\n");
        free(state);
        return NULL;
    }
    memcpy(state,pstate,sizeOfData);
    pad(state,  sizeOfData);
    
    // CBC Encryption
    for(int i=0;i<BLOCK_SIZE;i++) state[i] ^= IV[i]; //step1 improve this two times addition
    _AES_encrypt(state, expandedKey);                                     //step2

    int step=BLOCK_SIZE;    // changed UL to int to remove infinite loop error. FInd why it happens
        
    for(int j=1; j<noOfBlocks; j++){                         //for each block (16B state)
        for(int i=0;i<BLOCK_SIZE;i++) state[i+step] ^= state[i+step-BLOCK_SIZE]; //step1 improve this two times addition
        _AES_encrypt(state+step, expandedKey);                                     //step2
        step += BLOCK_SIZE;             
    }
    /*
    */
    /*
    */
    //PRINTBLOCK("CIPHERTEXT",noOfBlocks*BLOCK_SIZE, state);

    return state;
}
void  _CBC_Decrypt(UCH *cipherText, UL noOfBlocks, UCH *secKey, UCH *IV){
    
    UCH *expandedKey = (UCH*)malloc(4*EKSIZE); // no of bytes in EKSIZE 4byte-words
    if(expandedKey == NULL) { 
        fprintf(stderr,"Memory allocation fault in AES-KEXP\n");
        free(expandedKey);
        return;
    }
    _AES_expandKey(secKey, expandedKey);

    //PRINTBLOCK("CIPHERTEXT",noOfBlocks*BLOCK_SIZE, state);
    UCH copyBlock[BLOCK_SIZE];                                     //check all sUCH declarations for memory leaks, use malloc
    UCH lastBlock[BLOCK_SIZE];
    memcpy(lastBlock, IV, BLOCK_SIZE);
    int step=0;//BLOCK_SIZE;
    
    for(int j=0; j<noOfBlocks; j++){                                     //for each block (16B state)
        memcpy(copyBlock,cipherText+step, BLOCK_SIZE);                      //step3
        _AES_decrypt(cipherText+step, expandedKey);                                     //step2
        for(int i=0;i<BLOCK_SIZE;i++) cipherText[i+step] ^= lastBlock[i]; //step1, improve this two times addition
        //PRINTBLOCK("BLOCK",BLOCK_SIZE,state+step);
        memcpy(lastBlock, copyBlock,BLOCK_SIZE);
        step += BLOCK_SIZE;
    }

    while(cipherText[--step]==0x00);
    //UCH *plaintext = (UCH*)malloc(step);
    UCH plaintext[step];
    if(cipherText[step]!=0x80) {
        printf("Invalid message. Padding not correct.\n");
       // return NULL;
    }else{
        
        memcpy(plaintext,cipherText,step);
        PRINTBLOCK("PLAINTEXT",step, plaintext);
        //return plaintext;
    }
}
