#include<stdio.h>
#include<string.h>
#ifndef Nk                      // give -DNk=4,6,8 for aes128,192,256 resp. in command line argument with gcc
#define Nk 4
#endif
#include "aes_1.1cbc.c"          // included after Nk macro as Nk is not def in aes file
#define UL unsigned long
#define BLOCK_SIZE 16

#define PRINTBLOCK(NAME, SIZE, VAR) {\
        printf("\n%s\n", NAME);\
        for(int i=0;i<SIZE;i++) printf("%02x",*(VAR+i));\
        printf("\n");\
    }
UL padAndRetNOBlocks(uch *data, UL sizeOfData){     //check different padding mehcs, specifically PKCS#7

    //printf("A%d\n",sizeOfData);
    UL numBytesToAdd = BLOCK_SIZE - sizeOfData%BLOCK_SIZE;
    //printf("B%d\n",numBytesToAdd);
    data[sizeOfData] = 0x80;
    for(UL i=sizeOfData+1; i<sizeOfData+numBytesToAdd; i++)
        data[i] = 0x00;
    
    return sizeOfData/BLOCK_SIZE +1;

}
void genIV(){

}
void cbcEncrypt(uch *state, UL sizeOfData, uch *expandedKey, uch *IV){
    // Step 1: Divide state into 16bytes block, add padding
    // Step 2: IV ^ First block
    // Step 3: Feed this to AES-block cipher and store the resULt in cipherarray
    // Step 4: USe the last block as the IV for the next state block
    
    UL noOfBlocks = padAndRetNOBlocks(state,sizeOfData);     //step1, assuming state is 16bytes for now
    printf("\nNo of blocks = %d\n",noOfBlocks);             
    //uch lastEncBlock[BLOCK_SIZE];                                   //check all such declarations for memory leaks, use malloc
    //memcpy(lastEncBlock, IV, BLOCK_SIZE);                           //step3 lastEncBlock stores IV or Yi
    
    PRINTBLOCK("DATA",noOfBlocks*BLOCK_SIZE, state);
    
    for(int i=0;i<BLOCK_SIZE;i++) state[i] ^= IV[i]; //step1 improve this two times addition
    encrypt(state, expandedKey);                                                    //step2
    PRINTBLOCK("BLOCK",BLOCK_SIZE,state);
    UL step=BLOCK_SIZE;
        
    for(UL j=1; j<noOfBlocks; j++){                                                 //for each block (16B state)
        for(int i=0;i<BLOCK_SIZE;i++) state[i+step] ^= state[i+step-BLOCK_SIZE];    //step1 improve this two times addition
        encrypt(state+step, expandedKey);                                           //step2
        PRINTBLOCK("BLOCK",BLOCK_SIZE,state+step);
        step += BLOCK_SIZE;             
    }
    PRINTBLOCK("CIPHERTEXT",noOfBlocks*BLOCK_SIZE, state);
}
void cbcDecrypt(uch *state, UL sizeOfData, uch *expandedKey, uch *IV){
    
    UL noOfBlocks = sizeOfData/BLOCK_SIZE+1;
    printf("\nNo of blocks = %d\n",noOfBlocks);
    uch copyBlock[BLOCK_SIZE];                                     //check all such declarations for memory leaks, use malloc
    uch lastBlock[BLOCK_SIZE];
    memcpy(lastBlock, IV, BLOCK_SIZE);
    UL step=0;//BLOCK_SIZE;
    
    for(UL j=0; j<noOfBlocks; j++){                                    //for each block (16B state)
        memcpy(copyBlock,state+step, BLOCK_SIZE);                      //step3
        decrypt(state+step, expandedKey);                              //step2
        for(int i=0;i<BLOCK_SIZE;i++) state[i+step] ^= lastBlock[i];   //step1, improve this two times addition
        PRINTBLOCK("BLOCK",BLOCK_SIZE,state+step);
        memcpy(lastBlock, copyBlock,BLOCK_SIZE);
        step += BLOCK_SIZE;
    }
    PRINTBLOCK("PLAINTEXT",noOfBlocks*BLOCK_SIZE, state);
}
int main(){
    //uch state[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uch state[43] = {0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0x01,0x33,0x35,0x13,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    //uch state[16] = {0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    
    uch sec_key[Nk*4];
    for(int i=0;i<Nk*4; i++) sec_key[i] = i;
    
    // Key expansion
    uch expandedKey[4*EKSIZE]; // no of bytes in EKSIZE 4byte-words
    expandKey(sec_key, expandedKey);
    
    // Using iv = all zeros and iv = prevCipherText to check
    uch iv[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    // uch iv[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    
    cbcEncrypt(state, sizeof(state),expandedKey, iv); //sizeof(state) gives 17 here, but if state is passed as a argument then it will give sizeof(pointer)=8
    cbcDecrypt(state, sizeof(state),expandedKey, iv);
    
    
    
    /* for use with gprof
    for(int j=0;j<100000;j++) {
        encrypt(state, expandedKey);
        for(int j=0;j<16;j++) printf("0x%02x ", state[j]);
        printf("\n\n");
        //state[rnd[j]]++;
    
        //printf("0x%02x ", state[j]+1);
        //printf("\n");
    }   
    */
    return 0; 
}
