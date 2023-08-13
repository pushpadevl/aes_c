# aes_c
AES-128, 192, 256 implementation in C
CBC mode implemented over AES.

 1. To use different key length in AES over CBC, use command: 
     - gcc -DNk=4 cbc.c // for 128 bit AES keys
     - gcc -DNk=6 cbc.c // for 192 bit AES keys
     - gcc -DNk=8 cbc.c // for 256 bit AES keys

 2. The implementation uses following values as default
    - DATA="00112233445566778899aabbccddeeff"  
    - KEYS="000102030405060708090a0b0c0d0e0f"  //for AES-128
    - KEYS="000102030405060708090a0b0c0d0e0f1011121314151617"  //for AES-192
    - KEYS="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"  //for AES-256

 3. cbc.c file uses aes_1.1cbc.c file as a dependency. Make sure to keep them together.
    
