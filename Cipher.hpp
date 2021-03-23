//  Cipher.hpp
//  AES
#ifndef Cipher_hpp
#define Cipher_hpp

#include <stdio.h>
#include "State.hpp"

class Cipher{
    const static unsigned char sbox[16][16];
    const static unsigned char sboxInv[16][16];
    Sequence* input;
    Sequence* output;
    Sequence* key;
private:
    void shiftColumnsByOne(unsigned char** st, int* row, bool leftDir);
    void shiftColumnsByTwo(unsigned char** st, int* row);
    unsigned char xTime(unsigned char stateVal);
    unsigned char gFMultiply(unsigned char matrixValue, unsigned char stateVal);
    void RotWord(unsigned char* w);
    void Rcon(int c, unsigned char* ch);
    void subWord(unsigned char* wd);
    void generateKey(int Nk, unsigned char* buff);
    void keyExpansion(int Nk, int Nr, unsigned char** w);
    void addRoudKey(int round, unsigned char** w, unsigned char** st);
    void subBytes(unsigned char** st);
    void shiftRows(unsigned char** st);
    void mixColumns(unsigned char** st, unsigned char** s2);
    void invMixColumns(unsigned char** st, unsigned char** s2);
    void invShiftRows(unsigned char** st);
    void invSubBytes(unsigned char** st);
public:
    Cipher();
    Cipher(Sequence* inString, Sequence* key);   
    Sequence encrypt(Sequence* input);
    Sequence decrypt(Sequence* input);
    
};

#endif /* Cipher_hpp */
