//  Cipher.hpp
//  AES
#ifndef Cipher_hpp
#define Cipher_hpp

#include <stdio.h>
#include <bits/stdc++.h>
#include "State.hpp"

class Cipher{
    const static unsigned char sbox[16][16];
    Sequence* input;
    Sequence* output;
    Sequence* key;
private:
    void shiftColumnsByOne(unsigned char** st, int* row, bool rightDir);
    void shiftColumnsByTwo(unsigned char** st, int* row);
    unsigned char xTime(unsigned char stateVal);
    unsigned char gFMultiply(int matrixValue, unsigned char stateVal);
    void RotWord(unsigned char* w);
    void Rcon(int c, unsigned char* ch);
    void generateKey(int Nk, unsigned char* buff);
    void KeyExpansion(int Nk, int Nr, unsigned char** w);
    State& AddRoudKey(int round, unsigned char** key, State s);
public:
    Cipher();
    Cipher(Sequence* inString, Sequence* key);
    void addRoundKey();
    void subBytes(unsigned char** st);
    void shiftRows(unsigned char** st);
    void mixColumns(unsigned char** st, unsigned char** s2);
    Sequence* encrypt(Sequence* input, Sequence* key);    
    Sequence* getOutputSq() const;
};

#endif /* Cipher_hpp */
