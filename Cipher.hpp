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
public:
    Cipher();
    Cipher(Sequence* inString, Sequence* key);
    void addRoundKey();
    void subBytes(unsigned char** st);
    void shiftRows(unsigned char** st);
    void mixColumns();
    // void mixColumns();
    Sequence* getOutputSq() const;
};

#endif /* Cipher_hpp */
