//  Cipher.hpp
//  AES
#ifndef Cipher_hpp
#define Cipher_hpp

#include <stdio.h>
#include <bits/stdc++.h>
#include "State.hpp"

class Cipher{
    const static unsigned char sbox[16][16];
    string input;
    string output;
    string key;
private:
    void shiftColumnsByOne(unsigned char** st, int* row, bool rightDir);
    void shiftColumnsByTwo(unsigned char** st, int* row);
public:
    Cipher();
    void addRoundKey();
    void subBytes(unsigned char** st);
    void shiftRows(unsigned char** st);
    void mixColumns();
};

#endif /* Cipher_hpp */
