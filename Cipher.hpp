//  Cipher.hpp
//  AES
#ifndef Cipher_hpp
#define Cipher_hpp

#include <stdio.h>
#include "State.hpp"

class Cipher{
    string input;
    string output;
    string key;
private:
    void shiftColumnsByOne(unsigned char** st, int* row, bool rightDir);
    void shiftColumnsByTwo(unsigned char** st, int* row);
public:
    Cipher();
    void addRoundKey();
    void subBytes();
    void shiftRows(unsigned char** st);
    void mixColumns();
};

#endif /* Cipher_hpp */
