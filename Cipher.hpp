//  Cipher.hpp
//  AES
#ifndef Cipher_hpp
#define Cipher_hpp

#include <stdio.h>
#include "State.hpp"

class Cipher{
    Sequence* input;
    Sequence* output;
    Sequence* key;
public:
    Cipher(Sequence* inString, Sequence* key);
    void addRoundKey();
    void subBytes();
    void shiftRows();
    // void mixColumns();
    Sequence* getOutputSq() const;
};

#endif /* Cipher_hpp */
