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
public:
    void addRoundKey();
    void subBytes();
    void misColumns();
    void mixColumns();
};

#endif /* Cipher_hpp */
