//  Cipher.hpp
//  AES
#ifndef Cipher_hpp
#define Cipher_hpp

#include <stdio.h>
#include "State.hpp"

class Cipher{
    string input;
    string output;
    private:
        void RotWord(unsigned char* w);
        void Rcon(int c, unsigned char* ch);
        void generateKey(int Nk, unsigned char* buff);
        void KeyExpansion(int Nk, int Nr, unsigned char** w);
        State& AddRoudKey(int round, unsigned char** key, State s);

    public:
        void encrypt(Sequence* input);
        void subBytes();
        void misColumns();
        void mixColumns();
};

#endif /* Cipher_hpp */
