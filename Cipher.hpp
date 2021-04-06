//  Cipher.hpp
//  AES
#ifndef Cipher_hpp
#define Cipher_hpp

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fstream>
#include <iterator>
#include "State.hpp"
#include "Block.hpp"

class Cipher{
    const static unsigned char sbox[16][16];        //These are private
    const static unsigned char sboxInv[16][16];
    int Nk, Nr;
    string* textPath;
    string home, keyPath;
    unsigned char** w;      //KeyExpansion output
    Block* inputBlock;
private:
    void shiftColumnsByOne(unsigned char** st, int* row, bool leftDir);
    void shiftColumnsByTwo(unsigned char** st, int* row);
    unsigned char xTime(unsigned char stateVal);
    unsigned char gFMultiply(unsigned char matrixValue, unsigned char stateVal);
    void RotWord(unsigned char* w);
    void Rcon(int c, unsigned char* ch);
    void subWord(unsigned char* wd);
    void generateKey(unsigned char* buff, int _Nk);
    void keyExpansion(unsigned char* key);
    void addRoudKey(int round, unsigned char** w, unsigned char** st);
    void subBytes(unsigned char** st);
    void shiftRows(unsigned char** st);
    void mixColumns(unsigned char** st, unsigned char** s2);
    void invMixColumns(unsigned char** st, unsigned char** s2);
    void invShiftRows(unsigned char** st);
    void invSubBytes(unsigned char** st);
    void setBlockRoundCombinations(int* keyLength, bool setKeyPath);
    void cryptoDir();
    void getKey(bool encrypt);
    bool fileExists(const string* fileName);
    void readText(vector<unsigned char>* inpVct);
    void encrypt(Sequence* input);
    void decrypt(Sequence* input);
    void removePadding(Sequence* lastPlainText);
public:
    Cipher(string* _textPath, int* keyLength, bool padding, bool encrypt);
    Cipher(string* _textPath, string* _keyPath, int* keyLength, bool padding, bool encrypt);         
    void OFB(bool encrypting);
    void CBC_encrypt(); 
    void CBC_decrypt();
};

#endif /* Cipher_hpp */
