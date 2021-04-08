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
    int Nk, Nr, mssgLength;
    string* textPath;
    string home, aesKeyPath, macKeyPath;
    unsigned char** aesKeyExp;                      //KeyExpansion output
    unsigned char** macKeyExp;          
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
    void keyExpansion(unsigned char* key, unsigned char** keyExpanded);
    void addRoudKey(int round, unsigned char** w, unsigned char** st);
    void subBytes(unsigned char** st);
    void shiftRows(unsigned char** st);
    void mixColumns(unsigned char** st, unsigned char** s2);
    void invMixColumns(unsigned char** st, unsigned char** s2);
    void invShiftRows(unsigned char** st);
    void invSubBytes(unsigned char** st);
    void setBlockRoundCombinations(int* keyLength, bool setKeyPath);
    void cryptoDir();
    void getKey(bool encrypt, string* keyPath, unsigned char*** keyExpanded);
    bool fileExists(const string* fileName);
    int getKeySize(string* aesKey, string* macKey);
    void readText(vector<unsigned char>* inpVct);
    void encrypt(Sequence* input, unsigned char** key);
    void decrypt(Sequence* input, unsigned char** key);
    void removePadding(Sequence* lastPlainText);
    Sequence CBC_MAC(Block block, bool encrypting, bool padding);
    void getMessageLength(unsigned char** s, bool encrypting, bool padding);
    bool authenticateSequences(Sequence* first, Sequence* second);
    void writePlainText();
    void writeCipherText(Sequence* tag);
public:
    Cipher(string* _textPath, int* keyLength, bool padding, bool encrypt);
    Cipher(string* _textPath, string* _aesKeyPath, string* _macKeyPath, bool padding, bool encrypt);         
    ~Cipher();  
    void OFB_encrypt();
    void OFB_decrypt();
    void CBC_encrypt(); 
    void CBC_decrypt();
};

#endif /* Cipher_hpp */