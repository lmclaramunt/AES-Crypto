/*
 * Cipher.hpp
 * The structure of Cipher class
 */ 

#ifndef Cipher_hpp
#define Cipher_hpp

#include "stdio.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "stdlib.h"
#include "fstream"
#include "iterator"
#include "State.hpp"
#include "Block.hpp"

class Cipher{
    private:
        /* Enc/Dec variables-methods */
        const static unsigned char sbox[16][16];
        const static unsigned char sboxInv[16][16];
        unsigned char** aesKeyExp;
        unsigned char** macKeyExp;

        unsigned char xTime(unsigned char st);
        unsigned char gFMultiply(unsigned char matrixValue, unsigned char st);
        void shiftColumnsByOne(unsigned char** st, int* row, bool leftDir);
        void shiftColumnsByTwo(unsigned char** st, int* row);
        void RotWord(unsigned char* w);
        void Rcon(int c, unsigned char* ch);
        void subWord(unsigned char* wd);
        void generateKey(unsigned char* buff, int _Nk);
        void keyExpansion(unsigned char* key, unsigned char** keyExpanded);
        void addRoudKey(int round, unsigned char** w, unsigned char** st);
        void subBytes(unsigned char** st);
        void shiftRows(unsigned char** st);
        void mixColumns(unsigned char** st, unsigned char** tmp);
        void encrypt(Sequence* input, unsigned char** key);
        void decrypt(Sequence* input, unsigned char** key);
        void invMixColumns(unsigned char** st, unsigned char** s2);
        void invShiftRows(unsigned char** st);
        void invSubBytes(unsigned char** st);
        
        /* Utilities */
        Block* inputBlock;
        int Nk, Nr, mssgLength;
        string* textPath;
        string home, aesKeyPath, macKeyPath;

        bool authenticateSequences(Sequence* first, Sequence* second);
        bool fileExists(const string* fileName);
        int getKeySize(string* aesKey, string* macKey);
        Sequence CBC_MAC(Block block, bool encrypting, bool padding);
        void cryptoDir();
        void getKey(bool encrypt, string* keyPath, unsigned char*** keyExpanded);
        void getMessageLength(unsigned char** s, bool encrypting, bool padding);
        void readText(vector<unsigned char>* inpVct);
        void removePadding(Sequence* lastPlainText);
        void setBlockRoundCombinations(int* keyLength, bool setKeyPath);
        void writePlainText();
        void writeCipherText(Sequence* tag);

    public:
        Cipher(string* _textPath, int* keyLength, bool padding, bool encrypt);
        Cipher(string* _textPath, string* _aesKeyPath, string* _macKeyPath, bool padding, bool encrypt);
        Cipher(string* _textPath, string* _aesKeyPath, string* _macKeyPath, int* keyLength, bool padding, bool encrypt);         
        ~Cipher();  
        void CBC_encrypt();
        void CBC_decrypt();
        void OFB_encrypt();
        void OFB_decrypt();
};

#endif /* Cipher_hpp */
