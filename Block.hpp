/*
 * Block.hpp
 */ 

#ifndef Block_hpp
#define Block_hpp

#include "stdio.h"
#include "vector"
#include "string"
#include "iostream"
#include "Sequence.hpp"



using namespace std;

class Block {
    private:
        vector<Sequence> sequenceVct;
        void padding(vector<unsigned char>* input);
    public:
        Block(vector<unsigned char>* input, bool pad);
        ~Block();
        vector<Sequence>& getSequenceVector();
        vector<unsigned char> getInput() const;
        friend ostream& operator<<(ostream& os, const Block& block);
};

#endif /* Block_hpp */