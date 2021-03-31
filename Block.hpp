//  Block.hpp
//  AES


#ifndef Block_hpp
#define Block_hpp

#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
#include "Sequence.cpp"
using namespace std;

// //Sequence of 128 bits
// struct Sequence{
//     unsigned char s[16];
// };

//Block containing a vector Sequence
class Block{
    vector<Sequence> sequenceVct;
    void padding(vector<unsigned char>* input);
public:
    Block(vector<unsigned char>* input, bool pad);
    vector<Sequence> getSequenceVector();
    vector<unsigned char> getInput() const;
    friend ostream& operator<<(ostream& os, const Block& block);
};

#endif /* Block_hpp */
