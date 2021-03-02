//  Block.hpp
//  AES


#ifndef Block_hpp
#define Block_hpp

#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
using namespace std;

//Sequence of 128 bits
struct Sequence{
    unsigned char s[16];
};

//Block containing a vector Sequence
class Block{
    string* input;
    vector<Sequence> sequenceVct;
    void padding();
public:
    Block(string* _input);
    vector<Sequence> getSequenceVector() const;
    string getInput() const;
    friend ostream& operator<<(ostream& os, const Block& block);
};

#endif /* Block_hpp */
