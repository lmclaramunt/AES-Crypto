//  Sequence.hpp
//  AES
#ifndef Sequence_hpp
#define Sequence_hpp

#include <stdio.h>
#include <algorithm>
#include "Block.hpp"
using namespace std;

class Sequence{
    unsigned char* sq;
    int size;
public:
    Sequence(int _size);
    unsigned char* getSequence();
    void setSequence(unsigned char* sq);
    int getSize();
    void updateSequence(Sequence seq);
    friend ostream& operator<<(ostream& os, Sequence& seq);
    friend Sequence& operator^(Sequence& a, Sequence& b);
};

#endif /* Sequence_hpp */