//  Sequence.hpp
//  AES
#ifndef Sequence_hpp
#define Sequence_hpp

#include "Block.hpp"

class Sequence{
    unsigned char* sq;
    int size;
public:
    Sequence(int _size);
    unsigned char* getSequence();
    void setSequence(unsigned char* sq);
    int getSize();
};

#endif /* Sequence_hpp */