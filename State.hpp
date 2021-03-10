//  State.hpp
//  AES

#ifndef State_hpp
#define State_hpp

#include <stdio.h>
#include "Block.hpp"

class State{
    unsigned char** s;
public:
    State(Sequence* sq);
    unsigned char** getStateArray() const;
    void setStateArray(unsigned char** newS);
    friend ostream& operator<<(ostream& os, const State& state);
};

#endif /* State_hpp */
