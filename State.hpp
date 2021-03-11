//  State.hpp
//  AES

#ifndef State_hpp
#define State_hpp

#include <stdio.h>
#include "Block.hpp"

class State{
    private:
        unsigned char** s;
    public:
        State(Sequence* sq);
        unsigned char** getStateArray() const;
        friend ostream& operator<<(ostream& os, const State& state);
        friend State& operator^(State& a, State& b);
        void setStateArray(unsigned char** newS);
};

#endif /* State_hpp */
