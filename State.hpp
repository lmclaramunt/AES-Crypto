/*
 * State.hpp
 * The structure of State class
 */

#ifndef State_hpp
#define State_hpp

#include "stdio.h"
#include "Sequence.hpp"



class State {
    private:
        unsigned char** s;
    public:
        State(Sequence* sq);
        ~State();
        unsigned char** getStateArray() const;
        Sequence toSequence() const;
        void setStateArray(unsigned char** newS);
        friend ostream& operator<<(ostream& os, const State& state);
        friend State& operator^(State& a, State& b);
};

#endif /* State_hpp */
