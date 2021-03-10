//  State.cpp
//  AES

#include "State.hpp"

//Initialize a sequence of 128 bits into respective state
State::State(Sequence* sq): s(new unsigned char*[4]){
    for (int i=0; i < 4; i++) {
        s[i] = new unsigned char[4];
        for (int j=0; j < 4; j++) {
            s[i][j] = (*sq).s[i + 4*j];
        }
    }
}

// function to print hex value of each char in the state
ostream& operator<<(ostream& os, const State& state){
    for (int i=0; i < 4; i++) {
        for (int j=0; j < 4; j++) {
            os << hex <<(int)state.s[i][j] << ' ';
        }
        os << endl;
    }
    return os;
}

/*
 *  Getters
 */
unsigned char** State::getStateArray() const{
    return s;
}

Sequence State::toSequence() const{
    Sequence sq;
    for(int column = 0; column < 4; column++){
        for(int row = 0; row < 4; row++){    
            sq.s[column + 4*row] = s[row][column];
        }
    }
    return sq;
}

/*
 *  Setters
 */
void State::setStateArray(unsigned char** newS){
    s = newS;
}
