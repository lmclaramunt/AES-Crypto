//  State.cpp
//  AES

#include "State.hpp"

/**
     Constructor
     Initialize a state of 4 x 4 characters from input sequence
     @param sq - input sequence reference
 */
State::State(Sequence* sq): s(new unsigned char*[4]){
    for (int i=0; i < 4; i++) {
        s[i] = new unsigned char[4];
    }
    for (int i=0; i < 4; i++) {
        for (int j=0; j < 4; j++) {
            s[i][j] = sq->getSequence()[i + 4*j];
        }
    }
}

/*
 * Function to print hex value of each char in the state
 * (Over-ridden function)
 * Params: os -> output stream
 *         state -> state to be printed
 */
ostream& operator<<(ostream& os, const State& state) {
    for (int i=0; i < 4; i++) {
        for (int j=0; j < 4; j++) {
            os << hex <<(int)state.s[i][j] << ' ';
        }
        os << endl;
    }
    return os;
}

/*
 * XOR operation for states
 * (Over-ridden function)
 */
State& operator^(State& a, State& b) {
    for (int i=0; i < 4; i++) {
        for (int j=0; j < 4; j++) {
            a.s[i][j] ^= b.s[i][j];
        }
    }
    return a;
}

/*
 * Get state array
 * Return: state reference pointer
 */
unsigned char** State::getStateArray() const{
    return s;
}

Sequence State::toSequence() const{
    Sequence sq(16);
    for(int column = 0; column < 4; column++){
        for(int row = 0; row < 4; row++){    
            sq.getSequence()[column + 4*row] = s[row][column];
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
