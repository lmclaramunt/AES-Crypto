// Sequence.cpp
// AES

#include "Sequence.hpp"
using namespace std;

/**
 * Sequence can be a max of 128 bits, but they can hold less
 * bits if the input did not contain more data and padding was 
 * avoided
 * @param size - sequence size, determined by remaining bytes on
 *               input data
 */ 
Sequence::Sequence(int _size): size(_size){
    sq = new unsigned char[size];
}

//Get Sequence
unsigned char* Sequence::getSequence(){ return sq;}

//Get size of Sequence
int Sequence::getSize(){ return size;}

//Set sequence
void Sequence::setSequence(unsigned char* _sq){ this->sq = _sq;}