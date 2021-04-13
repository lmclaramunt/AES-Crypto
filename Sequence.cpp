/*
 * Sequence.cpp
 * The Sequence class represents the input as 128 bit sequence.
 * It has getter and setter methods and common operations used on sequences.
 */

#include "Sequence.hpp"



/*
 * Sequence can be a max of 128 bits, but they can hold less
 * bits if the input did not contain more data and padding was 
 * avoided
 * @param size - sequence size, determined by remaining bytes on
 *               input data
 */ 
Sequence::Sequence(int _size): size(_size){
    sq = new unsigned char[size];
}

/*
 * Get sequence
 */ 
unsigned char* &Sequence::getSequence() {
    return sq;
}

/*
 * Get size of Sequence
 */
int Sequence::getSize() {
    return size;
}

/*
 * Set sequence
 */ 
void Sequence::setSequence(unsigned char* sq) { 
    this->sq = sq;
}

/*
 * Set Sequence size, in bytes, and update sequence pointer 
 */
void Sequence::setSize(int _size) {
    if(_size > 16 || _size < 0) throw "Invalid capacity\n";
    if(size != _size) {
        unsigned char* temp = new unsigned char[_size];
        for(int i=0; i< _size; i++)
            temp[i] = sq[i];
        delete[] sq;
        sq = temp;
        size = _size;
    }
}

/*
 * Values stored in a 128 bit sequence will be updated
 * @param seq - new values to be stored in Sequence
 */
void Sequence::updateSequence(Sequence seq) {
    if(size == (seq).getSize()) {
        for(int i=0; i < (seq).getSize(); i++)
            sq[i] = (seq).getSequence()[i];
    } else
        throw "Sequences of different size";   
}



/* 
 * Make it easier to print Block (by sequence) in hex
 * (Over-ridden function)
 * 
 * OOP57-CPP. Prefer special member functions and overloaded 
 * operators to C Standard Library functions
 */
ostream& operator<<(ostream& os, Sequence& seq) {
    for (int i=0; i < seq.getSize(); i++) 
        os << hex <<(int)seq.getSequence()[i]<< ' ';
    os << endl;
    return os;
}

/*
 * XOR two sequences
 *   @param a - First sequence, result will be stored here
 *   @param b - Second sequence, used for XORing
 * (Over-ridden function)
 */
Sequence& operator^(Sequence& a, Sequence& b) {
    int m = min(a.getSize(), b.getSize());
    for (int i=0; i < m; i++) {
        a.getSequence()[i] ^= b.getSequence()[i];
    }
    return a;
}