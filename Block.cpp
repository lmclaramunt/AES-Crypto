/*
 * Block.cpp
 * The Block class is used to represent blocks.
 * It has all the methods to convert input text into blocks of size Nb (4 bytes) and adds padding if necessary.
*/

#include "Block.hpp"



using namespace std;

/*
 * Given input, initialize the vector that has sequences of 128 bits
 * @param input - vector with bytes to be partitioned into Blocks
 * @param pad - if padding is required
 *
 *  OOP53-CPP. Write constructor member initializers in the canonical order
 */
Block::Block(vector<unsigned char>* input, bool pad) {
    if(pad) padding(input);
    Sequence sq = ((*input).size() >= 16) ? Sequence(16) : Sequence((*input).size());
    int j = 0;
    for (int i=0; i < (*input).size(); i++) {
        sq.getSequence()[j] = (unsigned) (*input).at(i);
        if (i%16==15) {
            sequenceVct.push_back(sq);      //Append 128 bits, and restart
            sq = (((*input).size()-(i+1)) >= 16) ? Sequence(16) : Sequence(((*input).size()-(i+1)));
            j = -1;
        }
        j++;
    }
    if (j != 0) sequenceVct.push_back(sq);       //Left over is padding was avoided
}

/*
 * DCL57-CPP. Do not let exceptions escape from destructors or deallocation functions
 * MEM53-CPP. Explicitly construct and destruct objects when manually managing object lifetime
 */
Block::~Block() {
    try {
        sequenceVct.clear();
        sequenceVct.shrink_to_fit();
    } catch (...) {
        cout<<"Could not clear the vector from memory!"<<endl;
    }
}

/*
 * Make sure the input is a multiple of 16 (128 bits). Add required bytes for this.
 * Always add bytes to remove them properly 
 * E.g. if 3 bytes are missing add 0x030303
 *      if 5 bytes are missing add 0x0505050505
 * @param input - vector with input bytes
 */
void Block::padding(vector<unsigned char>* input) {
    int mod = (*input).size() % 16;
    for (int i=0; i<16-mod; i++)
        input->push_back(0x10-mod);
}

/*
 * Get reference to Block's vector 
 */ 
vector<Sequence>& Block::getSequenceVector() {
    return sequenceVct;
}



/* 
 * Make it easier to print Block (by sequence) in hex
 * (Over-ridden function)
 * 
 * OOP57-CPP. Prefer special member functions and overloaded 
 * operators to C Standard Library functions
 */
ostream& operator<<(ostream& os, const Block& block) {
    for (Sequence sq: block.sequenceVct) {
        for (int i = 0; i < sq.getSize(); i++) {
            os << hex << (int)sq.getSequence()[i]<<" ";
        }
        os << endl;
    }
    return os;
}