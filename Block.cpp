//  Block.cpp
//  AES

#include "Block.hpp"

using namespace std;
/**
    Given input, initialize the vector that has sequences of 128 bits
    @param input - vector with bytes to be partitioned into Blocks
    @param pad - if padding is required
*/
Block::Block(vector<unsigned char>* input, bool pad){
    if(pad) padding(input);
    Sequence sq = ((*input).size() >= 16) ? Sequence(16) : Sequence((*input).size());
    int j = 0;
    for(int i=0; i < (*input).size(); i++){
        sq.getSequence()[j] = (unsigned) (*input).at(i);
        if(i%16==15){
            sequenceVct.push_back(sq);      //Append 128 bits, and restart
            sq = (((*input).size()-(i+1)) >= 16) ? Sequence(16) : Sequence(((*input).size()-(i+1)));
            j=-1;
        }
        j++;
    }
    if(j != 0) sequenceVct.push_back(sq);       //Left over is padding was avoided
}

/**
    Make sure the input will have `10` so its a multiple of 16 (128 bits)
    Always add `10` so we can remove them when decryptings
    @param input - vector with input bytes
*/
void Block::padding(vector<unsigned char>* input){
    int mod = (*input).size() % 16;
    if(mod == 0){                     //If input is already a multiple of 16
        input->push_back(0x01);        //Add entire block with `10`
        for(int i=0; i<15;i++)
            input->push_back(0x00);
    }else if(mod == 15){              //If input is missing only one char
        input->push_back(0x01);     //Add `1` and entire block of `0`s
        for(int i=0; i < 16; i++)
            input->push_back(0x00);
    }else{
        mod = 15 - mod;               //Add required `01`
        input->push_back(0x01);
        for(int i=0; i<mod;i++)
            input->push_back(0x00);
    }
}

//Make it easier to print Block (by sequence) in hex
ostream& operator<<(ostream& os, const Block& block){
    for(Sequence sq: block.sequenceVct){
        for(int i = 0; i < sq.getSize(); i++){
            os << hex << (int)sq.getSequence()[i]<<" ";
        }
        os << endl;
    }
    return os;
}

/*
 *  Getters
 */
vector<Sequence> Block::getSequenceVector(){
    return sequenceVct;
}

