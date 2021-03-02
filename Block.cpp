//  Block.cpp
//  AES

#include "Block.hpp"

using namespace std;

//Given input, initialize the vector that has sequences of 128 bits
Block::Block(string* _input): input(_input){
    padding();
    for(int i = 0; i < (*_input).length(); i += 16){
        string str_obj((*_input).substr(i, 16));        //Get the next substring of 16 char, 128 bits
        Sequence sq;
        for(int j = 0; j < 16; j++){
            sq.s[j] = (unsigned) str_obj[j];        //Store char
        }
        sequenceVct.push_back(sq);                  //Store in block
    }
}

//Make sure the input will have `10` so its a multiple of 16 (128 bits)
//Always add `10` so we can remove them when decryptings
void Block::padding(){
    int mod = (*input).length() % 16;
    if(mod == 0){                     //If input is already a multiple of 16
        (*input).append(1, 0x01);     //Add entire block with `10`
        (*input).append(15, 0x00);
    }else if(mod == 15){              //If input is missing only one char
        (*input).append(1, 0x01);     //Add `1` and entire block of `0`s
        (*input).append(16, 0x00);
    }else{
        mod = 15 - mod;               //Add required `01`
        (*input).append(1, 0x01);
        (*input).append(mod, 0x00);
    }
}

//Make it easier to print Block (by sequence) in hex
ostream& operator<<(ostream& os, const Block& block){
    for(Sequence sq: block.sequenceVct){
        for(int i = 0; i < 16; i++){
            os << hex << (int)sq.s[i]<<" ";
        }
        os << endl;
    }
    return os;
}

/*
 *  Getters
 */
vector<Sequence> Block::getSequenceVector() const{
    return sequenceVct;
}

string Block::getInput() const{
    return *input;
}
