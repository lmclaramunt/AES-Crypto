#include <cstring>
#include "Block.hpp"
#include "State.hpp"

using namespace std;

// # of columns of 32-bit words in the state
const int Nb = 4;

/*
// function to convert state to output block
Block stateToOutput (State state) {
    Block block;
    for (int j=0; j < Nb; j++) {
        for (int i=0; i < 4; i++) {
            block.s[i+4*j] = state.s[i][j];
        }
    }
    return block;
}
*/
int main(){
    string input = "Hello World! CSE 569 Project: AES...";
    Block block(&input);
    cout<<"Input Block:\n"<<block;
    vector<Sequence> sqVct =  block.getSequenceVector();
    for(Sequence sq: sqVct){
        State state(&sq);
        cout<<"State:\n"<<state;
    }
    
    return 0;
}
