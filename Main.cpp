#include <cstring>
#include "Block.cpp"
#include "State.cpp"
#include "Cipher.cpp"

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
    Cipher cp;
    for(Sequence sq: sqVct){
        State state(&sq);
        cout<<"Original State:\n"<<state;
        cp.subBytes(state.getStateArray());
        cout<<"Sub Bytes State:\n"<<state;
    }
    
    return 0;
}
