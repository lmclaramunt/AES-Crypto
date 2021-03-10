#include <cstring>
#include "Block.cpp"
#include "State.cpp"
#include "Cipher.cpp"

using namespace std;

// # of columns of 32-bit words in the state
const int Nb = 4;

int main(){
    /*
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
        */
    // string input = "Hello World! CSE 569 Project: AES...";
    // Block block(&input);
    // cout<<"Input Block:\n"<<block;
    // vector<Sequence> sqVct =  block.getSequenceVector();
    // for(Sequence sq: sqVct){
    //     Cipher cipher(&sq, &sq);
    //     Sequence* outSq = cipher.getOutputSq();
    // }
    Sequence m;
    int l[16] = {0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5};
    // unsigned char c[16];
    for(int i=0;i<16;i++){
        m.s[i] = (unsigned)(char)l[i];
    }
    Cipher cipher(&m, &m);
    Sequence* outSq = cipher.getOutputSq();
    return 0;
}
