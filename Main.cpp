#include <cstring>
#include "Block.cpp"
#include "State.cpp"
#include "Cipher.cpp"

using namespace std;

int main(){
    Sequence sq = {0x32, 0x43, 0xf6, 0xa8, 
                  0x88, 0x5a, 0x30, 0x8d, 
                  0x31, 0x31, 0x98, 0xa2, 
                  0xe0, 0x37, 0x07, 0x34};
    State st(&sq);
    cout<<st;
    Cipher cipher;
    unsigned char key[32];
    cipher.generateKey(8, key);
    cout<<"Key:\n";
    for(int i = 0; i < 32; i++){
        cout<<hex<<(int)key[i]<<" ";
    }
    cout<<endl;
    return 0;
}
