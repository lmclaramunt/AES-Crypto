#include <cstring>
#include "Block.cpp"
#include "State.cpp"
#include "Cipher.cpp"

using namespace std;

int main(){
    Sequence m = {0x32, 0x43, 0xf6, 0xa8, 
                  0x88, 0x5a, 0x30, 0x8d, 
                  0x31, 0x31, 0x98, 0xa2, 
                  0xe0, 0x37, 0x07, 0x34};
    Cipher cipher;
    Sequence sq = cipher.encrypt(&m);
    for(int i = 0; i < 16; i++){
        cout<<hex<<(int)sq.s[i]<<" ";
        if(i % 4 == 3) cout<<endl;
    }
    return 0;
}
