#include <cstring>
#include "Block.cpp"
#include "State.cpp"
#include "Cipher.cpp"

using namespace std;

int main(){
    Sequence m = {0x19, 0x3d, 0xe3, 0xbe, 
                  0xa0, 0xf4, 0xe2, 0x2b, 
                  0x9a, 0xc6, 0x8d, 0x2a, 
                  0xe9, 0xf8, 0x48, 0x08};
    Cipher cipher;
    cipher.encrypt(&m);
    return 0;
}
