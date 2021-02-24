#include <iostream>
#include <vector>
#include <cstring>
#include <string>

using namespace std;

//Structure used to store Blocks of 128 bits - (int)16 char  
struct Block{
    int s[16];
};

//Make sure the input will have `10` so its a multiple of 16 (128 bits)
//Always add `10` so we can remove them when decryptings
void padding(string& input){
    int mod = input.length() % 16;
    if(mod == 0){                       //If input is already a multiple of 16
        input.append<int>(1, 0x01);     //Add entire block with `10`
        input.append<int>(15, 0x00);
    }else if(mod == 15){                //If input is missing only one char
        input.append<int>(1, 0x01);     //Add `1` and entire block of `0`s
        input.append<int>(16, 0x00);
    }else{
        mod = 15 - mod;                 //Add required `01` 
        input.append<int>(1, 0x01);
        input.append<int>(mod, 0x00);
    }
}

//Get 128 bit Blocks from the input that will be encrypted/decypted 
void getInputBlocks(string& input, vector<Block>& blocks){
    padding(input);
    for(int i = 0; i < input.length(); i += 16){
        string str_obj(input.substr(i, 16));        //Get the next substring of 16 char, 128 bits
        Block newBlock;
        for(int j = 0; j < 16; j++){
            newBlock.s[j] = (int)str_obj[j];       //Store char as int
        }
        blocks.push_back(newBlock);                //Store in block
    }
}

//Print each number in the block as a hex number
void printBlocks(vector<Block>& blocks){
    for(auto w = blocks.begin(); w != blocks.end(); ++w){
        Block b = *w;
        for(int i = 0; i < 16; i++){
            cout << hex << b.s[i] << " ";
        }
        cout<<endl;
    }
}

int main(){
    string input = "Hello World! CSE 569 Project: AES...";
    vector<Block> blocks;
    getInputBlocks(input, blocks);
    printBlocks(blocks);
    
    return 0;
}
