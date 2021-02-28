#include <iostream>
#include <vector>
#include <cstring>
#include <string>

using namespace std;

// # of columns of 32-bit words in the state
const int Nb = 4;

//Structure used to store Blocks of 128 bits - (int)16 char  
struct Block{
    char s[4*Nb];        
};

struct State{
    char s[4][Nb];       
};

//Make sure the input will have `10` so its a multiple of 16 (128 bits)
//Always add `10` so we can remove them when decryptings
void padding(string& input){
    int mod = input.length() % 16;
    if(mod == 0){                  //If input is already a multiple of 16
        input.append(1, 0x01);     //Add entire block with `10`
        input.append(15, 0x00);
    }else if(mod == 15){           //If input is missing only one char
        input.append(1, 0x01);     //Add `1` and entire block of `0`s
        input.append(16, 0x00);
    }else{
        mod = 15 - mod;            //Add required `01` 
        input.append(1, 0x01);
        input.append(mod, 0x00);
    }
}

//Get 128 bit Blocks from the input that will be encrypted/decypted 
void getInputBlocks(string& input, vector<Block>& blocks){
    padding(input);
    for(int i = 0; i < input.length(); i += 16){
        string str_obj(input.substr(i, 16));        //Get the next substring of 16 char, 128 bits
        Block newBlock;
        for(int j = 0; j < 16; j++){
            newBlock.s[j] = str_obj[j];       //Store char as int
        }
        blocks.push_back(newBlock);                //Store in block
    }
}

//Print each number in the block as a hex number
void printBlocks(vector<Block>& blocks){
    for(auto w = blocks.begin(); w != blocks.end(); ++w){
        Block b = *w;
        for(int i = 0; i < 16; i++){
            cout << hex << (int)b.s[i] << " ";
        }
        cout<<endl;
    }
}

// function to convert input block to state
State inputToState(Block block) {
    State state;
    for (int i=0; i < 4; i++) {
        for (int j=0; j < Nb; j++) {
            state.s[i][j] = block.s[i + 4*j];
        }
    }
    return state;
}

// function to print hex value of each number in the state
void printState(State state) {
    for (int i=0; i < 4; i++) {
        for (int j=0; j < 4; j++) {
            std::cout << hex <<(int)state.s[i][j] << ' ';
        }
        std::cout << "\n";
    }
}

// function to print hex value of each number in the state
void printBlock(Block block) {
    for (int i=0; i < 4*Nb; i++) {
        std::cout << hex << (int)block.s[i] << ' ';
    }
    std::cout << "\n";
}

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

int main(){
    string input = "Hello World! CSE 569 Project: AES...";
    vector<Block> blocks;
    getInputBlocks(input, blocks);
    printBlocks(blocks);
    for(auto w = blocks.begin(); w != blocks.end(); ++w){
        Block b = *w;
        State s = inputToState(b);
        std::cout << "Block to State\n";
        printState(s);
        std::cout << "State to Block\n";
        printBlock(stateToOutput(s));
    }
    return 0;
}
