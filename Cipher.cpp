//  Cipher.cpp
//  AES

#include "Cipher.hpp"

//S-Box
const unsigned char Cipher::sbox[16][16] = {
        {0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76},
        {0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0},
        {0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15},
        {0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75},
        {0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84},
        {0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf},
        {0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8},
        {0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2},
        {0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73},
        {0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb},
        {0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79},
        {0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08},
        {0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a},
        {0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e},
        {0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf},
        {0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16}};

Cipher::Cipher(){}

/*
 Shift the columns within the State's row by the row number
 Lowest positions in the row are swaped into highest positions,
 while highest positions change to lower positions
 **/
void Cipher::shiftRows(unsigned char** st){
    int row = 1;
    shiftColumnsByOne(st, &row, true);
    shiftColumnsByTwo(st, &(++row));
    shiftColumnsByOne(st, &(++row), false);   //Shift to the left by 1 is equivalent to shift to the right by 3
}
/**
 Shift Columns in a State by one to either the left or right direction
 @param st - 2D State array that will be modified
 @param row - row within the State that will be modified
 @param rightDir - if true shift in right direction, else in left direction
 */
void Cipher::shiftColumnsByOne(unsigned char** st, int* row, bool rightDir){
    if(rightDir){
        for(int column = 0; column < 3; column++){
            unsigned char temp = st[*row][column];
            int next = (column + 1) % 4;
            st[*row][column] = st[*row][next];
            st[*row][next] = temp;
        }
    }else{
        for(int column = 3; column > 0; column--){
            unsigned char temp = st[*row][column];
            int next = (column + 1) % 4;
            st[*row][column] = st[*row][next];
            st[*row][next] = temp;
        }
    }
}

// method to find xtime()
unsigned char xTime(unsigned char stateVal) {
    // cout<<hex<<(int)stateVal<<" ";
    if ((int)stateVal <= 128) {
        return stateVal<<1;
    }
    return (stateVal<<1)^0x1b;
}

// method to find the value of the mix column state
unsigned char gFMultiply(int matrixValue, unsigned char stateVal){
    if (matrixValue == 0x01) {
        return stateVal;
    }
    else if (matrixValue == 0x03) {
        return xTime(stateVal)^stateVal;
    }
    else {
        return xTime(stateVal);
    }
}

// function to mix the columns of the state
void mixColumns(unsigned char** s, unsigned char** s2){
    int matrixValues[4] = {0x02, 0x03, 0x01, 0x01};
    for (int i=0; i < 4; i++) {
        for (unsigned int j=0; j < 4; j++) {
            if (i==0) {
                s2[j] = new unsigned char[4];
            }
            unsigned int temp = 0;
            for (unsigned int k=0; k < 4; k++) {
                temp ^= gFMultiply(matrixValues[(k-j)%4], s[k][i]);
            }
            s2[j][i] = temp;
        }
    }
}

/**
 Shift Columns in a State by two
    st[0] <--> st[2]
    st[1] <--> st[3]
 @param st - 2D 4x4 State array that will be modified
 @param row - row within the State that will be modified
 */
void Cipher::shiftColumnsByTwo(unsigned char** st, int* row){
    for(int column = 0; column < 2; column++){
        unsigned char temp = st[*row][column];
        st[*row][column] = st[*row][column+2];
        st[*row][column+2] = temp;
    }
}

/**
 Substitute each byte in the State using S-Box
 @param st - 2D 4x4 State array that will be modified
 */
void Cipher::subBytes(unsigned char** st){
    for(int row = 0; row < 4; row++){
        for(int column = 0; column < 4; column++){
            bitset<8> subBits(st[row][column]);
            string bitString = subBits.to_string();
            bitset<4> rowBits(bitString.substr(0, 4));
            bitset<4> columnBits(bitString.substr(4, 4));
            st[row][column] = sbox[rowBits.to_ullong()][columnBits.to_ullong()];
        }
    }
}

// method to encrypt input using key
Sequence* encrypt(Sequence* input, Sequence* key) {
    State state(input);
    cout<<"State:\n"<<state;
    cout<<endl;
    unsigned char** s2 = new unsigned char*[4];
    // AddRoundKey(state, w[0, Nb-1])
    // for # rounds
    // SubBytes(state) // See Sec. 5.1.1
    // ShiftRows(state)
    mixColumns(state.getStateArray(), s2);
    // AddRoundKey(state, w[0, Nb-1])
    // end for
    state.setStateArray(s2);
    cout<<"State after one mix columns:\n"<<state;
    cout<<endl;
    return input;
}

//Initialize a input and key
Cipher::Cipher(Sequence* inString, Sequence* key){
    input = inString;
    key = key;
    output = encrypt(input, key);
}

/*
 *  Getters
 */
Sequence* Cipher::getOutputSq() const{
    return output;
}