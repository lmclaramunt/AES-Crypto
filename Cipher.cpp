//  Cipher.cpp
//  AES

#include "Cipher.hpp"

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