//  Cipher.cpp
//  AES
#include "random"
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

const unsigned char rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

//Initialize a input and key
Cipher::Cipher(Sequence* inString, Sequence* key){
    input = inString;
    key = key;
}

Cipher::Cipher(){}

/**
 Substitute each byte in the State using S-Box
 @param st - 2D 4x4 State array that will be modified
 */
void Cipher::subBytes(unsigned char** st){
    for(int row = 0; row < 4; row++)
        subWord(st[row]);
}

/*
 Shift the columns within the State's row by the row number
 Lowest positions in the row are swaped into highest positions,
 while highest positions change to lower positions
 @param st - State whose rows will be shifted
 */
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

// method to find xtime()
unsigned char Cipher::xTime(unsigned char stateVal) {
    // cout<<hex<<(int)stateVal<<" ";
    if ((int)stateVal <= 128) {
        return stateVal<<1;
    }
    return (stateVal<<1)^0x1b;
}

// method to find the value of the mix column state
unsigned char Cipher::gFMultiply(int matrixValue, unsigned char stateVal){
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
void Cipher::mixColumns(unsigned char** st, unsigned char** s2){
    int matrixValues[4] = {0x02, 0x03, 0x01, 0x01};
    for (int i=0; i < 4; i++) {
        for (unsigned int j=0; j < 4; j++) {
            if (i==0) {
                s2[j] = new unsigned char[4];
            }
            unsigned int temp = 0;
            for (unsigned int k=0; k < 4; k++) {
                temp ^= gFMultiply(matrixValues[(k-j)%4], st[k][i]);
            }
            s2[j][i] = temp;
        }
    }
}

/*
 * Rotate the word left by 1 Byte and save
 * @param w -> 4 Bytes word
 */
void Cipher::RotWord(unsigned char* w) {
    unsigned char tmp = w[0];
    w[0] = w[1]; w[1] = w[2]; w[2] = w[3];
    w[3] = tmp;
}

/*
 * Generate round constant word
 * @param c -> Round contanst for Cth round
 * @param buff -> Save the rcon as a word
 */
void Cipher::Rcon(int c, unsigned char* buff) {
    buff[0] = rcon[c-1];
    buff[1] = buff[2] = buff[3] = 0;
}

/*
   Takes four-byte input word and applies the S-box to 
   each byte independently
   @param wd - four byte word
 */
void Cipher::subWord(unsigned char* wd){
    for(int i = 0; i < 4; i++){
        int k = (int)wd[i];
        wd[i] = sbox[k/16][k%16];
    }
}

/*
 * Generate Nk random Integers (32 bits) and
 * save them as character
 * @param buff -> Buffer to save the key
 * @param Nk -> Key-size in words
 */
void Cipher::generateKey(int Nk, unsigned char* buff) {
    unsigned int rand[Nk], x=0;
    bool* key2 = new bool[32*Nk];
    
    std::random_device rd("/dev/urandom");
    std::fill_n(key2, 32*Nk, 0);

    /* Generate Nk 32 bits INTs */
    for (int i=0; i<Nk; i++)
        rand[i] = rd();

    /* Saving the binary sequence */
    for (int i=31; i>=0; i--) {
        for (int j=0; j<Nk; j++) {
            if((rand[j] & 1<<i) == 1<<i)
                key2[32*j+31-i]=1;
        }
    }
    for(int i=0; i<4*Nk; i++) {
        unsigned char ch = 0;
        for (int j=0; j<8; j++)
            if(key2[8*i+j])
                ch += 1<<(7-j);
        buff[x++] += ch;
    }
}

/*
 * Generate and expand the key from Nk words(4 bytes) to
 * (Nr+1) words. (NIST doc)
 * @param Nk -> Key-size in words
 * @param Nr -> Number of rounds in AES Enc
 * @param w -> (Nr+1)*4 char array to store expanded key
 */
void Cipher::keyExpansion(int Nk, int Nr, unsigned char** w) {
    unsigned char key[4*Nk], temp[4];
    int i = 0;

    generateKey(Nk, key);
    
    while(i < Nk) {
        for(int j=0; j<4; j++) w[i][j] = key[4*i+j];
        i++;
    }
    i = Nk;
    while (i < 4*(Nr+1)) {
        for(int j=0; j<4; j++) temp[j] = w[i-1][j];
        if (i % Nk == 0) {
            unsigned char rcon[4];
            Rcon(i/Nk, rcon);
            RotWord(temp);
            subWord(temp);
            for(int j=0; j<4; j++) temp[j] ^= rcon[j];
        } else if (Nk > 6 && i % Nk == 4) {
            subWord(temp);
        }
        for(int j=0; j<4; j++) w[i][j] = w[i-Nk][j] ^ temp[j];
        i++;
    }
}

/*
 * AddRoundKey to the state and return
 * @param round -> Round number
 * @param w -> Stored KeyExpansion output
 * @param s -> Current state of input block
 */
void Cipher::addRoudKey(int round, unsigned char** w, unsigned char** st) {
    //unsigned char** ch=s.getStateArray();
    for (int i=4*round, k=0; i < 4*(round+1); i++, k++) {
        for (int j=0; j < 4; j++) {
            st[j][k] ^= w[i][j];
        }
    }
    //s.setStateArray(ch);
    //return s;
}

/*
 * AES encryption routine
 * @param input -> input string
*/
Sequence Cipher::encrypt(Sequence* input) {
    int Nr = 14, Nk = 8;
    unsigned char** w;
    w = new unsigned char*[4*(Nr+1)];
    for(int j=0; j<4*(Nr+1); j++)
        w[j] = new unsigned char[4];
    
    State state(input);
    keyExpansion(Nk, Nr, w);
    addRoudKey(0, w, state.getStateArray());

    for (int i=1; i < Nr-1; i++) {
        unsigned char** s2 = new unsigned char*[4];
        subBytes(state.getStateArray());
        //cout<<"State after SubBytes:\n"<<state<<endl;
        shiftRows(state.getStateArray());
        //cout<<"State after Shift Rows:\n"<<state<<endl;
        mixColumns(state.getStateArray(), s2);
        state.setStateArray(s2);
        //cout<<"State after Mix Columns:\n"<<state<<endl;
        addRoudKey(i, w, state.getStateArray());
        //cout << "State for :"<<i<<endl<<state<<endl;
    }

    subBytes(state.getStateArray());
    //cout<<"State after SubBytes:\n"<<state<<endl;
    shiftRows(state.getStateArray());
    //cout<<"State after Mix Columns:\n"<<state<<endl;
    addRoudKey(Nr-1, w, state.getStateArray());
    //cout << "Final State:"<<endl<<state<<endl;
    return state.toSequence();
}