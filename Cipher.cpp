//  Cipher.cpp
//  AES
#include "random"
#include "Cipher.hpp"

/*
 * Rotate the word left by 1 Byte and save
 * Params: w -> 4 Bytes word
 */
void Cipher::RotWord(unsigned char* w) {
    unsigned char tmp = w[0];
    w[0] = w[1]; w[1] = w[2]; w[2] = w[3];
    w[3] = tmp;
}

/*
 * Generate round constant word
 * Params: c -> Round contanst for Cth round
 *         buff -> Save the rcon as a word
 */
void Cipher::Rcon(int c, unsigned char* buff) {
    buff[0] = 1<<c;
    buff[1] = buff[2] = buff[3] = 0;
}

/*
 * Generate Nk random Integers (32 bits) and
 * save them as character
 * Params: buff -> Buffer to save the key
 *         Nk -> Key-size in words
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
 * Params: Nk -> Key-size in words
 *         Nr -> Number of rounds in AES Enc
 *         w -> (Nr+1)*4 char array to store expanded key
 */
void Cipher::KeyExpansion(int Nk, int Nr, unsigned char** w) {
    unsigned char key[16], temp[4];
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
            //SubWord(temp);
            for(int j=0; j<4; j++) temp[j] ^= rcon[j];
        } else if (Nk > 6 && i % Nk == 4) {
            //SubWord(temp);
        }
        for(int j=0; j<4; j++) w[i][j] = w[i-Nk][j] ^ temp[j];
        i++;
    }
}

/*
 * AddRoundKey to the state and return
 * Params: round -> Round number
 *         w -> Stored KeyExpansion output
 *         s -> Current state of input block
 */
State& Cipher::AddRoudKey(int round, unsigned char** w, State s) {
    unsigned char** ch=s.getStateArray();
    
    /*
    cout<<"state\n"<<s<<endl;
    cout<<"key:::";
    for (int k=4*round; k<4*(round+1); k++) {
        for (int j=0; j < 4; j++) {
            cout<< (int)key[k][j]<<" ";
        }
        cout<<endl;
    }
    cout<<endl;
    */
    for (int i=4*round, k=0; i < 4*(round+1); i++, k++) {
        for (int j=0; j < 4; j++) {
            ch[j][k] ^= w[i][j];
        }
    }
    s.setStateArray(ch);
    return s;
}

/*
 * AES encryption routine
 * Params: input -> input string
 */
void Cipher::encrypt(Sequence* input) {
    int Nr = 10;
    unsigned char** w;
    w = new unsigned char*[4*(Nr+1)];
    for(int j=0; j<4*(Nr+1); j++)w[j] = new unsigned char[4];
    State state(input);

    KeyExpansion(4, 10, w);

    for (int i=0; i < Nr; i++) {
        state = AddRoudKey(i, w, state);
        cout << "state for :"<<i<<endl<<state<<endl;
    }
}