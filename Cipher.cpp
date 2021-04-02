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

//S-box Inverse
const unsigned char Cipher::sboxInv[16][16] = {
        {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
        {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
        {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
        {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
        {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
        {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
        {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
        {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
        {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
        {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
        {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
        {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
        {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
        {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
        {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

const unsigned char rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

//Initialize a input and key
Cipher::Cipher(string* _textPath, int* keyLength, bool padding, bool encrypt): 
        textPath(_textPath){
    try{
        if(textPath->empty()) throw "Missing path to file\n";
            cryptoDir();
            setBlockRoundCombinations(keyLength, true);
            getKey(encrypt);
            vector<unsigned char> inpVct;
            readText(&inpVct);
            inputBlock = new Block(&inpVct, padding);
    }catch(const char* str){
        throw str;
    }
}

Cipher::Cipher(string* _textPath, string* _keyPath, int* keyLength, bool padding, bool encrypt): 
    textPath(_textPath), keyPath(*_keyPath){
    try{
        if(textPath->empty()) throw "Missing path to file\n";
            cryptoDir();
            setBlockRoundCombinations(keyLength, false);
            getKey(encrypt);
            vector<unsigned char> inpVct;
            readText(&inpVct);
            inputBlock = new Block(&inpVct, padding);
    }catch(const char* str){
        throw str;
    }
}

/**
 Set number of rounds performed during AES execution according
 to key's length
 @param keyLength - length in bits (128/192/256)   
 */
void Cipher::setBlockRoundCombinations(int* keyLength, bool setKeyPath){
    switch (*keyLength)
    {
    case 128:
        Nk = 4, Nr = 10;
        break;
    case 192:
        Nk = 6, Nr = 12;
        break;
    case 256:
        Nk = 8, Nr = 14;
        break;
    default: throw "Invalid Key Length -- Valid: 128, 192, 256"; break;
    }
    if(setKeyPath) keyPath = home + "/.AES-" + to_string(*keyLength) + ".aes";
}

/**
 * Create directory where keys will be stored,
 * if it doesn't exists
 */
void Cipher::cryptoDir(){
    struct stat info;
    home = getenv("HOME");
    home += "/.crypto";
    const char *pathname = &home[0];
    if(stat(pathname, &info) != 0){
        mkdir(pathname, 0600);
    }
}
/**
 * Get the either either from a file or generate a new one
    if there is no key to deal with
    @param encrypt - bool to determine if we are 
        encrypting or decrypting
*/
void Cipher::getKey(bool encrypt){
    unsigned char* key = new unsigned char[4*Nk];
    ifstream input(keyPath, ios::binary);
    if(input.is_open()){        //Read key, given path to it
        for(int i=0; i < 4*Nk; i++)
            key[i] = input.get();
        input.close(); 
    }else if(encrypt){          //Create new key if we are encrypting
        generateKey(key, Nk);
        ofstream keyFile;
        keyFile.open(keyPath, ios::binary);
        keyFile.write((const char*)key, 4*Nk);
        keyFile.close();       
    }else{
        throw "Missing key for decryption\n";   //User should have key to decrypt
    }

    w = new unsigned char*[4*(Nr+1)];    //Expand the key   
    for(int j=0; j<4*(Nr+1); j++)
        w[j] = new unsigned char[4];
    keyExpansion(key);
}

/**
 * Read file and store its bytes in Blocks of 128 bits
 * Padding can be done if required
 * @param block - block with 128 bits partions
 */
void Cipher::readText(vector<unsigned char>* inpVct){
    ifstream input(*textPath, ios::binary);
    streampos textSize;             //Size of the file
    input.seekg(0, ios::end);
    textSize = input.tellg();
    input.seekg(0, ios::beg);
    inpVct->reserve(textSize);      //The vector will have enough space for all elements
    inpVct->insert(inpVct->begin(), 
        (istreambuf_iterator<char>(input)),
        (istreambuf_iterator<char>()));
    input.close();
}

/**
 * Quickly check if the file exists
 * @param filePath - File's path
 */ 
bool Cipher::fileExists(const string* filePath) {
  struct stat info;   
  return stat ((*filePath).c_str(), &info) == 0; 
}

/**
 Substitute each byte in the State using S-Box
 @param st - 2D 4x4 State array that will be modified
 */
void Cipher::subBytes(unsigned char** st){
    for(int row = 0; row < 4; row++)
        subWord(st[row]);
}

/**
 Shift the columns within the State's row by the row number
 Lowest positions in the row are swaped into highest positions,
 while highest positions change to lower positions
 @param st - State whose rows will be shifted
 */
void Cipher::shiftRows(unsigned char** st){
    int row = 1;
    shiftColumnsByOne(st, &row, true);
    shiftColumnsByTwo(st, &(++row));
    shiftColumnsByOne(st, &(++row), false);   //Shift to the right by 1 is equivalent to shift to the left by 3
}

/**
 Shift Columns in a State by one to either the left or right direction
 @param st - 2D State array that will be modified
 @param row - row within the State that will be modified
 @param leftDir - if true shift in left direction, else in right direction
 */
void Cipher::shiftColumnsByOne(unsigned char** st, int* row, bool leftDir){
    if(leftDir){
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
    if (stateVal < 0x80) {
        return stateVal<<1;
    }
    return (stateVal<<1)^0x1b;
}

// method to find the value of the mix column state
unsigned char Cipher::gFMultiply(unsigned char matrixValue, unsigned char stateVal){
    unsigned char mul = 0x00;
    if (matrixValue%0x02) {
        mul = stateVal;
        matrixValue -= 0x01;
    }
    while (matrixValue) {
        unsigned char xt = stateVal;
        for (int i=0; i < (int)log2(matrixValue); i++){
            xt = xTime(xt);
        }
        mul ^= xt;
        matrixValue %= (unsigned)(int)pow(2, (int)log2(matrixValue));
    }
    return mul;
}

// function to mix the columns of the state
void Cipher::mixColumns(unsigned char** st, unsigned char** s2){
    unsigned char matrixValues[4] = {0x02, 0x03, 0x01, 0x01};
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

// function to inverse mix columns of the state
void Cipher::invMixColumns(unsigned char** st, unsigned char** s2){
    unsigned char matrixValues[4] = {0x0e, 0x0b, 0x0d, 0x09};
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

/**
 * Rotate the word left by 1 Byte and save
 * @param w -> 4 Bytes word
 */
void Cipher::RotWord(unsigned char* w) {
    unsigned char tmp = w[0];
    w[0] = w[1]; w[1] = w[2]; w[2] = w[3];
    w[3] = tmp;
}

/**
 * Generate round constant word
 * @param c -> Round contanst for Cth round
 * @param buff -> Save the rcon as a word
 */
void Cipher::Rcon(int c, unsigned char* buff) {
    buff[0] = rcon[c-1];
    buff[1] = buff[2] = buff[3] = 0;
}

/**
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

/**
 * Generate Nk random Integers (32 bits) and
 * save them as character
 * @param buff -> Buffer to save the key
 * @param Nk -> Key-size in words
 */
void Cipher::generateKey(unsigned char* buff, int _Nk) {
    unsigned int rand[_Nk], x=0;
    bool* key2 = new bool[32*_Nk];
    
    std::random_device rd("/dev/urandom");
    std::fill_n(key2, 32*_Nk, 0);

    /* Generate Nk 32 bits INTs */
    for (int i=0; i<_Nk; i++)
        rand[i] = rd();

    /* Saving the binary sequence */
    for (int i=31; i>=0; i--) {
        for (int j=0; j<_Nk; j++) {
            if((rand[j] & 1<<i) == 1<<i)
                key2[32*j+31-i]=1;
        }
    }
    for(int i=0; i<4*_Nk; i++) {
        unsigned char ch = 0;
        for (int j=0; j<8; j++)
            if(key2[8*i+j])
                ch += 1<<(7-j);
        buff[x++] += ch;
    }
}

/**
 * Generate and expand the key from Nk words(4 bytes) to
 * (Nr+1) words. (NIST doc)
 * @param Nk -> Key-size in words
 * @param Nr -> Number of rounds in AES Enc
 * @param w -> (Nr+1)*4 char array to store expanded key
 */
void Cipher::keyExpansion(unsigned char* key) {
    unsigned char temp[4];
    int i = 0;
    //unsigned char key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    
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

/**
 * AddRoundKey to the state and return
 * @param round -> Round number
 * @param w -> Stored KeyExpansion output
 * @param s -> Current state of input block
 */
void Cipher::addRoudKey(int round, unsigned char** w, unsigned char** st) {
    for (int i=4*round, k=0; i < 4*(round+1); i++, k++) {
        for (int j=0; j < 4; j++) {
            st[j][k] ^= w[i][j];
        }
    }
}

/**
 * AES encryption routine
 * @param input - 128 bits that will go through encryption protocol
*/
void Cipher::encrypt(Sequence* input) {
    State state(input);
    addRoudKey(0, w, state.getStateArray());
    
    for (int i=1; i < Nr; i++) {
        unsigned char** s2 = new unsigned char*[4];
        subBytes(state.getStateArray());
        shiftRows(state.getStateArray());
        mixColumns(state.getStateArray(), s2);
        state.setStateArray(s2);
        addRoudKey(i, w, state.getStateArray());
    }

    subBytes(state.getStateArray());
    shiftRows(state.getStateArray());
    addRoudKey(Nr, w, state.getStateArray());
    input->updateSequence(state.toSequence());
}

/******************************************************
                    INVERSE - DECRYPTION
******************************************************/

/**
 Shift the columns within the State's row by the row number
 Inverse order compared to original shiftRows method
 @param st - State whose rows will be shifted
 */
void Cipher::invShiftRows(unsigned char** st){
    int row = 1;
    shiftColumnsByOne(st, &row, false);
    shiftColumnsByTwo(st, &(++row));
    shiftColumnsByOne(st, &(++row), true);   //Shift to the left by 1 is equivalent to shift to the right by 3
}

/**
 * Inverse of byte substitution. Using inverse S-box
 * @param st - State whose bytes will be substituted
 */ 
void Cipher::invSubBytes(unsigned char** st){
    for(int i = 0; i < 4; i++){
        for(int j=0; j < 4; j++){
            int k = (int)st[i][j];
            st[i][j] = sboxInv[k/16][k%16];
        }
    }
}

/**
 * AES Decryption 
 * @param input - 128 bits that will go through decryption protocol
 */ 
void Cipher::decrypt(Sequence* input){
    State state(input);
    addRoudKey(Nr, w, state.getStateArray());

    for (int i=Nr-1; i > 0; i--) {
        unsigned char** s2 = new unsigned char*[4];
        invShiftRows(state.getStateArray());
        invSubBytes(state.getStateArray());
        addRoudKey(i, w, state.getStateArray());
        invMixColumns(state.getStateArray(), s2);
        state.setStateArray(s2);
    }

    invShiftRows(state.getStateArray());
    invSubBytes(state.getStateArray());
    addRoudKey(0, w, state.getStateArray());
    input->updateSequence(state.toSequence());
}

/******************************************************
                Output Feedback Mode - OFB
******************************************************/
/**
 * OFB mode of operation, for encryption and decryption
    @param encrypting - bool to determine if we are encrypting
            or decrypting a file, and should generate or look up 
            for IV
*/
void Cipher::OFB(bool encrypting){
    ofstream ciphertext;
    ciphertext.open(*textPath, ios::binary);
    Sequence ivSq(16);   
    if(encrypting){     //Generate IV if we are encrypting
        unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        ivSq.setSequence(iv);
        ciphertext.write((const char*)ivSq.getSequence(), ivSq.getSize());  //IV will be first 128-bits of ciphertext
    }

    for(Sequence sq: inputBlock->getSequenceVector()){
        if(!encrypting){
            ivSq.updateSequence(sq);    //If we are decrypting, then update the value of IV
            encrypting = true;          //by using first 128 bits, and decryption will continue
            continue;                   //with the next bytes
        }
        encrypt(&ivSq);
        sq = sq ^ ivSq;
        ciphertext.write((const char*)sq.getSequence(), sq.getSize()); 
    }
    ciphertext.close();
}

/******************************************************
            Cipher Block Chaining Mode - CBC
******************************************************/
/**
 * Encrypt using CBC mode of operation.
 * A random, non-secret, IV will be generated for each encryption
 * and attached as the first 128 bits of the cyphertext.
 * Plaintext go through a padding process for CBC encryption.
*/
void Cipher::CBC_encrypt(){
    ofstream ciphertext;
    ciphertext.open(*textPath, ios::binary);
    Sequence ivSq(16); 
    // unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  
    //                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    // ivSq.setSequence(iv);
    generateKey(ivSq.getSequence(), 4);
    ciphertext.write((const char*)ivSq.getSequence(), ivSq.getSize());
    for(Sequence sq: inputBlock->getSequenceVector()){  
        ivSq = sq ^ ivSq;
        encrypt(&ivSq);
        ciphertext.write((const char*)ivSq.getSequence(), ivSq.getSize());
    }
    ciphertext.close();  
}

/**
 * Decrypt using CBC mode of operation.
 * IV is recovered from the first 128 bits of ciphertext
 * Padding is removed from the recovered plaintext before 
 * writting it back into the designated file
*/
void Cipher::CBC_decrypt(){
    ofstream plaintext;
    plaintext.open(*textPath, ios::binary);
    Sequence prevSq(16), cipherText(16); 
    int i = 0;
    int size =inputBlock->getSequenceVector().size();
    for(Sequence sq: inputBlock->getSequenceVector()){         
        if(i == 0){
            prevSq.updateSequence(sq);  //If we are decrypting, then update the value of IV
            i++;                        //by using first 128 bits, and decryption will continue
            continue;                   //with the next bytes
        }
        cipherText.updateSequence(sq);  //Keep track of ciphertext, we'll need it next round   
        decrypt(&sq);
        sq = sq ^ prevSq;               
        prevSq.updateSequence(cipherText);  //Update previous sequence, to ciphertext values
        if(i == size-1){
            try{
                removePadding(&plaintext, &inputBlock->getSequenceVector().at(i-1), &sq);  //CBC always uses padding
            }catch(const char* str){
                throw str;
            }
        }
        else if(i < size-2){
            plaintext.write((const char*)sq.getSequence(), sq.getSize());
        }       
        i++;
    }
    plaintext.close();
}

/**
 * Remove padding before writting to plaintext. Last two 128 bits blocks
 * could have been affected by padding, so look analyze them
 * @param file - file where plaintext will be written
 * @param prevPlainText - sequence of plaintext previous to the last block
 * @param lastPlainText - last sequence of plaintext in a Block
*/
void Cipher::removePadding(ofstream* file, Sequence* prevPlainText, Sequence* lastPlainText){ 
    int i = 16;      
    bool error = false, oneFound = false;
    while (i > 0)           //Iterate through all sequence if necessary
    {
        i--;
        if((*lastPlainText).getSequence()[i] == 0x00)   
            continue;
        else if((*lastPlainText).getSequence()[i] == 0x01){
            oneFound = true;
            break;
        }else{
            error = true;   //Last block should have `10` before anything else
            break;
        }
    }
    if(!error){
        if(oneFound && i==0){
            file->write((const char*)(*prevPlainText).getSequence(), 16);   //last sequence was for padding, so ignore it
        }else if(!oneFound && i==0){
            file->write((const char*)(*prevPlainText).getSequence(), 15);   //ignore last sequence, and last bit of prev
        }else{
            file->write((const char*)(*prevPlainText).getSequence(), 16);   //write entire prev sequence
            file->write((const char*)(*lastPlainText).getSequence(), i);    //and all bytes until `10` was found
        }   
    }else
        throw "Padding error!\n";   //Error if the last block doesn't containt `10` in its last bytes
}