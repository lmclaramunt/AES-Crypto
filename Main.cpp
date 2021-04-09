/*
 * Main.cpp
 * 
 * We have followed these secure coding pratices throughout:
 * DCL53-CPP. Do not write syntactically ambiguous declarations
 * EXP50-CPP. Do not depend on the order of evaluation for side effects
 * EXP53-CPP. Do not read uninitialized memory
 * CTR52-CPP. Guarantee that library functions do not overflow
 * MEM50-CPP. Do not access freed memory
 * ERR51-CPP. Handle all exceptions
 * MSC52-CPP. Value-returning functions must return a value from all exit paths
 * ARR37-C. Do not add or subtract an integer to a pointer to a non-array object
 * FIO46-C. Do not access a closed file
 * DCL52-CPP. Never qualify a reference type with const or volatile
 * 
 * Specific instances of usage are also refereced in code.
 */

#include "cstring"
#include "sstream"
#include "iostream"
// #include "Sequence.cpp"
// #include "Block.cpp"
// #include "State.cpp"
// #include "Cipher.cpp"
#include "Cipher.hpp"



using namespace std;

static void help(string name) {
    cerr<<name<<endl
        <<"Usage:\n"
        <<"-e/encrypt [-p/path filePath] && (-ofb || -cbc) && "
        <<"[-b/bits length] ([-k/key keyPath])"<<endl
        <<"-d/decrypt [-p/path filePath] && (-ofb || -cbc) && "
        <<"[-b/bits length] ([-k/key keyPath])"<<endl
        <<"-h/help"<<endl;
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        help(argv[0]);
        return 1;
}

    string filePath = "", aesKeyPath = "", macKeyPath = "";
    int keyLength = 0;
    bool encrypt = false, decrypt = false, ofb = false, cbc = false;
    for(int i = 1; i < argc; i++) {
        string arg = argv[i];
        if(arg == "-h" || arg== "-help" ) {
            help(argv[0]);
            return 1;
        } else if(arg == "-e" || arg == "-encrypt") {
            encrypt = true;
        } else if(arg == "-d" || arg == "-decrypt") {
            decrypt = true;
        } else if(arg == "-ofb") {
            ofb = true;
        } else if(arg == "-cbc") {
            cbc = true;
        } else if(arg == "-b" || arg == "-bits") {
            if(i+1 < argc) {
                stringstream ss(argv[++i]);
                ss >> keyLength;
            } else {
                cerr<<"-b/bits option requires key length in bits (128/192/256)"<<endl;
                return 1;
            }
        } else if(arg == "-aes") {
            if(i+1 < argc) {
                aesKeyPath = argv[++i];
            } else {
                cerr<<"-aes option requires the path to the AES key"<<endl;
                return 1;
            }
        } else if(arg == "-mac") {
            if(i+1 < argc) {
                macKeyPath = argv[++i];
            } else {
                cerr<<"-mac option requires the path to the MAC key"<<endl;
                return 1;
            }
        } else if (arg == "-p" || arg == "-path") {
            if(i+1 < argc) {
                filePath = argv[++i];
            } else {
                cerr<<"-p/path option requires a path"<<endl;
                return 1;
            }
        }
    }

    try {
        Cipher* c;
        if(encrypt && !filePath.empty() && (ofb || cbc)) {
            if(!aesKeyPath.empty() && !macKeyPath.empty())
                c = new Cipher(&filePath, &aesKeyPath, &macKeyPath, cbc, true);     //cbc bool determine if 
            else                                                                                //padding is needed
                c = new Cipher(&filePath, &keyLength, cbc, true);                               //true - since we're encrypting
            if(cbc) {
                c->CBC_encrypt();
            } else {
                c->OFB_encrypt();
            }            
        } else if(decrypt && !filePath.empty() && (ofb || cbc)) {
            if(!aesKeyPath.empty() && !macKeyPath.empty())
                c = new Cipher(&filePath, &aesKeyPath, &macKeyPath, false, false);  //both bool to false since we are
            else                                                                    //decrypting and no padding is needed
                c = new Cipher(&filePath, &keyLength, false, false);
            if(cbc) {
                c->CBC_decrypt();
            } else {
                c->OFB_decrypt();
            }
        } else {
            cerr<<"Invalid parameters. Use -h/help for assistance if needed"<<endl;
            return 1;
        }
    } catch(const char* str) {
        cerr<<"Exception: "<<str<<endl;
        return 1;
    }

    return 0;
}