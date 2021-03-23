#include <cstring>
#include <sstream>
#include "Block.cpp"
#include "State.cpp"
#include "Cipher.cpp"

using namespace std;

/*
-encrypt -k keyPath -p plaintextPath -b 128/192/256
-decrypt -k keyPath -c ciphertextPath
-help
*/
static void help(string name){
    cerr<<name<<endl
        <<"Usage:\n"
        <<"\t-e/encrypt [-p/plaintext plaintextPath] && ([-k/key keyPath] || [-b/bits length])"<<endl
        <<"\t-d/decrypt [-c/ciphertext ciphertextPath] && [-k/key keyPath]"<<endl
        <<"\t-h/help"<<endl;
}


int main(int argc, char* argv[]){
    // Sequence sq = {0x32, 0x43, 0xf6, 0xa8, 
    //               0x88, 0x5a, 0x30, 0x8d, 
    //               0x31, 0x31, 0x98, 0xa2, 
    //               0xe0, 0x37, 0x07, 0x34};
    if(argc < 2){
        help(argv[0]);
        return 1;
    }

    string plaintext = "", ciphertext = "", keyPath = "";
    int keyLength = 0;
    bool encrypt = false, decrypt = false;
    for(int i = 1; i < argc; i++){
        string arg = argv[i];
        if(arg == "-h" || arg == "-help" ){
            help(argv[0]);
            return 1;
        }else if(arg == "-e" || arg == "-encrypt"){
            encrypt = true;
        }else if(arg == "-d" || arg == "-decrypt"){
            decrypt = true;
        }else if(arg == "-b" || arg == "-bits"){
            if(i+1 < argc){
                try{
                    stringstream ss(argv[++i]);
                    ss >> keyLength;
                    if(keyLength != 128 && keyLength != 192 && keyLength != 256){
                        throw "Invalid Key Length -- Valid: 128, 192, 256";
                    }
                }catch(const char* str){
                    cerr<<"Exception: "<<str<<endl;
                    return 1;
                }
            }else{
                cerr<<"-b/bits option requires key length in bits (128/192/256)"<<endl;
                return 1;
            }
        }else if(arg == "-k" || arg == "-key"){
            if(i+1 < argc){
                keyPath = argv[++i];
            }else{
                cerr<<"-k/key option requires a path to key"<<endl;
                return 1;
            }
        }else if(arg == "-p" || arg == "-plaintext"){
            if(i+1 < argc){
                plaintext = argv[++i];
            }else{
                cerr<<"-p/plaintext option requires a path to plaintext"<<endl;
                return 1;
            }
        }else if(arg == "-c" || arg == "-ciphertext"){
            if(i+1 < argc){
                ciphertext = argv[++i];
            }else{
                cerr<<"-c/ciphertext option requires a path to ciphertext"<<endl;
                return 1;
            }
        }
    }
    if(encrypt && !plaintext.empty()){
        if(!keyPath.empty()){
            cout<<"We are encrypting "<<plaintext<<" key "<<keyPath<<endl;
        }else if(keyLength >= 128){
            cout<<"We are encrypting "<<plaintext<<" key of length "<<keyLength<<endl;
        }else{
            cerr<<"Invalid parameters for encryption. Use -h/help for assistance if needed"<<endl;
            return 1;
        }
    }else if(decrypt && !ciphertext.empty()){
        if(!keyPath.empty()){
            cout<<"We are decrypting "<<ciphertext<<" key "<<keyLength<<endl;
        }else{
            cerr<<"Invalid parameters for decryption. Use -h/help for assistance if needed"<<endl;
            return 1;
        }
    }else{
        cerr<<"Invalid parameters. Use -h/help for assistance if needed"<<endl;
        return 1;
    }

    return 0;
}
