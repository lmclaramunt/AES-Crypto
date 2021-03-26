#include <cstring>
#include <sstream>
#include "Block.cpp"
#include "State.cpp"
#include "Cipher.cpp"

using namespace std;

static void help(string name){
    cerr<<name<<endl
        <<"Usage:\n"
        <<"-e/encrypt [-p/path filePath] && (-ofb || -cbc) && "
        <<"[-b/bits length] ([-k/key keyPath])"<<endl
        <<"-d/decrypt [-p/path filePath] && (-ofb || -cbc) && "
        <<"[-b/bits length] ([-k/key keyPath])"<<endl
        <<"-h/help"<<endl;
}

int main(int argc, char* argv[]){
    if(argc < 2){
        help(argv[0]);
        return 1;
    }

    string filePath = "", keyPath = "";
    int keyLength = 0;
    bool encrypt = false, decrypt = false, ofb = false, cbc = false;
    for(int i = 1; i < argc; i++){
        string arg = argv[i];
        if(arg == "-h" || arg== "-help" ){
            help(argv[0]);
            return 1;
        }else if(arg == "-e" || arg == "-encrypt"){
            encrypt = true;
        }else if(arg == "-d" || arg == "-decrypt"){
            decrypt = true;
        }else if(arg == "-ofb"){
            ofb = true;
        }else if(arg == "-cbc"){
            cbc = true;
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
        }else if(arg == "-p" || arg == "-path"){
            if(i+1 < argc){
                filePath = argv[++i];
            }else{
                cerr<<"-p/path option requires a path"<<endl;
                return 1;
            }
        }
    }
    if(encrypt && !filePath.empty() && (ofb || cbc)){
        if(!keyPath.empty()){
            Cipher cipher(&filePath, &keyPath, &keyLength, cbc);
            if(cbc){
                //Do CBC encryption
            }else{
                cipher.OFB();
            }
        }else{
            Cipher cipher(&filePath, &keyLength, cbc);
            if(cbc){
                //Do CBC encryption
            }else{
                cipher.OFB();
            }
        }
    }else if(decrypt && !filePath.empty() && (ofb || cbc)){
        if(!keyPath.empty()){
            Cipher cipher(&filePath, &keyPath, &keyLength, cbc);
            if(cbc){
                //Do CBC decryption
            }else{
                cipher.OFB();
            }
        }Cipher cipher(&filePath, &keyLength, cbc);
            if(cbc){
                //Do CBC decryption
            }else{
                cipher.OFB();
            }
    }else{
        cerr<<"Invalid parameters. Use -h/help for assistance if needed"<<endl;
        return 1;
    }

    return 0;
}
