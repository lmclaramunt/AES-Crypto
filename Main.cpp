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
                stringstream ss(argv[++i]);
                ss >> keyLength;
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

    try{
        Cipher* c;
        if(encrypt && !filePath.empty() && (ofb || cbc)){
            if(!keyPath.empty())
                c = new Cipher(&filePath, &keyPath, &keyLength, cbc, true);
            else
                c = new Cipher(&filePath, &keyLength, cbc, true);
            if(cbc){
                c->CBC_encrypt();
            }else{
                c->OFB(true);
            }            
        }else if(decrypt && !filePath.empty() && (ofb || cbc)){
            if(!keyPath.empty())
                c = new Cipher(&filePath, &keyPath, &keyLength, cbc, false);
            else
                c = new Cipher(&filePath, &keyLength, cbc, false);
            if(cbc){
                c->CBC_decrypt();
            }else{
                c->OFB(false);
            }
        }else{
            cerr<<"Invalid parameters. Use -h/help for assistance if needed"<<endl;
            return 1;
        }
    }catch(const char* str){
        cerr<<"Exception: "<<str<<endl;
        return 1;
    }

    return 0;
}
