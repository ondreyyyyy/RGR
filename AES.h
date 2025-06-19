#ifndef AES_H
#define AES_H

#include <string>
using namespace std;
extern "C" {
    void aesEncryptFile(const string& inputFile, const string& outputFile, const string& keyIVfile);
    void aesDecryptFile(const string& inputFile, const string& keyIVfile, const string& outputFile);
    string aesEncryptText(const string& text, const string& keyIVfile);
}

#endif