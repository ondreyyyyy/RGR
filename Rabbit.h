#ifndef RABBIT_H
#define RABBIT_H

using namespace std;
#include <string>
#ifdef __cplusplus
extern "C" {
#endif

    void rabbitEncryptFile(const string& inputFile, const string& outputFile, const string& keyNonceFile);
    void rabbitDecryptFile(const string& inputFile, const string& keyNonceFile, const string& outputFile);
    string rabbitEncryptText(const string& text, const string& keyNonceFile);
    string rabbitDecryptText(const string& ciphertext, const string& keyNonceFile);

#ifdef __cplusplus
}
#endif

#endif // RABBIT_H
