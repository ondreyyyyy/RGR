#ifndef CHACHA20_H
#define CHACHA20_H

#include <cstdint>
#include <string>
using namespace std;

#ifdef __cplusplus
extern "C" {
#endif

	void chachaEncryptFile(const string& inputFile, const string& outputFile, const string& keyNonceFile);
	void chachaDecryptFile(const string& inputFile, const string& keyNonceFile, const string& outputFile);
	string chachaEncryptText(const string& text, const string& keyNonceFile);

#ifdef __cplusplus
}
#endif
#endif
