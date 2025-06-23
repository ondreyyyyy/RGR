#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <string>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include "file.h"
#include "chacha20.h"

using namespace std;

#define const0 0x61707865 // константы, которые заполняют первые четыре ячейки таблицы состояния state
#define const1 0x3320646e
#define const2 0x79622d32
#define const3 0x6b206574
#define rotateLeft32(x, n) (((x) << (n)) | ((x) >> (32 - (n)))) // циклический сдвиг влево на n

void generateRandomBytes(uint8_t* buffer, size_t size) { // генерация ключа и одноразового числа nonce
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < size; ++i) {
        buffer[i] = static_cast<uint8_t>(dis(gen));
    }
}

void initState(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter = 0) { // инициализация таблицы состояния state
    state[0] = const0; // константы
    state[1] = const1;
    state[2] = const2;
    state[3] = const3;

    for (int i = 0; i < 8; ++i) { // разделение ключа на 8 слов по 4 байта и заполнение восьми ячеек таблицы
        state[4 + i] = ((uint32_t)key[i * 4 + 3] << 24) |
            ((uint32_t)key[i * 4 + 2] << 16) |
            ((uint32_t)key[i * 4 + 1] << 8) |
            ((uint32_t)key[i * 4]);
    }

    state[12] = counter; // счетчик блоков, увеличивается на 1 с каждым блоком

    for (int i = 0; i < 3; ++i) { // последние три ячейки - одноразовое число nonce
        state[13 + i] = ((uint32_t)nonce[i * 4 + 3] << 24) |
            ((uint32_t)nonce[i * 4 + 2] << 16) |
            ((uint32_t)nonce[i * 4 + 1] << 8) |
            ((uint32_t)nonce[i * 4]);
    }
}

void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) { // четверть раунд
    a += b; d ^= a; d = rotateLeft32(d, 16);
    c += d; b ^= c; b = rotateLeft32(b, 12);
    a += b; d ^= a; d = rotateLeft32(d, 8);
    c += d; b ^= c; b = rotateLeft32(b, 7);
}

void generateKeystream(uint32_t state[16], uint8_t* output) { // генерация ключевого потока
    uint32_t workingState[16]; // инициализация таблицы
    memcpy(workingState, state, sizeof(workingState));

    for (int i = 0; i < 10; ++i) {
        quarterRound(workingState[0], workingState[4], workingState[8], workingState[12]); // первый раунд для столбцов
        quarterRound(workingState[1], workingState[5], workingState[9], workingState[13]);
        quarterRound(workingState[2], workingState[6], workingState[10], workingState[14]);
        quarterRound(workingState[3], workingState[7], workingState[11], workingState[15]);

        quarterRound(workingState[0], workingState[5], workingState[10], workingState[15]); // второй раунд для диагональных элементов
        quarterRound(workingState[1], workingState[6], workingState[11], workingState[12]);
        quarterRound(workingState[2], workingState[7], workingState[8], workingState[13]);
        quarterRound(workingState[3], workingState[4], workingState[9], workingState[14]);
    } // повторяется 10 раз

    for (int i = 0; i < 16; ++i) { // сложение с исходной таблицей
        workingState[i] += state[i];
    }

    for (int i = 0; i < 16; ++i) { // преобразование слов в поток байтов - это и есть ключевой поток
        output[i * 4 + 0] = (workingState[i] >> 0) & 0xff;
        output[i * 4 + 1] = (workingState[i] >> 8) & 0xff;
        output[i * 4 + 2] = (workingState[i] >> 16) & 0xff;
        output[i * 4 + 3] = (workingState[i] >> 24) & 0xff;
    }

    state[12]++; // обновление счетчика блоков, в случае переполнения увеличиваем часть nonce
    if (state[12] == 0) {
        state[13]++;
    }
}

void encryptDecryptChaCha(const uint8_t key[32], const uint8_t nonce[12], uint8_t* data, size_t size) { // весь процесс генерации ключевого потока
    uint32_t state[16];
    initState(state, key, nonce); // инициализация таблицы

    uint8_t keystream[64]; // ключевой поток
    size_t pos = 0;

    while (pos < size) {
        generateKeystream(state, keystream); // генерация ключевого потока

        size_t blockSize = min((size_t)64, size - pos); // размер блока для шифрования/дешифрования 
        for (size_t i = 0; i < blockSize; ++i) { // xor блока текста (шифртекста или открытого) с ключевым потоком
            data[pos + i] ^= keystream[i];
        }

        pos += blockSize; // переходим к след. блоку
    }
}

void saveKeyAndNonce(const string& filename, const uint8_t key[32], const uint8_t nonce[12]) { // сохранение ключа и nonce в файл (для дешифрации)
    ofstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не удалось создать файл для ключей: " + filename);
    }

    file.write(reinterpret_cast<const char*>(key), 32);
    file.write(reinterpret_cast<const char*>(nonce), 12);
}

void loadKeyAndNonce(const string& filename, uint8_t key[32], uint8_t nonce[12]) { // загрузка ключа и nonce из файла
    ifstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не удалось открыть файл с ключами: " + filename);
    }

    file.read(reinterpret_cast<char*>(key), 32);
    file.read(reinterpret_cast<char*>(nonce), 12);

    if (file.gcount() != 12) {
        throw runtime_error("Неверный формат файла ключей");
    }
}

extern "C" {
    void chachaEncryptFile(const string& inputFile, const string& outputFile, const string& keyNonceFile) {
        auto inputData = readFile(inputFile);
        if (inputData.empty()) return;

        uint8_t key[32];
        uint8_t nonce[12];
        generateRandomBytes(key, 32);
        generateRandomBytes(nonce, 12);

        encryptDecryptChaCha(key, nonce, inputData.data(), inputData.size());
        writeFile(outputFile, inputData);
        saveKeyAndNonce(keyNonceFile, key, nonce);
    }

    void chachaDecryptFile(const string& inputFile, const string& keyNonceFile, const string& outputFile) {
        auto cipherData = readFile(inputFile);
        if (cipherData.empty()) return;

        uint8_t key[32];
        uint8_t nonce[12];
        loadKeyAndNonce(keyNonceFile, key, nonce);

        encryptDecryptChaCha(key, nonce, cipherData.data(), cipherData.size());
        writeFile(outputFile, cipherData);
    }

    string chachaEncryptText(const string& text, const string& keyNonceFile) {
        uint8_t key[32];
        uint8_t nonce[12];
        generateRandomBytes(key, 32);
        generateRandomBytes(nonce, 12);

        vector<uint8_t> data(text.begin(), text.end());
        encryptDecryptChaCha(key, nonce, data.data(), data.size());
        saveKeyAndNonce(keyNonceFile, key, nonce);

        return string(data.begin(), data.end());
    }
    
    string chachaDecryptText(const string& ciphertext, const string& keyNonceFile) {
        uint8_t key[32];
        uint8_t nonce[12];
        loadKeyAndNonce(keyNonceFile, key, nonce);

        vector<uint8_t> cipherVec(ciphertext.begin(), ciphertext.end());
        encryptDecryptChaCha(key, nonce, cipherVec.data(), cipherVec.size());
        
        return string(cipherVec.begin(), cipherVec.end());
    }
}
