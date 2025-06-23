#include "Rabbit.h"
#include "file.h"
#include <iostream>
#include <fstream>
#include <random>

using namespace std;

const uint32_t constant [8] = { 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3 };

void generateRabbitKeyAndIV(uint8_t key[16], uint8_t iv[8]) { // генерация ключа и вектора инициализации
    random_device rd;
    uniform_int_distribution<uint16_t> dist(0, 255); 

    for (int i = 0; i < 16; ++i) {
        key[i] = static_cast<uint8_t>(dist(rd)); 
    }

    for (int i = 0; i < 8; ++i) {
        iv[i] = static_cast<uint8_t>(dist(rd));
    }
}

void rabbitNextState(uint32_t x[8], uint32_t c[8], uint32_t& phi) { // обновление состояния
    uint32_t g[8], cOld[8];

    for (int i = 0; i < 8; ++i) {
        cOld[i] = c[i]; // сохранение текущих счетчиков как старые
    }

    c[0] += constant[0] + phi; // обновление счетчиков
    c[1] += constant[1] + (c[0] < cOld[0]);
    c[2] += constant[2] + (c[1] < cOld[1]);
    c[3] += constant[3] + (c[2] < cOld[2]);
    c[4] += constant[4] + (c[3] < cOld[3]);
    c[5] += constant[5] + (c[4] < cOld[4]);
    c[6] += constant[6] + (c[5] < cOld[5]);
    c[7] += constant[7] + (c[6] < cOld[6]);
    phi = (c[7] < cOld[7]); // проверка переполнения для сл. итерации (для c[0])

    for (int i = 0; i < 8; ++i) { // вычиление g
        g[i] = x[i] + c[i];
        g[i] = (g[i] * g[i]) ^ ((g[i] * g[i]) >> 32);
    }

    x[0] = g[0] + ((g[7] << 16) | (g[7] >> 16)) + ((g[6] << 16) | (g[6] >> 16)); // вычисление переменных состояния 
    x[1] = g[1] + ((g[0] << 8) | (g[0] >> 24)) + g[7];
    x[2] = g[2] + ((g[1] << 16) | (g[1] >> 16)) + ((g[0] << 16) | (g[0] >> 16));
    x[3] = g[3] + ((g[2] << 8) | (g[2] >> 24)) + g[1];
    x[4] = g[4] + ((g[3] << 16) | (g[3] >> 16)) + ((g[2] << 16) | (g[2] >> 16));
    x[5] = g[5] + ((g[4] << 8) | (g[4] >> 24)) + g[3];
    x[6] = g[6] + ((g[5] << 16) | (g[5] >> 16)) + ((g[4] << 16) | (g[4] >> 16));
    x[7] = g[7] + ((g[6] << 8) | (g[6] >> 24)) + g[5];
}

void rabbitSetup(uint32_t x[8], uint32_t c[8], uint32_t& phi, // инициализация состояния
    const uint8_t key[16], const uint8_t iv[8]) {
    uint16_t k[8];
    for (int i = 0; i < 8; ++i) { // разбиение ключа на 8 подключей
        k[i] = (uint16_t)key[i * 2] | ((uint16_t)key[i * 2 + 1] << 8);
    }

    for (int j = 0; j < 8; ++j) { // инициализация восьми переменных состояния
        if (j % 2 == 0) {
            x[j] = ((uint32_t)k[(j + 1) % 8] << 16) | k[j]; // для четных
        }
        else {
            x[j] = ((uint32_t)k[(j + 5) % 8] << 16) | k[(j + 4) % 8]; // для нечетных
        }
    }

    
    for (int j = 0; j < 8; ++j) { // инициализация восьми счетчиков
        if (j % 2 == 0) { 
            c[j] = ((uint32_t)k[(j + 4) % 8] << 16) | k[(j + 5) % 8]; // для четных 
        }
        else {
            c[j] = ((uint32_t)k[j] << 16) | k[(j + 1) % 8]; // для нечетных 
        }
    }
    
    if (iv != nullptr) {
        uint16_t ivPart[4]; // разбиение вектора инициализации на 4 части
        for (int i = 0, j = 0; i < 8; i += 2, j++) {
            ivPart[j] = (uint16_t)iv[i] << 8 | iv[i + 1];
        }

        // обновление четных счетчиков
        c[0] ^= (uint32_t)ivPart[2] << 16 | ivPart[3];
        c[2] ^= (uint32_t)ivPart[0] << 16 | ivPart[1];
        c[4] ^= (uint32_t)ivPart[2] << 16 | ivPart[3];
        c[6] ^= (uint32_t)ivPart[0] << 16 | ivPart[1];

        // обновление нечетных счетчиков
        c[1] ^= (uint32_t)ivPart[0] << 16 | ivPart[2];
        c[3] ^= (uint32_t)ivPart[1] << 16 | ivPart[3];
        c[5] ^= (uint32_t)ivPart[0] << 16 | ivPart[2];
        c[7] ^= (uint32_t)ivPart[1] << 16 | ivPart[3]; 
    }

    phi = 0;
    for (int i = 0; i < 4; ++i) rabbitNextState(x, c, phi); // обновление состояния 4 раза

    for (int j = 0; j < 8; ++j) { // повторная инициализация всех восьми счетчиков
        c[j] ^= x[(j + 4) % 8];
    }
}
void rabbitGenerateKeyStream(uint32_t x[8], uint32_t c[8], uint32_t& phi, uint8_t* output, size_t length) { // генерация ключ. потока
    for (size_t i = 0; i < length; i += 16) {
        rabbitNextState(x, c, phi); // обновление состояния

        uint16_t s0 = (x[0] & 0xFFFF) ^ (x[5] >> 16); // вычисление частей ключевого потока
        uint16_t s1 = (x[0] >> 16) ^ (x[3] & 0xFFFF);
        uint16_t s2 = (x[2] & 0xFFFF) ^ (x[7] >> 16);
        uint16_t s3 = (x[2] >> 16) ^ (x[5] & 0xFFFF);
        uint16_t s4 = (x[4] & 0xFFFF) ^ (x[1] >> 16);
        uint16_t s5 = (x[4] >> 16) ^ (x[7] & 0xFFFF);
        uint16_t s6 = (x[6] & 0xFFFF) ^ (x[3] >> 16);
        uint16_t s7 = (x[6] >> 16) ^ (x[1] & 0xFFFF);

        uint16_t s[8] = { s0, s1, s2, s3, s4, s5, s6, s7 };
        for (int j = 0; j < 16; ++j) { // формирование ключевого потока
            if (i + j < length) {
                output[i + j] = (s[j / 2] >> ((j % 2) * 8)) & 0xFF;
            }
        }
    }
}

// функция шифрования/дешифрования текста
void encryptDecryptRabbit(const uint8_t key[16], const uint8_t iv[8], uint8_t* data, size_t length) {
    uint32_t x[8], c[8];
    uint32_t phi;
    vector<uint8_t> keyStream(length); 

    rabbitSetup(x, c, phi, key, iv);
    rabbitGenerateKeyStream(x, c, phi, keyStream.data(), length);

    for (size_t i = 0; i < length; ++i) {
        data[i] ^= keyStream[i]; // xor с ключевым потоком
    }
}

void saveRabbitKeyAndIV(const string& filename, const uint8_t key[16], const uint8_t iv[8]) {
    ofstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не удалось открыть файл для записи ключа и IV");
    }

    file.write(reinterpret_cast<const char*>(key), 16);
    file.write(reinterpret_cast<const char*>(iv), 8);
}

void loadRabbitKeyAndIV(const string& filename, uint8_t key[16], uint8_t iv[8]) {
    ifstream file(filename, ios::binary | ios::ate);
    if (!file) {
        throw runtime_error("Не удалось открыть файл с ключом и IV");
    }

    streamsize fileSize = file.tellg();
    if (fileSize != 24) {
        throw runtime_error("Неверный размер файла с ключом и IV");
    }

    file.seekg(0, ios::beg);

    if (!file.read(reinterpret_cast<char*>(key), 16)) {
        throw runtime_error("Ошибка чтения ключа из файла");
    }

    if (!file.read(reinterpret_cast<char*>(iv), 8)) {
        throw runtime_error("Ошибка чтения вектора инициализации из файла");
    }
}

extern "C" {
    void rabbitEncryptFile(const string& inputFile, const string& outputFile, const string& keyNonceFile) {
        auto inputData = readFile(inputFile);
        if (inputData.empty()) return;

        uint8_t key[16];
        uint8_t iv[8];
        generateRabbitKeyAndIV(key, iv);

        encryptDecryptRabbit(key, iv, inputData.data(), inputData.size());
        writeFile(outputFile, inputData);
        saveRabbitKeyAndIV(keyNonceFile, key, iv);
    }

    void rabbitDecryptFile(const string& inputFile, const string& keyNonceFile, const string& outputFile) {
        auto cipherData = readFile(inputFile);
        if (cipherData.empty()) return;

        uint8_t key[16];
        uint8_t iv[8];
        loadRabbitKeyAndIV(keyNonceFile, key, iv);

        encryptDecryptRabbit(key, iv, cipherData.data(), cipherData.size());
        writeFile(outputFile, cipherData);
    }

    string rabbitEncryptText(const string& text, const string& keyNonceFile) {
        uint8_t key[16];
        uint8_t iv[8];
        generateRabbitKeyAndIV(key, iv);

        vector<uint8_t> textVec(text.begin(), text.end());
        encryptDecryptRabbit(key, iv, textVec.data(), textVec.size());
        saveRabbitKeyAndIV(keyNonceFile, key, iv);

        return string(textVec.begin(), textVec.end());
    }
    
    string rabbitDecryptText(const string& ciphertext, const string& keyNonceFile) {
        uint8_t key[16];
        uint8_t iv[8];
        loadRabbitKeyAndIV(keyNonceFile, key, iv);

        vector<uint8_t> cipherVec(ciphertext.begin(), ciphertext.end());
        encryptDecryptRabbit(key, iv, cipherVec.data(), cipherVec.size());
        
        return string(cipherVec.begin(), cipherVec.end());
    }
}
