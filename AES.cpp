#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <fstream>
#include <random>
#include <algorithm>
#include "file.h"
#include "AES.h"

using namespace std;

const unsigned char Sbox[256] = { // нелинейная таблица замен для трансформации байтов
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const unsigned char InvSbox[256] = { // обратный Sbox (для процедуры дешифрования)
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// константы для генерации раундовых ключей
const unsigned char Rcon[11] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

// генерация ключа и вектора инициализации
void generateKeyAndIV(vector<unsigned char>& key, vector<unsigned char>& IV) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);

    key.resize(16);
    IV.resize(16);

    for (int i = 0; i < 16; i++) {
        key[i] = static_cast<unsigned char>(dis(gen));
        IV[i] = static_cast<unsigned char>(dis(gen));
    }
}

// функция для расширения ключа (необходимо 11 ключей по 16 байт)
void keyExpantion(const unsigned char key[16], unsigned char extendedKey[176]) {
    for (int i = 0; i < 16; i++) {
        extendedKey[i] = key[i];
    }
    
    for (int i = 4; i < 44; i++) { // для 11 подключей нужно 44 слова, 4 уже есть. 1 слово - 4 байта
        unsigned char tempW[4];
        for (int j = 0; j < 4; j++) { // предыдущее слово
            tempW[j] = extendedKey[(i - 1) * 4 + j];
        }

        if (i % 4 == 0) { // если номер текущего слова делится на 4
            unsigned char lastByte = tempW[0]; // двигаем слово влево
            tempW[0] = tempW[1];
            tempW[1] = tempW[2];
            tempW[2] = tempW[3];
            tempW[3] = lastByte;

            for (int j = 0; j < 4; j++) { // заменяем байты слова на байты из Sbox
                tempW[j] = Sbox[tempW[j]];
            }

            tempW[0] ^= Rcon[i / 4]; // XOR с константой из Rcon

        }
    
        for (int j = 0; j < 4; j++) { // XOR с предыдущим словом и запись нового слова
            extendedKey[i * 4 + j] = extendedKey[(i - 4) * 4 + j] ^ tempW[j];
        }
    }
}

// функция для замены текущего состояния на байты из Sbox
void subBytes(unsigned char state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = Sbox[state[i]];
    }
}

// функция для обратной замены 
void invSubBytes(unsigned char state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = InvSbox[state[i]];
    }
}

// функции для сдвига строк в матрице состояния
void ShiftRows(unsigned char state[16]) {
    unsigned char temp;

    // первая не двигается, вторая - влево на 1 байт
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // третья - на 2 байта влево
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // четвертая строка - на 3 байта влево
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

void InvShiftRows(unsigned char state[16]) {
    unsigned char temp;

    // Вторая строка: сдвиг вправо на 1 байт
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // Третья строка: сдвиг вправо на 2 байта
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Четвертая строка: сдвиг вправо на 3 байта
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// функция, с помощью которой будет производиться умножение стобца State на фиксированную матрицу в поле Галуа
unsigned char gfMultiplication(unsigned char a, unsigned char b) {
    unsigned char result = 0;
    unsigned char highBitSet; // флаг для проверки старшего бита

    for (int i = 0; i < 8; i++) { // проходимя по 8 битам
        if (b & 1) { // если младший бит это единица
            result ^= a; // xor (сложение в поле Галуа) a с результатом 
        }

        highBitSet = (a & 0x80); // проверяем старший бит а
        a <<= 1; // сдвигаем влево на 1 бит
        if (highBitSet) { // если был переполняющий бит
            a ^= 0x1b; // xor (вычитание) с неприводимым многочленом x^8 + x^4 + x^3 + x + 1 (0x1B) (гарантируем, что a всегда остается 8 битным числом)
        }
        b >>= 1; // переход к следующему биту
    }

    return result;
}

// функция для перемножения столбца состояния на фиксированную матрицу в поле Галуа
void mixColums(unsigned char state[16]) {
    unsigned char temp[16]; 

    for (int i = 0; i < 4; i++) {
        temp[i * 4 + 0] = (unsigned char)(gfMultiplication(0x02, state[i * 4 + 0]) ^ gfMultiplication(0x03, state[i * 4 + 1]) ^ state[i * 4 + 2] ^ state[i * 4 + 3]); //^ - сложение
        temp[i * 4 + 1] = (unsigned char)(state[i * 4 + 0] ^ gfMultiplication(0x02, state[i * 4 + 1]) ^ gfMultiplication(0x03, state[i * 4 + 2]) ^ state[i * 4 + 3]);
        temp[i * 4 + 2] = (unsigned char)(state[i * 4 + 0] ^ state[i * 4 + 1] ^ gfMultiplication(0x02, state[i * 4 + 2]) ^ gfMultiplication(0x03, state[i * 4 + 3]));
        temp[i * 4 + 3] = (unsigned char)(gfMultiplication(0x03, state[i * 4 + 0]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ gfMultiplication(0x02, state[i * 4 + 3]));
    }

    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}

// обратный процесс
void invMixColumns(unsigned char state[16]) {
    unsigned char temp[16];

    for (int i = 0; i < 4; i++) {
        temp[i * 4 + 0] = (unsigned char)(gfMultiplication(0x0e, state[i * 4 + 0]) ^ gfMultiplication(0x0b, state[i * 4 + 1]) ^ gfMultiplication(0x0d, state[i * 4 + 2]) ^ gfMultiplication(0x09, state[i * 4 + 3]));
        temp[i * 4 + 1] = (unsigned char)(gfMultiplication(0x09, state[i * 4 + 0]) ^ gfMultiplication(0x0e, state[i * 4 + 1]) ^ gfMultiplication(0x0b, state[i * 4 + 2]) ^ gfMultiplication(0x0d, state[i * 4 + 3]));
        temp[i * 4 + 2] = (unsigned char)(gfMultiplication(0x0d, state[i * 4 + 0]) ^ gfMultiplication(0x09, state[i * 4 + 1]) ^ gfMultiplication(0x0e, state[i * 4 + 2]) ^ gfMultiplication(0x0b, state[i * 4 + 3]));
        temp[i * 4 + 3] = (unsigned char)(gfMultiplication(0x0b, state[i * 4 + 0]) ^ gfMultiplication(0x0d, state[i * 4 + 1]) ^ gfMultiplication(0x09, state[i * 4 + 2]) ^ gfMultiplication(0x0e, state[i * 4 + 3]));
    }

    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}

// функция последнего этапа раунда (xor текущего состояния state с раунд-ключом)
void AddRoundKey(unsigned char state[16], const unsigned char roundKey[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

// процесс шифровки блока открытого текста
void AESencryptBlock(unsigned char state[16], const unsigned char extendedKey[176]) {
    // начальный раунд с первым раунд-ключом
    AddRoundKey(state, extendedKey);

    // 9 раундов
    for (int i = 1; i < 10; i++) {
        subBytes(state);
        ShiftRows(state);
        mixColums(state);
        AddRoundKey(state, extendedKey + i * 16);
    }

    // финальный раунд
    subBytes(state);
    ShiftRows(state);
    AddRoundKey(state, extendedKey + 10 * 16);
}

// дешифровка шифртекста
void AESdecryptBlock(unsigned char state[16], const unsigned char extendedKey[176]) {
    AddRoundKey(state, extendedKey + 10 * 16); // начальный раунд с последним раундовым ключом (обратный процесс)
    InvShiftRows(state);
    invSubBytes(state);

    for (int i = 9; i > 0; i--) {
        AddRoundKey(state, extendedKey + i * 16);
        invMixColumns(state);
        InvShiftRows(state);
        invSubBytes(state);
    }

    // финальный раунд с первым раунд ключом
    AddRoundKey(state, extendedKey);
}

// функция для дополнения блока до 16 байт
vector<unsigned char> Padding(const vector<unsigned char>& data) {
    size_t paddingLength = 16 - (data.size() % 16); // длина дополнения
    vector<unsigned char> paddedData = data;
    paddedData.insert(paddedData.end(), paddingLength, static_cast<unsigned char>(paddingLength)); // дополнение
    return paddedData;
}

// функция для удаления дополнения
vector<unsigned char> Unpadding(const vector<unsigned char>& data) {
    if (data.empty()) return data;

    size_t paddingLength = data.back();
    if (paddingLength == 0 || paddingLength > 16) return data; // блок кратен 16

    for (size_t i = data.size() - paddingLength; i < data.size(); i++) { // проверка что все количество paddingLength элементов равно paddingLength
        if (data[i] != paddingLength) return data;
    }

    return vector<unsigned char>(data.begin(), data.end() - paddingLength); // удаление дополнения
}

// XOR блоков 
void BlocksXOR(const unsigned char a[16], const unsigned char b[16], unsigned char result[16]) {
    for (int i = 0; i < 16; i++) {
        result[i] = a[i] ^ b[i];
    }
}

// основная функция для шифрования текста
vector<unsigned char> encryptAES128CBC(const vector<unsigned char>& plaintext, const vector<unsigned char>& key, const vector<unsigned char>& IV) {
    if (key.size() != 16 || IV.size() != 16) {
        throw runtime_error("Неверный размер ключа или вектора инициализации!");
    }

    unsigned char extendedKey[176]; // расширение ключа
    keyExpantion(key.data(), extendedKey);

    vector<unsigned char> paddedData = Padding(plaintext); // дополняем, чтобы было кратно 16

    vector<unsigned char> ciphertext;
    unsigned char prevBlock[16];
    copy(IV.begin(), IV.end(), prevBlock); // предыдущий блок - это вектор инициализации

    // процесс для каждого блока открытого текста
    for (size_t i = 0; i < paddedData.size(); i += 16) {
        unsigned char block[16];
        copy(paddedData.begin() + i, paddedData.begin() + 16 + i, block); // блок открытого текста

        BlocksXOR(block, prevBlock, block); // для CBC: XOR предыдущего блока (шифртекст или вектор инициализации) с блоком текущего открытого текста
        
        AESencryptBlock(block, extendedKey); // шифруем блок

        // запись полученного результата в шифртекст и переход к следующему блоку, текущий блок становится предыдущим
        copy(block, block + 16, prevBlock);
        ciphertext.insert(ciphertext.end(), block, block + 16);
    }

    return ciphertext;
}

// основная функция дешифровки
vector<unsigned char> decryptAES128CBC(const vector<unsigned char>& ciphertext, const vector<unsigned char>& key, const vector<unsigned char>& IV) {
    if (key.size() != 16 || IV.size() != 16) { 
        throw runtime_error("Неверный размер ключа или вектора инициализации!");
    }

    unsigned char extendedKey[176]; // расширение ключа
    keyExpantion(key.data(), extendedKey);

    vector<unsigned char> plaintext;
    unsigned char prevBlock[16];
    copy(IV.begin(), IV.end(), prevBlock); // предыдущий блок это вектор инициализации

    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        unsigned char block[16]; // текущий блок шифртекста
        copy(ciphertext.begin() + i, ciphertext.begin() + i + 16, block);

        unsigned char ciphertextBlock[16]; // расшифровка блока
        copy(block, block + 16, ciphertextBlock);
        AESdecryptBlock(block, extendedKey);

        BlocksXOR(block, prevBlock, block);
        plaintext.insert(plaintext.end(), block, block + 16); // результат записываем как открытый текст, при этом результат становится предыдущим блоком
        copy(ciphertextBlock, ciphertextBlock + 16, prevBlock);
    }
    vector<unsigned char> resultText = Unpadding(plaintext); // удаление дополнений
    return resultText;
}

// Сохранение ключа в файл
void saveKey(const string& filename, const vector<unsigned char>& key) {
    ofstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Невозможно открыть файл для записи: " + filename);
    }
    file.write(reinterpret_cast<const char*>(key.data()), key.size());
}

// Загрузка ключа из файла
vector<unsigned char> loadKey(const string& filename) {
    ifstream file(filename, ios::binary | ios::ate);
    if (!file) {
        throw runtime_error("Невозможно открыть файл для чтения: " + filename);
    }

    streamsize size = file.tellg();
    file.seekg(0, ios::beg); // Переходим в начало файла, чтобы нормально читать

    vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw runtime_error("Ошибка чтения из файла: " + filename);
    }

    return buffer;
}

extern "C" {
    void aesEncryptFile(const string& inputFile, const string& outputFile, const string& keyIVfile) {
        auto text = readFile(inputFile);
        vector<unsigned char> key, IV;
        generateKeyAndIV(key, IV);
        auto ciphertext = encryptAES128CBC(text, key, IV);
        writeFile(outputFile, ciphertext);

        vector<unsigned char> keyIV;
        keyIV.insert(keyIV.end(), key.begin(), key.end());
        keyIV.insert(keyIV.end(), IV.begin(), IV.end());
        writeFile(keyIVfile, keyIV);
    }

    void aesDecryptFile(const string& inputFile, const string& keyIVfile, const string& outputFile) {
        auto ciphertext = readFile(inputFile);
        auto keyIV = readFile(keyIVfile);
        if (keyIV.size() != 32) {
            throw runtime_error("Неверный размер файла с ключом и IV.");
        }
        vector<unsigned char> key(keyIV.begin(), keyIV.begin() + 16);
        vector<unsigned char> IV(keyIV.begin() + 16, keyIV.end());
        auto text = decryptAES128CBC(ciphertext, key, IV);
        writeFile(outputFile, text);
    }

    string aesEncryptText(const string& text, const string& keyIVfile) {
        vector<unsigned char> textVec(text.begin(), text.end());
        vector<unsigned char> key, IV;
        generateKeyAndIV(key, IV);
        auto ciphertext = encryptAES128CBC(textVec, key, IV);

        vector<unsigned char> keyIV;
        keyIV.insert(keyIV.end(), key.begin(), key.end());
        keyIV.insert(keyIV.end(), IV.begin(), IV.end());
        writeFile(keyIVfile, keyIV);

        return string(ciphertext.begin(), ciphertext.end());
    }
}