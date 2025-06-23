#include "file.h"
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;

vector<unsigned char> readFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не удалось открыть файл: " + filename);
    }

    file.seekg(0, ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, ios::beg);

    vector<unsigned char> data(fileSize);
    if (!file.read(reinterpret_cast<char*>(data.data()), fileSize)) {
        throw runtime_error("Ошибка чтения фалйа: " + filename);
    }

    return data;
}

void writeFile(const string& filename, const vector<unsigned char>& data) {
    ofstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не удалось создать файл: " + filename);
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}
