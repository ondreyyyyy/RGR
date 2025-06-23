#include <iostream>
#include <stdexcept>
#include <limits>
#include <string>
#include <cstdlib>
#include <dlfcn.h>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>
#include "file.h"

using namespace std;
namespace fs = std::filesystem;

typedef void (*aesEncryptFileFunc)(const string&, const string&, const string&);
typedef void (*aesDecryptFileFunc)(const string&, const string&, const string&);
typedef string (*aesEncryptTextFunc)(const string&, const string&);
typedef string (*aesDecryptTextFunc)(const string&, const string&);

typedef void (*chachaEncryptFileFunc)(const string&, const string&, const string&);
typedef void (*chachaDecryptFileFunc)(const string&, const string&, const string&);
typedef string (*chachaEncryptTextFunc)(const string&, const string&);
typedef string (*chachaDecryptTextFunc)(const string&, const string&);

typedef void (*rabbitEncryptFileFunc)(const string&, const string&, const string&);
typedef void (*rabbitDecryptFileFunc)(const string&, const string&, const string&);
typedef string (*rabbitEncryptTextFunc)(const string&, const string&);
typedef string (*rabbitDecryptTextFunc)(const string&, const string&);

enum class Cipher {
    AES,
    CHACHA20,
    RABBIT,
    EXIT,
    UNKNOWN
};

int main() {
    setlocale(LC_ALL, "RU");

    void* aesLib = dlopen("./libaes.so", RTLD_LAZY);
    void* chachaLib = dlopen("./libchacha.so", RTLD_LAZY);
    void* rabbitLib = dlopen("./librabbit.so", RTLD_LAZY);

    aesEncryptFileFunc aesEncryptFile = nullptr;
    aesDecryptFileFunc aesDecryptFile = nullptr;
    aesEncryptTextFunc aesEncryptText = nullptr;
    aesDecryptTextFunc aesDecryptText = nullptr;

    chachaEncryptFileFunc chachaEncryptFile = nullptr;
    chachaDecryptFileFunc chachaDecryptFile = nullptr;
    chachaEncryptTextFunc chachaEncryptText = nullptr;
    chachaDecryptTextFunc chachaDecryptText = nullptr;

    rabbitEncryptFileFunc rabbitEncryptFile = nullptr;
    rabbitDecryptFileFunc rabbitDecryptFile = nullptr;
    rabbitEncryptTextFunc rabbitEncryptText = nullptr;
    rabbitDecryptTextFunc rabbitDecryptText = nullptr;

    if (aesLib) {
        aesEncryptFile = (aesEncryptFileFunc)dlsym(aesLib, "aesEncryptFile");
        aesDecryptFile = (aesDecryptFileFunc)dlsym(aesLib, "aesDecryptFile");
        aesEncryptText = (aesEncryptTextFunc)dlsym(aesLib, "aesEncryptText");
        aesDecryptText = (aesDecryptTextFunc)dlsym(aesLib, "aesDecryptText");

        if (!aesEncryptFile || !aesDecryptFile || !aesEncryptText || !aesDecryptText) {
            cerr << "Ошибка при загрузке функций AES: " << dlerror() << endl;
            dlclose(aesLib);
            aesLib = nullptr;
        }
    }

    if (chachaLib) {
        chachaEncryptFile = (chachaEncryptFileFunc)dlsym(chachaLib, "chachaEncryptFile");
        chachaDecryptFile = (chachaDecryptFileFunc)dlsym(chachaLib, "chachaDecryptFile");
        chachaEncryptText = (chachaEncryptTextFunc)dlsym(chachaLib, "chachaEncryptText");
        chachaDecryptText = (chachaDecryptTextFunc)dlsym(chachaLib, "chachaDecryptText");

        if (!chachaEncryptFile || !chachaDecryptFile || !chachaEncryptText || !chachaDecryptText) {
            cerr << "Ошибка при загрузке функций ChaCha20: " << dlerror() << endl;
            dlclose(chachaLib);
            chachaLib = nullptr;
        }
    }

    if (rabbitLib) {
        rabbitEncryptFile = (rabbitEncryptFileFunc)dlsym(rabbitLib, "rabbitEncryptFile");
        rabbitDecryptFile = (rabbitDecryptFileFunc)dlsym(rabbitLib, "rabbitDecryptFile");
        rabbitEncryptText = (rabbitEncryptTextFunc)dlsym(rabbitLib, "rabbitEncryptText");
        rabbitDecryptText = (rabbitDecryptTextFunc)dlsym(rabbitLib, "rabbitDecryptText");

        if (!rabbitEncryptFile || !rabbitDecryptFile || !rabbitEncryptText || !rabbitDecryptText) {
            cerr << "Ошибка при загрузке функций Rabbit: " << dlerror() << endl;
            dlclose(rabbitLib);
            rabbitLib = nullptr;
        }
    }

    while (true) {
        try {
            cout << "\n==АЛГОРИТМЫ ШИФРОВАНИЯ/ДЕШИФРОВАНИЯ==\n";
            cout << "1. AES" << (aesLib ? "" : " (недоступно)") << "\n";
            cout << "2. ChaCha20" << (chachaLib ? "" : " (недоступно)") << "\n";
            cout << "3. Rabbit" << (rabbitLib ? "" : " (недоступно)") << "\n";
            cout << "4. Выход\n";
            cout << "Введите команду: ";

            Cipher cipherChoice;
            int cipherSelect;
            cin >> cipherSelect;
            cin.ignore();

            if (cin.fail()) {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                throw runtime_error("Ошибка ввода. Пожалуйста, введите число.");
            }

            switch (cipherSelect) {
                case 1: cipherChoice = Cipher::AES; break;
                case 2: cipherChoice = Cipher::CHACHA20; break;
                case 3: cipherChoice = Cipher::RABBIT; break;
                case 4: cipherChoice = Cipher::EXIT; break;
                default: cipherChoice = Cipher::UNKNOWN;
            }

            if (cipherChoice == Cipher::EXIT) break;
            if (cipherChoice == Cipher::UNKNOWN) {
                cout << "Неизвестный алгоритм. Попробуйте снова.\n";
                continue;
            }
            
            if (cipherChoice == Cipher::AES) {
                if (!aesLib) {
                    cout << "Ошибка: библиотека AES не загружена или недоступна!\n";
                    continue;
                }
                while (true) {
                    try {
                        cout << "\n==АЛГОРИТМ ШИФРОВАНИЯ/ДЕШИФРОВАНИЯ AES128 (CBC)==\n";
                        cout << "1. Шифрование\n";
                        cout << "2. Дешифрование\n";
                        cout << "3. Выход\n";
                        cout << "Выберите команду: ";

                        int choice;
                        cin >> choice;
                        cin.ignore();
                        if (cin.fail()) {
                            throw logic_error("Введено недопустимое значение.");
                        }
                        if (choice == 3) {
                            break;
                        }
                        else if (choice != 1 && choice != 2) {
                            throw logic_error("Неизвестная команда.");
                        }

                        cout << "\nВыберите способ ввода:\n";
                        cout << "1. Консоль\n2. Файл\n";
                        cout << "Номер способа: ";

                        int inputMethod;
                        cin >> inputMethod;
                        cin.ignore();

                        if (cin.fail()) {
                            throw logic_error("Введено недопустимое значение.");
                        }
                        else if (inputMethod != 1 && inputMethod != 2) {
                            throw logic_error("Неизвестная команда.");
                        }

                        if (choice == 1) { 
                            if (inputMethod == 1) {
                                string text, keyFile, outputFile;
                                cout << "Введите текст: ";
                                getline(cin, text);
                                if (text.empty()) {
                                    throw runtime_error("Текст не может быть пустым.");
                                }

                                cout << "Введите полный путь для сохранения ключа и IV: ";
                                getline(cin, keyFile);
                                if (keyFile.empty()) {
                                    throw runtime_error("Путь к файлу ключа не может быть пустым.");
                                }

                                cout << "Введите полный путь для сохранения шифртекста: ";
                                getline(cin, outputFile);
                                if (outputFile.empty()) {
                                    throw runtime_error("Путь к файлу шифртекста не может быть пустым.");
                                }

                                try {
                                    string ciphertext = aesEncryptText(text, keyFile);
                                    writeFile(outputFile, vector<unsigned char>(ciphertext.begin(), ciphertext.end()));
                                    
                                    // вывод в hex
                                    ostringstream hexStream;
                                    hexStream << hex << setfill('0');
                                    for (unsigned char c : ciphertext) {
                                        hexStream << setw(2) << static_cast<int>(c);
                                    }
                                    string hexCiphertext = hexStream.str();
                                    
                                    cout << "Текст успешно зашифрован в файл " << outputFile << endl;
                                    cout << "Ключ и IV сохранен в файл " << keyFile << endl;
                                    cout << "Шифртекст (hex): " << hexCiphertext << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при шифровании: ") + e.what());
                                }
                            } else { 
                                string filename, keyFile, cipherFile;
                                cout << "Введите полный путь к файлу для шифрования: ";
                                getline(cin, filename);
                                if (!fs::exists(filename)) {
                                    throw runtime_error("Файл для шифрования не существует.");
                                }

                                cout << "Введите полный путь для сохранения ключа и IV: ";
                                getline(cin, keyFile);
                                if (keyFile.empty()) {
                                    throw runtime_error("Путь к файлу ключа не может быть пустым.");
                                }

                                cout << "Введите полный путь для сохранения шифртекста: ";
                                getline(cin, cipherFile);
                                if (cipherFile.empty()) {
                                    throw runtime_error("Путь к файлу шифртекста не может быть пустым.");
                                }

                                try {
                                    aesEncryptFile(filename, cipherFile, keyFile);
                                    cout << "Файл успешно зашифрован в " << cipherFile << endl;
                                    cout << "Ключ и IV сохранен в файл " << keyFile << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при шифровании файла: ") + e.what());
                                }
                            }
                        } else { 
                            if (inputMethod == 1) {
                                string hexCiphertext, keyFile, outputFile;
                                cout << "Введите шифртекст (в hex-формате): ";
                                getline(cin, hexCiphertext);
                                
                                // удаление пробелов и не hex символов
                                hexCiphertext.erase(remove_if(hexCiphertext.begin(), hexCiphertext.end(), [](char c) {
                                    return !isxdigit(c);
                                }), hexCiphertext.end());
                                
                                if (hexCiphertext.empty() || hexCiphertext.size() % 2 != 0) {
                                    throw runtime_error("Некорректный hex-формат шифртекста.");
                                }

                                // преобразование hex в байты
                                vector<unsigned char> ciphertextBytes;
                                for (size_t i = 0; i < hexCiphertext.length(); i += 2) {
                                    string byteString = hexCiphertext.substr(i, 2);
                                    unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
                                    ciphertextBytes.push_back(byte);
                                }
                                string ciphertext(ciphertextBytes.begin(), ciphertextBytes.end());

                                cout << "Введите полный путь к файлу с ключом и IV: ";
                                getline(cin, keyFile);
                                if (!fs::exists(keyFile)) {
                                    throw runtime_error("Файл с ключом не существует.");
                                }

                                cout << "Введите полный путь для сохранения расшифрованного текста: ";
                                getline(cin, outputFile);
                                if (outputFile.empty()) {
                                    throw runtime_error("Путь для сохранения результата не может быть пустым.");
                                }

                                try {
                                    string plaintext = aesDecryptText(ciphertext, keyFile);
                                    writeFile(outputFile, vector<unsigned char>(plaintext.begin(), plaintext.end()));
                                    cout << "Текст успешно расшифрован в файл " << outputFile << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при дешифровании: ") + e.what());
                                }
                            } else { 
                                string cipherFile, keyFile, outputFile;
                                cout << "Введите полный путь к файлу с шифртекстом: ";
                                getline(cin, cipherFile);
                                if (!fs::exists(cipherFile)) {
                                    throw runtime_error("Файл с шифртекстом не существует.");
                                }

                                cout << "Введите полный путь к файлу с ключом и IV: ";
                                getline(cin, keyFile);
                                if (!fs::exists(keyFile)) {
                                    throw runtime_error("Файл с ключом не существует.");
                                }

                                cout << "Введите полный путь для сохранения расшифрованного файла: ";
                                getline(cin, outputFile);
                                if (outputFile.empty()) {
                                    throw runtime_error("Путь для сохранения результата не может быть пустым.");
                                }

                                try {
                                    aesDecryptFile(cipherFile, keyFile, outputFile);
                                    cout << "Файл успешно расшифрован в " << outputFile << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при дешифровании: ") + e.what());
                                }
                            }
                        }
                    }
                    catch (const exception& e) {
                        cerr << "Ошибка: " << e.what() << endl;
                        cin.clear();
                        cin.ignore(numeric_limits<streamsize>::max(), '\n');
                    }
                }
            }
            else if (cipherChoice == Cipher::CHACHA20) {
                if (!chachaLib) {
                    cout << "Ошибка: библиотека ChaCha20 не загружена или недоступна!\n";
                    continue;
                }
                while (true) {
                    try {
                        cout << "\n==АЛГОРИТМ ШИФРОВАНИЯ/ДЕШИФРОВАНИЯ ChaCha20==\n";
                        cout << "1. Шифрование\n";
                        cout << "2. Дешифрование\n";
                        cout << "3. Выход\n";
                        cout << "Выберите команду: ";

                        int choice;
                        cin >> choice;
                        cin.ignore();
                        if (cin.fail()) {
                            throw logic_error("Введено недопустимое значение.");
                        }
                        if (choice == 3) {
                            break;
                        }
                        else if (choice != 1 && choice != 2) {
                            throw logic_error("Неизвестная команда.");
                        }

                        cout << "\nВыберите способ ввода:\n";
                        cout << "1. Консоль\n2. Файл\n";
                        cout << "Номер способа: ";

                        int inputMethod;
                        cin >> inputMethod;
                        cin.ignore();

                        if (inputMethod == 1) {
                            if (choice == 1) { 
                                string text, keyFile, outputFile;
                                cout << "Введите текст: ";
                                getline(cin, text);
                                if (text.empty()) {
                                    throw runtime_error("Текст не может быть пустым.");
                                }

                                cout << "Введите полный путь для сохранения ключа и nonce: ";
                                getline(cin, keyFile);
                                if (keyFile.empty()) {
                                    throw runtime_error("Путь к файлу ключа не может быть пустым.");
                                }

                                cout << "Введите полный путь для сохранения шифртекста: ";
                                getline(cin, outputFile);
                                if (outputFile.empty()) {
                                    throw runtime_error("Путь к файлу шифртекста не может быть пустым.");
                                }

                                try {
                                    string ciphertext = chachaEncryptText(text, keyFile);
                                    writeFile(outputFile, vector<unsigned char>(ciphertext.begin(), ciphertext.end()));
                                    
                                    // вывод в hex
                                    ostringstream hexStream;
                                    hexStream << hex << setfill('0');
                                    for (unsigned char c : ciphertext) {
                                        hexStream << setw(2) << static_cast<int>(c);
                                    }
                                    string hexCiphertext = hexStream.str();
                                    
                                    cout << "Текст успешно зашифрован в файл " << outputFile << endl;
                                    cout << "Шифртекст (hex): " << hexCiphertext << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при шифровании: ") + e.what());
                                }
                            } else { 
                                string hexCiphertext, keyFile, outputFile;
                                cout << "Введите шифртекст (в hex-формате): ";
                                getline(cin, hexCiphertext);
                                
                                // удаление пробелов и не hex символов
                                hexCiphertext.erase(remove_if(hexCiphertext.begin(), hexCiphertext.end(), [](char c) {
                                    return !isxdigit(c);
                                }), hexCiphertext.end());
                                
                                if (hexCiphertext.empty() || hexCiphertext.size() % 2 != 0) {
                                    throw runtime_error("Некорректный hex-формат шифртекста.");
                                }

                                // преобразование hex в байты
                                vector<unsigned char> ciphertextBytes;
                                for (size_t i = 0; i < hexCiphertext.length(); i += 2) {
                                    string byteString = hexCiphertext.substr(i, 2);
                                    unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
                                    ciphertextBytes.push_back(byte);
                                }
                                string ciphertext(ciphertextBytes.begin(), ciphertextBytes.end());

                                cout << "Введите полный путь к файлу с ключом и nonce: ";
                                getline(cin, keyFile);
                                if (!fs::exists(keyFile)) {
                                    throw runtime_error("Файл с ключом не существует.");
                                }

                                cout << "Введите полный путь для сохранения расшифрованного текста: ";
                                getline(cin, outputFile);
                                if (outputFile.empty()) {
                                    throw runtime_error("Путь для сохранения результата не может быть пустым.");
                                }

                                try {
                                    string plaintext = chachaDecryptText(ciphertext, keyFile);
                                    writeFile(outputFile, vector<unsigned char>(plaintext.begin(), plaintext.end()));
                                    cout << "Текст успешно расшифрован в файл " << outputFile << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при дешифровании: ") + e.what());
                                }
                            }
                        } else {
                            if (choice == 1) {
                                string filename, keyFile, cipherFile;
                                cout << "Введите полный путь к файлу для шифрования: ";
                                getline(cin, filename);
                                if (!fs::exists(filename)) {
                                    throw runtime_error("Файл для шифрования не существует.");
                                }

                                cout << "Введите полный путь для сохранения ключа и nonce: ";
                                getline(cin, keyFile);
                                if (keyFile.empty()) {
                                    throw runtime_error("Путь к файлу ключа не может быть пустым.");
                                }

                                cout << "Введите полный путь для сохранения шифртекста: ";
                                getline(cin, cipherFile);
                                if (cipherFile.empty()) {
                                    throw runtime_error("Путь к файлу шифртекста не может быть пустым.");
                                }

                                try {
                                    chachaEncryptFile(filename, cipherFile, keyFile);
                                    cout << "Файл успешно зашифрован в " << cipherFile << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при шифровании файла: ") + e.what());
                                }
                            } else {
                                string cipherFile, keyFile, outputFile;
                                cout << "Введите полный путь к файлу с шифртекстом: ";
                                getline(cin, cipherFile);
                                if (!fs::exists(cipherFile)) {
                                    throw runtime_error("Файл с шифртекстом не существует.");
                                }

                                cout << "Введите полный путь к файлу с ключом и nonce: ";
                                getline(cin, keyFile);
                                if (!fs::exists(keyFile)) {
                                    throw runtime_error("Файл с ключом не существует.");
                                }

                                cout << "Введите полный путь для сохранения расшифрованного файла: ";
                                getline(cin, outputFile);
                                if (outputFile.empty()) {
                                    throw runtime_error("Путь для сохранения результата не может быть пустым.");
                                }

                                try {
                                    chachaDecryptFile(cipherFile, keyFile, outputFile);
                                    cout << "Файл успешно расшифрован в " << outputFile << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при дешифровании: ") + e.what());
                                }
                            }
                        }
                    }
                    catch (const exception& e) {
                        cerr << "Ошибка: " << e.what() << endl;
                        cin.clear();
                        cin.ignore(numeric_limits<streamsize>::max(), '\n');
                    }
                }
            }
            else if (cipherChoice == Cipher::RABBIT) {
                if (!rabbitLib) {
                    cout << "Ошибка: библиотека Rabbit не загружена или недоступна!\n";
                    continue;
                }
                while (true) {
                    try {
                        cout << "\n==АЛГОРИТМ ШИФРОВАНИЯ/ДЕШИФРОВАНИЯ Rabbit==\n";
                        cout << "1. Шифрование\n";
                        cout << "2. Дешифрование\n";
                        cout << "3. Выход\n";
                        cout << "Выберите команду: ";

                        int choice;
                        cin >> choice;
                        cin.ignore();
                        if (cin.fail()) {
                            throw logic_error("Введено недопустимое значение.");
                        }
                        if (choice == 3) {
                            break;
                        }
                        else if (choice != 1 && choice != 2) {
                            throw logic_error("Неизвестная команда.");
                        }

                        cout << "\nВыберите способ ввода:\n";
                        cout << "1. Консоль\n2. Файл\n";
                        cout << "Номер способа: ";

                        int inputMethod;
                        cin >> inputMethod;
                        cin.ignore();

                        if (inputMethod == 1) {
                            if (choice == 1) { 
                                string text, keyFile, outputFile;
                                cout << "Введите текст: ";
                                getline(cin, text);
                                if (text.empty()) {
                                    throw runtime_error("Текст не может быть пустым.");
                                }

                                cout << "Введите полный путь для сохранения ключа: ";
                                getline(cin, keyFile);
                                if (keyFile.empty()) {
                                    throw runtime_error("Путь к файлу ключа не может быть пустым.");
                                }

                                cout << "Введите полный путь для сохранения шифртекста: ";
                                getline(cin, outputFile);
                                if (outputFile.empty()) {
                                    throw runtime_error("Путь к файлу шифртекста не может быть пустым.");
                                }

                                try {
                                    string ciphertext = rabbitEncryptText(text, keyFile);
                                    writeFile(outputFile, vector<unsigned char>(ciphertext.begin(), ciphertext.end()));
                                    
                                    // вывод в hex
                                    ostringstream hexStream;
                                    hexStream << hex << setfill('0');
                                    for (unsigned char c : ciphertext) {
                                        hexStream << setw(2) << static_cast<int>(c);
                                    }
                                    string hexCiphertext = hexStream.str();
                                    
                                    cout << "Текст успешно зашифрован в файл " << outputFile << endl;
                                    cout << "Шифртекст (hex): " << hexCiphertext << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при шифровании: ") + e.what());
                                }
                            } else { 
                                string hexCiphertext, keyFile, outputFile;
                                cout << "Введите шифртекст (в hex-формате): ";
                                getline(cin, hexCiphertext);
                                
                                // удаление пробелов и не hex символов
                                hexCiphertext.erase(remove_if(hexCiphertext.begin(), hexCiphertext.end(), [](char c) {
                                    return !isxdigit(c);
                                }), hexCiphertext.end());
                                
                                if (hexCiphertext.empty() || hexCiphertext.size() % 2 != 0) {
                                    throw runtime_error("Некорректный hex-формат шифртекста.");
                                }

                                // преобразование hex в байты
                                vector<unsigned char> ciphertextBytes;
                                for (size_t i = 0; i < hexCiphertext.length(); i += 2) {
                                    string byteString = hexCiphertext.substr(i, 2);
                                    unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
                                    ciphertextBytes.push_back(byte);
                                }
                                string ciphertext(ciphertextBytes.begin(), ciphertextBytes.end());

                                cout << "Введите полный путь к файлу с ключом: ";
                                getline(cin, keyFile);
                                if (!fs::exists(keyFile)) {
                                    throw runtime_error("Файл с ключом не существует.");
                                }

                                cout << "Введите полный путь для сохранения расшифрованного текста: ";
                                getline(cin, outputFile);
                                if (outputFile.empty()) {
                                    throw runtime_error("Путь для сохранения результата не может быть пустым.");
                                }

                                try {
                                    string plaintext = rabbitDecryptText(ciphertext, keyFile);
                                    writeFile(outputFile, vector<unsigned char>(plaintext.begin(), plaintext.end()));
                                    cout << "Текст успешно расшифрован в файл " << outputFile << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при дешифровании: ") + e.what());
                                }
                            }
                        } else {
                            if (choice == 1) { 
                                string filename, keyFile, cipherFile;
                                cout << "Введите полный путь к файлу для шифрования: ";
                                getline(cin, filename);
                                if (!fs::exists(filename)) {
                                    throw runtime_error("Файл для шифрования не существует.");
                                }

                                cout << "Введите полный путь для сохранения ключа: ";
                                getline(cin, keyFile);
                                if (keyFile.empty()) {
                                    throw runtime_error("Путь к файлу ключа не может быть пустым.");
                                }

                                cout << "Введите полный путь для сохранения шифртекста: ";
                                getline(cin, cipherFile);
                                if (cipherFile.empty()) {
                                    throw runtime_error("Путь к файлу шифртекста не может быть пустым.");
                                }

                                try {
                                    rabbitEncryptFile(filename, cipherFile, keyFile);
                                    cout << "Файл успешно зашифрован в " << cipherFile << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при шифровании файла: ") + e.what());
                                }
                            } else { 
                                string cipherFile, keyFile, outputFile;
                                cout << "Введите полный путь к файлу с шифртекстом: ";
                                getline(cin, cipherFile);
                                if (!fs::exists(cipherFile)) {
                                    throw runtime_error("Файл с шифртекстом не существует.");
                                }

                                cout << "Введите полный путь к файлу с ключом: ";
                                getline(cin, keyFile);
                                if (!fs::exists(keyFile)) {
                                    throw runtime_error("Файл с ключом не существует.");
                                }

                                cout << "Введите полный путь для сохранения расшифрованного файла: ";
                                getline(cin, outputFile);
                                if (outputFile.empty()) {
                                    throw runtime_error("Путь для сохранения результата не может быть пустым.");
                                }

                                try {
                                    rabbitDecryptFile(cipherFile, keyFile, outputFile);
                                    cout << "Файл успешно расшифрован в " << outputFile << endl;
                                } catch (const exception& e) {
                                    throw runtime_error(string("Ошибка при дешифровании: ") + e.what());
                                }
                            }
                        }
                    }
                    catch (const exception& e) {
                        cerr << "Ошибка: " << e.what() << endl;
                        cin.clear();
                        cin.ignore(numeric_limits<streamsize>::max(), '\n');
                    }
                }
            }
        }
        catch (const exception& e) {
            cerr << "Ошибка: " << e.what() << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    }

    if (aesLib) dlclose(aesLib);
    if (chachaLib) dlclose(chachaLib);
    if (rabbitLib) dlclose(rabbitLib);
    return 0;
}
