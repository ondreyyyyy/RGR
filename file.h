#ifndef FILE_H
#define FILE_H

#include <vector>
#include <string>
#include <stdexcept>
#include <fstream>

std::vector<unsigned char> readFile(const std::string& filename);
void writeFile(const std::string& filename, const std::vector<unsigned char>& data);

#endif // FILE_H