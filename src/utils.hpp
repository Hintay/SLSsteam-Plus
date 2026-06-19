#pragma once

#include <string>
#include <vector>


namespace Utils
{
	std::vector<std::string> strsplit(char* str, const char* delimeter);
	std::string getFileSHA256(const char* filePath);
	std::string sha256OfString(const std::string& data);
}
