#include "utils.hpp"

#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>

std::vector<std::string> Utils::strsplit(char *str, const char *delimeter)
{
	auto splits = std::vector<std::string>();

	char* split = strtok(str, delimeter);
	splits.emplace(splits.end(), std::string(split));

	while(split)
	{
		split = strtok(nullptr, delimeter);
		if (!split)
		{
			break;
		}

		splits.emplace(splits.end(), std::string(split));
	}

	return splits;
}

namespace
{
	std::string finalizeSha256(EVP_MD_CTX* ctx)
	{
		unsigned char sha256Bytes[EVP_MAX_MD_SIZE];
		unsigned int sha256Length = 0;
		if (EVP_DigestFinal_ex(ctx, sha256Bytes, &sha256Length) != 1)
		{
			EVP_MD_CTX_free(ctx);
			throw std::runtime_error("Unable to finalize SHA256!");
		}
		EVP_MD_CTX_free(ctx);

		std::stringstream sha256;
		for (unsigned int i = 0; i < sha256Length; i++)
		{
			sha256 << std::hex << std::setw(2) << std::setfill('0') << (int)sha256Bytes[i];
		}

		return sha256.str();
	}

	EVP_MD_CTX* initSha256()
	{
		EVP_MD_CTX* ctx = EVP_MD_CTX_new();
		if (!ctx)
			throw std::runtime_error("Unable to initialize SHA256!");
		if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
		{
			EVP_MD_CTX_free(ctx);
			throw std::runtime_error("Unable to initialize SHA256!");
		}
		return ctx;
	}
}

std::string Utils::getFileSHA256(const char *filePath)
{
	std::ifstream fs(filePath, std::ios::binary);
	if (!fs.is_open())
		throw std::runtime_error("Unable to read file!");

	EVP_MD_CTX* ctx = initSha256();

	char buffer[64 * 1024];
	while (fs.good())
	{
		fs.read(buffer, sizeof(buffer));
		const std::streamsize read = fs.gcount();
		if (read > 0 && EVP_DigestUpdate(ctx, buffer, static_cast<size_t>(read)) != 1)
		{
			EVP_MD_CTX_free(ctx);
			throw std::runtime_error("Unable to update SHA256!");
		}
	}
	if (fs.bad())
	{
		EVP_MD_CTX_free(ctx);
		throw std::runtime_error("Unable to read complete file!");
	}

	return finalizeSha256(ctx);
}

std::string Utils::sha256OfString(const std::string& data)
{
	EVP_MD_CTX* ctx = initSha256();

	if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
	{
		EVP_MD_CTX_free(ctx);
		throw std::runtime_error("Unable to update SHA256!");
	}

	return finalizeSha256(ctx);
}
