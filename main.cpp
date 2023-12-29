#include <iostream>
#include <fstream>
#include <string>
#include <elfio/elfio.hpp>
#include "cryptopp/hmac.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"

// Key Generation
void generate_key(CryptoPP::SecByteBlock& key, size_t KEYSIZE);

// Performs HMAC-SHA256 and returns HMAC
std::string HMACSHA256(std::string& filePath, CryptoPP::SecByteBlock& key);

// Function to write HMAC to ELF
void writeToELF(std::string& filePath, std::string& hmac);

// Use to verify the data in actually written into the ELF
void readAndDisplaySection(const std::string& filePath, const std::string& sectionName);

int main() {

    std::string filePath = "elf.bin";
    std::string test_modified_file = "elf.bin_modified";
    std::string section_name = ".section lsdAlcohol";
    std::string encoded;
    CryptoPP::SecByteBlock key(16);
    generate_key(key, 16);

    // Prints key in hex format
    encoded.clear();
    CryptoPP::StringSource ss1(key, key.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
        )
    );
    std::cout << "key: " << encoded << std::endl;

    // HMAC-SHA256 on ELF (resulting HMAC is 32-bytes)
    std::string elf_hmac = HMACSHA256(filePath, key);
    std::cout << "hmac of elf: " << elf_hmac << std::endl;

    // Write the resulting HMAC to ELF
    try {
        writeToELF(filePath, elf_hmac);
    } catch (std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << '\n';
        return 1;
    }

    // Display section from modified ELF
    try {
        readAndDisplaySection(test_modified_file, section_name);
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

// Function Definitions

void generate_key(CryptoPP::SecByteBlock& key, size_t KEYSIZE) {
    CryptoPP::AutoSeededRandomPool rng;

    rng.GenerateBlock(key, key.size());
}

std::string HMACSHA256(std::string& filePath, CryptoPP::SecByteBlock& key) {
    std::ifstream elf;
    elf.open(filePath, std::ios::binary);

    if (!elf.is_open()) {
        std::cout << "Error opening file: " << filePath << std::endl;
        exit(1);
    }

    std::string fileContent((std::istreambuf_iterator<char>(elf)), std::istreambuf_iterator<char>());
    elf.close();

    std::string encoded, mac;

    try {
        CryptoPP::HMAC < CryptoPP::SHA256 > hmac (key, key.size());
        CryptoPP::StringSource ss(fileContent, true,
            new CryptoPP::HashFilter(hmac,
                new CryptoPP::StringSink(mac)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    // print out HMAC
    encoded.clear();
    CryptoPP::StringSource ss2(mac, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
        )
    );

    return encoded;
}

void writeToELF(std::string& filePath, std::string& hmac) {
    ELFIO::elfio reader;

    if (!reader.load(filePath)) {
        throw std::runtime_error("Error opening file: " + filePath);
    }

    const std::string sectionName = ".section lsdAlcohol";
    ELFIO::section* newSection = reader.sections.add(sectionName.c_str());
    newSection->set_type(ELFIO::SHT_PROGBITS);
    newSection->set_flags(ELFIO::SHF_WRITE | ELFIO::SHF_ALLOC);
    newSection->set_addr_align(0x4);
    newSection->set_data(hmac.data(), hmac.size());

    reader.set_entry(newSection->get_address());

    const std::string modifiedELF = filePath + "_modified";
    if (!reader.save(modifiedELF.c_str())) {
        throw std::runtime_error("Error saving modified file.");
    }

    std::cout << "Modified ELF saved successfully. " << std::endl; 
}

void readAndDisplaySection(const std::string& filePath, const std::string& sectionName) {
    ELFIO::elfio reader;

    if (!reader.load(filePath)) {
        throw std::runtime_error("Error reading file: " + filePath);
    }

    // Find the section by name
    const ELFIO::section* targetSection = reader.sections[sectionName];
    if (!targetSection) {
        throw std::runtime_error("Section not found: " + sectionName);
    }

    // Get the data of the section
    const ELFIO::Elf_Word dataSize = targetSection->get_size();
    const ELFIO::Elf64_Addr dataAddress = targetSection->get_address();
    const char* sectionData = reinterpret_cast<const char*>(targetSection->get_data());

    // Display the content
    std::cout << "Content of section '" << sectionName << "':" << std::endl;
    for (ELFIO::Elf_Word i = 0; i < dataSize; ++i) {
        std::cout << sectionData[i];
    }
    std::cout << std::endl;
}