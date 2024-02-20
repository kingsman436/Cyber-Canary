#include <iostream>
#include <filesystem>
#include <fstream>
#include <clang-c/Index.h>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;

// Define a named function with the required signature for the visitor function
CXChildVisitResult visitorFunction(CXCursor cursor, CXCursor parent, CXClientData clientData) {
    // Extract the vulnerability information from clientData
    auto data = reinterpret_cast<std::pair<std::string, std::string>*>(clientData);
    std::string affectedFunction = data->first;
    std::string vulnerabilityDescription = data->second;

    // Check if cursor represents a function call
    if (clang_getCursorKind(cursor) == CXCursor_CallExpr) {
        CXString functionName = clang_getCursorSpelling(cursor);
        std::string functionNameStr = clang_getCString(functionName);
        clang_disposeString(functionName);

        // Check if the function call matches the affected function
        if (functionNameStr == affectedFunction) {
            std::cout << "Potential vulnerability detected: " << vulnerabilityDescription << std::endl;
            // You may want to perform additional actions here, such as logging or reporting the vulnerability
        }
    }
    return CXChildVisit_Recurse;
}

void processJsonFile(const std::string& filePath, const std::string& sourceFilePath) {
    std::ifstream jsonFile(filePath);

    // Check if the file is open
    if (!jsonFile.is_open()) {
        std::cerr << "Error opening the file: " << filePath << std::endl;
        return;
    }

    // Parse the JSON data
    nlohmann::json jsonData;
    jsonFile >> jsonData;

    // Close the file
    jsonFile.close();

    // Extract relevant vulnerability information
    std::string vulnerabilityDescription = jsonData["description"];
    std::string affectedFunction = jsonData["affected_function"];

    // Initialize libclang index
    CXIndex index = clang_createIndex(0, 0);

    // Parse the source file
    CXTranslationUnit tu = clang_parseTranslationUnit(
        index, sourceFilePath.c_str(), nullptr, 0, nullptr, 0, CXTranslationUnit_None);

    if (!tu) {
        std::cerr << "Error parsing translation unit" << std::endl;
        return;
    }

    // Get the cursor for the translation unit
    CXCursor rootCursor = clang_getTranslationUnitCursor(tu);

    // Set up the client data to pass vulnerability information to the visitor function
    std::pair<std::string, std::string> clientData = std::make_pair(affectedFunction, vulnerabilityDescription);

    // Pass the address of the visitor function to clang_visitChildren
    clang_visitChildren(rootCursor, visitorFunction, reinterpret_cast<void*>(&clientData));

    // Clean up
    clang_disposeTranslationUnit(tu);
    clang_disposeIndex(index);
}

int main() {
    // Specify the directory containing the JSON files
    std::string directoryPath = "C:\\Users\\Justin L\\source\\repos\\cvelistV5\\cves";

    // Specify the directory containing the source files
    std::string sourceDirectoryPath = "C:\\path\\to\\source\\files";

    // Iterate over files in the directory and its subdirectories
    for (const auto& entry : fs::recursive_directory_iterator(directoryPath)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            // Process each JSON file
            processJsonFile(entry.path().string(), sourceDirectoryPath);
        }
    }

    return 0;
}
