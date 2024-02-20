#ifndef TOKEN_GENERATOR_H
#define TOKEN_GENERATOR_H
#include <string>
#include <ctime>

class TOTP {
public:
    TOTP(){};
    std::string generateOTPToken(const std::string token, std::time_t t);
private:
    std::string decodeBase32(const std::string token);
};

#endif // TOKEN_GENERATOR_H
