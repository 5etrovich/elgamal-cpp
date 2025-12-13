#ifndef BIGNUM_H
#define BIGNUM_H

#include <iostream>
#include "openssl/bn.h"

class BigNum {
private:
    BIGNUM *bn;

public:
    BigNum();
    BigNum(const char *str);
    BigNum(const BigNum& other);
    ~BigNum();

    BigNum& operator=(const BigNum& other);

    bool operator<(const BigNum &other) const;
    bool operator>(const BigNum &other) const;
    bool operator<=(const BigNum &other) const;
    bool operator>=(const BigNum &other) const;
    bool operator==(const BigNum &other) const;
    bool operator!=(const BigNum &other) const;
    
    bool coprime(const BigNum& other) const;

    BigNum operator+(const BigNum &other) const;
    BigNum operator-(const BigNum &other) const;
    BigNum operator*(const BigNum &other) const;
    BigNum operator/(const BigNum &other) const;

    BigNum mod_inv(const BigNum& mod) const;
    BigNum mod_exp(const BigNum& mod, const BigNum& exp) const;

    static BigNum prime(int bits);

    friend std::ostream &operator<<(std::ostream &o, const BigNum &bn);
    friend std::istream &operator>>(std::istream &i, BigNum &bn);
};

#endif
