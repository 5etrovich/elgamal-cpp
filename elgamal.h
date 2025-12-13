#ifndef ELGAMAL_H
#define ELGAMAL_H

#include "bignum.h"
#include <iostream>

struct EGCiphertext {
    BigNum c1;
    BigNum c2;
};

struct EGKeyPair {
    BigNum public_key;
    BigNum private_key;
    BigNum modulus;
    BigNum generator;
};

class ElGamal {
private:
    int key_size;
    EGKeyPair KeyPair;

public:
    ElGamal(int size = 512);
    
    EGKeyPair genpkey() const;
    void setpkey(const EGKeyPair& kp);
    
    EGCiphertext encrypt(const char* msg) const;
    const char* decrypt(const EGCiphertext& ciphertext) const;
    
    BigNum text2bn(const char* text) const;
    const char* bn2text(const BigNum& bn) const;
};

std::ostream &operator<<(std::ostream& o, const EGKeyPair& kp);
std::istream &operator>>(std::istream& i, EGKeyPair& kp);

#endif
