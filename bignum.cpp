#include "bignum.h"
#include <cstring>
#include <cstdlib>

BigNum::BigNum() {
    bn = BN_new();
    if (!bn) {
        std::cerr << "Ошибка выделения памяти для BIGNUM" << std::endl;
        exit(1);
    }
    BN_zero(bn);
}

BigNum::BigNum(const char *str) {
    bn = BN_new();
    if (!bn) {
        std::cerr << "Ошибка выделения памяти для BIGNUM" << std::endl;
        exit(1);
    }
    if (!BN_dec2bn(&bn, str)) {
        std::cerr << "Ошибка преобразования строки в BIGNUM: " << str << std::endl;
        BN_zero(bn);
    }
}

BigNum::BigNum(const BigNum& other) {
    bn = BN_new();
    if (!bn) {
        std::cerr << "Ошибка выделения памяти для BIGNUM" << std::endl;
        exit(1);
    }
    if (!BN_copy(bn, other.bn)) {
        std::cerr << "Ошибка копирования BIGNUM" << std::endl;
        BN_zero(bn);
    }
}

BigNum::~BigNum() {
    if (bn) {
        BN_free(bn);
    }
}

BigNum& BigNum::operator=(const BigNum& other) {
    if (this != &other) {
        if (!BN_copy(bn, other.bn)) {
            std::cerr << "Ошибка присваивания BIGNUM" << std::endl;
            BN_zero(bn);
        }
    }
    return *this;
}

bool BigNum::operator<(const BigNum& other) const {
    return BN_cmp(bn, other.bn) < 0;
}

bool BigNum::operator>(const BigNum& other) const {
    return BN_cmp(bn, other.bn) > 0;
}

bool BigNum::operator<=(const BigNum& other) const {
    return BN_cmp(bn, other.bn) <= 0;
}

bool BigNum::operator>=(const BigNum& other) const {
    return BN_cmp(bn, other.bn) >= 0;
}

bool BigNum::operator==(const BigNum& other) const {
    return BN_cmp(bn, other.bn) == 0;
}

bool BigNum::operator!=(const BigNum& other) const {
    return BN_cmp(bn, other.bn) != 0;
}

bool BigNum::coprime(const BigNum& other) const {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return false;
    
    int res = BN_are_coprime(bn, other.bn, ctx);
    BN_CTX_free(ctx);
    return res == 1;
}

BigNum BigNum::operator+(const BigNum& other) const {
    BigNum res;
    BN_CTX *ctx = BN_CTX_new();
    if (ctx) {
        BN_add(res.bn, bn, other.bn);
        BN_CTX_free(ctx);
    }
    return res;
}

BigNum BigNum::operator-(const BigNum& other) const {
    BigNum res;
    BN_CTX *ctx = BN_CTX_new();
    if (ctx) {
        BN_sub(res.bn, bn, other.bn);
        BN_CTX_free(ctx);
    }
    return res;
}

BigNum BigNum::operator*(const BigNum& other) const {
    BigNum res;
    BN_CTX *ctx = BN_CTX_new();
    if (ctx) {
        BN_mul(res.bn, bn, other.bn, ctx);
        BN_CTX_free(ctx);
    }
    return res;
}

BigNum BigNum::operator/(const BigNum& other) const {
    BigNum res;
    BN_CTX *ctx = BN_CTX_new();
    if (ctx) {
        BIGNUM *rem = BN_new();
        BN_div(res.bn, rem, bn, other.bn, ctx);
        BN_free(rem);
        BN_CTX_free(ctx);
    }
    return res;
}

BigNum BigNum::mod_inv(const BigNum& mod) const {
    BigNum res;
    BN_CTX *ctx = BN_CTX_new();
    if (ctx) {
        BIGNUM *result = BN_mod_inverse(res.bn, bn, mod.bn, ctx);
        if (!result) {
            BN_zero(res.bn);
        }
        BN_CTX_free(ctx);
    }
    return res;
}

BigNum BigNum::mod_exp(const BigNum& mod, const BigNum& exp) const {
    BigNum res;
    BN_CTX *ctx = BN_CTX_new();
    if (ctx) {
        int st = BN_mod_exp(res.bn, bn, exp.bn, mod.bn, ctx);
        if (st == 0) {
            BN_zero(res.bn);
        }
        BN_CTX_free(ctx);
    }
    return res;
}

std::ostream &operator<<(std::ostream& o, const BigNum& bn) {
    char *str = BN_bn2dec(bn.bn);
    if (str) {
        o << str;
        OPENSSL_free(str);
    } else {
        o << "0";
    }
    return o;
}

std::istream &operator>>(std::istream &i, BigNum& bn) {
    std::string buf;
    i >> buf;
    if (!BN_dec2bn(&bn.bn, buf.c_str())) {
        BN_zero(bn.bn);
    }
    return i;
}

BigNum BigNum::prime(int bits) {
    BigNum res;
    BN_GENCB *cb = NULL;
    if (!BN_generate_prime_ex(res.bn, bits, 1, NULL, NULL, cb)) {
        std::cerr << "Ошибка генерации простого числа" << std::endl;
        BN_zero(res.bn);
    }
    return res;
}
