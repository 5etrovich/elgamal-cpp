#include "elgamal.h"
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <cstdio>
#include <vector>
#include <ctime>

std::ostream &operator<<(std::ostream& o, const EGKeyPair& kp){
    o << kp.public_key << std::endl;
    o << kp.private_key << std::endl;
    o << kp.modulus << std::endl;
    o << kp.generator << std::endl;
    return o;
}

std::istream &operator>>(std::istream& i, EGKeyPair& kp){
    i >> kp.public_key >> kp.private_key >> kp.modulus >> kp.generator;
    return i;
}

ElGamal::ElGamal(int size) : key_size(size){
    KeyPair.public_key = BigNum("0");
    KeyPair.private_key = BigNum("0");
    KeyPair.modulus = BigNum("0");
    KeyPair.generator = BigNum("0");
    srand((unsigned int)time(NULL));
}

EGKeyPair ElGamal::genpkey() const{
    EGKeyPair kp;
    
    // Генерируем простое число p (модуль)
    kp.modulus = BigNum::prime(key_size);
    
    // Генерируем порождающий элемент g (1 < g < p)
    kp.generator = BigNum::prime(17);
    while(kp.generator >= kp.modulus){
        kp.generator = BigNum::prime(16);
    }
    
    // Генерируем приватный ключ x (1 < x < p-1)
    kp.private_key = BigNum::prime(key_size / 2);
    BigNum p_minus_1 = kp.modulus - BigNum("1");
    while(kp.private_key >= p_minus_1 || kp.private_key <= BigNum("1")){
        kp.private_key = BigNum::prime(key_size / 2 - 1);
    }
    
    // Вычисляем публичный ключ y = g^x mod p
    kp.public_key = kp.generator.mod_exp(kp.modulus, kp.private_key);
    
    return kp;
}

void ElGamal::setpkey(const EGKeyPair& kp){
    KeyPair = kp;
}

EGCiphertext ElGamal::encrypt(const char* msg) const {
    EGCiphertext ct;
    BigNum message = text2bn(msg);
    
    std::cout << "Сообщение в виде числа: " << message << std::endl;
    
    if(message >= KeyPair.modulus){
        std::cerr << "Ошибка: Сообщение больше или равно модулю!" << std::endl;
        ct.c1 = BigNum("0");
        ct.c2 = BigNum("0");
        return ct;
    }
    
    // Генерируем случайное число k (1 < k < p-1)
    BigNum k = BigNum::prime(key_size / 2);
    BigNum p_minus_1 = KeyPair.modulus - BigNum("1");
    while(k >= p_minus_1 || k <= BigNum("1")){
        k = BigNum::prime(key_size / 2 - 1);
    }
    
    // c1 = g^k mod p
    ct.c1 = KeyPair.generator.mod_exp(KeyPair.modulus, k);
    
    // y^k mod p
    BigNum yk = KeyPair.public_key.mod_exp(KeyPair.modulus, k);
    
    // c2 = (m * (y^k mod p)) mod p
    BigNum temp = message * yk;
    ct.c2 = temp - ((temp / KeyPair.modulus) * KeyPair.modulus);
    
    std::cout << "Зашифрованное сообщение (c1): " << ct.c1 << std::endl;
    std::cout << "Зашифрованное сообщение (c2): " << ct.c2 << std::endl;
    
    return ct;
}

const char* ElGamal::decrypt(const EGCiphertext& ciphertext) const{
    static char buf[4096];
    memset(buf, 0, sizeof(buf));
    
    // s = c1^x mod p
    BigNum s = ciphertext.c1.mod_exp(KeyPair.modulus, KeyPair.private_key);
    
    // s_inv = s^(-1) mod p (модульное обратное)
    BigNum s_inv = s.mod_inv(KeyPair.modulus);
    
    // m = (c2 * s_inv) mod p
    BigNum temp = ciphertext.c2 * s_inv;
    BigNum message = temp - ((temp / KeyPair.modulus) * KeyPair.modulus);
    
    std::cout << "Расшифрованное число: " << message << std::endl;
    
    return bn2text(message);
}

BigNum ElGamal::text2bn(const char* text) const {
    if(!text || strlen(text) == 0){
        return BigNum("0");
    }
    
    std::vector<int> bytes;
    for(size_t i = 0; i < strlen(text); ++i){
        bytes.push_back((int)(unsigned char)text[i]);
    }
    
    BigNum result("0");
    BigNum base("256");
    
    for(size_t i = 0; i < bytes.size(); ++i){
        result = result * base;
        
        char buf[16];
        sprintf(buf, "%d", bytes[i]);
        result = result + BigNum(buf);
    }
    
    return result;
}

const char* ElGamal::bn2text(const BigNum& bn) const{
    static char buf[4096];
    memset(buf, 0, sizeof(buf));
    
    BigNum num = bn;
    BigNum zero("0");
    BigNum base("256");
    
    if(num == zero){
        buf[0] = '\0';
        return buf;
    }
    
    std::vector<int> bytes;
    while(num > zero){
        BigNum rem = num - ((num / base) * base);
        
        std::ostringstream os;
        os << rem;
        
        int byte_value = 0;
        std::string rem_str = os.str();
        
        for(size_t j = 0; j < rem_str.size(); ++j){
            char c = rem_str[j];
            byte_value = byte_value * 10 + (c - '0');
        }
        
        bytes.push_back(byte_value);
        num = num / base;
    }
    
    size_t pos = 0;
    for(int i = (int)bytes.size() - 1; i >= 0; --i){
        if(pos < sizeof(buf) - 1){
            buf[pos++] = (char)bytes[i];
        }
    }
    
    buf[pos] = '\0';
    return buf;
}