#include <iostream>
#include <cstring>
#include "elgamal.h"

void clear(){
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

int main(){
    clear();
    std::cout << "Шифрование ElGamal\n\n" << std::endl;
    
    ElGamal eg(512);
    std::cout << "Создан объект ElGamal" << std::endl;
    
    EGKeyPair kp = eg.genpkey();
    eg.setpkey(kp);
    std::cout << "Ключевая пара сгенерирована!\n" 
              << "y (публичный ключ): " << kp.public_key << '\n'
              << "x (приватный ключ): " << kp.private_key << '\n'
              << "p (модуль): " << kp.modulus << '\n'
              << "g (генератор): " << kp.generator << std::endl;
    
    std::cout << "\nВведите сообщение для шифрования: ";
    char text[1024];
    std::cin.getline(text, sizeof(text));
    
    if(strlen(text) == 0){
        strcpy(text, "Это тестовое сообщение");
    }
    
    EGCiphertext ciphertext = eg.encrypt(text);
    std::cout << "\nИсходное сообщение: " << text << std::endl;
    
    const char* decrypted_msg = eg.decrypt(ciphertext);
    
    if(strcmp(text, decrypted_msg) == 0){
        std::cout << "\nСообщение расшифровано корректно!" << std::endl;
        std::cout << "Расшифрованное сообщение: " << decrypted_msg << std::endl;
    } else {
        std::cout << "\nОшибка! Расшифрованное сообщение: " << decrypted_msg << std::endl;
        std::cout << "Не совпадает с исходным: " << text << std::endl;
    }
    
    return 0;
}
