//
// Created by buffer on 2022/1/8.
//

#ifndef TUNA_CPP_ENCRYPT_H
#define TUNA_CPP_ENCRYPT_H

#include <cstdlib>
#include <sodium.h>
#include <cstring>


class BaseDecEncrypter {
public:
    virtual ~BaseDecEncrypter() = default;

    virtual void encrypt(char *dst, size_t dlen, char *src,
                         size_t slen, unsigned char *nonce) = 0;

    virtual void decrypt(char *dst, size_t dlen, char *src,
                         size_t slen, unsigned char *nonce) = 0;
};

class XSalsa20poly1305Encrypter : public BaseDecEncrypter {
public:
    XSalsa20poly1305Encrypter(unsigned char *shared_key, size_t slen);

    ~XSalsa20poly1305Encrypter() override;

    void encrypt(char *dst, size_t dlen, char *src,
                 size_t slen, unsigned char *nonce);

    void decrypt(char *dst, size_t dlen, char *src,
                 size_t slen, unsigned char *nonce);

public:
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char max_nonce[crypto_box_NONCEBYTES];

private:
    unsigned char shared_key_[crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES];
};

void increaseNonce(unsigned char *nonce, size_t len);

void initNonce(unsigned char *initNonce, int nonceSize, bool initiator);

void maxNonce(unsigned char *maxNonce, int nonceSize, bool initiator);


#endif //TUNA_CPP_ENCRYPT_H
