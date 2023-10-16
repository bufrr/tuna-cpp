//
// Created by buffer on 2022/1/8.
//

#include "encrypt.h"

void XSalsa20poly1305Encrypter::encrypt(char *dst, size_t dlen, char *src, size_t slen, unsigned char *nonce) {
    crypto_box_easy_afternm(reinterpret_cast<unsigned char *>(dst), reinterpret_cast<const unsigned char *>(src), slen,
                            nonce, shared_key_);
}

void XSalsa20poly1305Encrypter::decrypt(char *dst, size_t dlen, char *src, size_t slen, unsigned char *nonce) {
    crypto_box_open_easy_afternm(reinterpret_cast<unsigned char *>(dst), reinterpret_cast<const unsigned char *>(src),
                                 slen, nonce, shared_key_);
}

XSalsa20poly1305Encrypter::XSalsa20poly1305Encrypter(unsigned char *shared_key, size_t slen) {
    memmove(shared_key_, shared_key, slen);
    initNonce(nonce, crypto_box_NONCEBYTES, false);
    maxNonce(max_nonce, crypto_box_NONCEBYTES, false);
}

XSalsa20poly1305Encrypter::~XSalsa20poly1305Encrypter() {
    memset(shared_key_, 0, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
}

void increaseNonce(unsigned char *nonce, size_t len) {
    for (int i = len - 1; i >= 0; i--) {
        nonce[i]++;
        if (nonce[i] > 0) {
            break;
        }
    }
}

void initNonce(unsigned char *initNonce, int nonceSize, bool initiator) {
    sodium_memzero(initNonce, nonceSize);
    if (!initiator) {
        initNonce[0] |= 128;
    }
}

void maxNonce(unsigned char *maxNonce, int nonceSize, bool initiator) {
    for (int i=0; i<nonceSize; i++) {
        maxNonce[i] = 255;
    }
    if(initiator) {
        maxNonce[0] &= 127;
    }
}

