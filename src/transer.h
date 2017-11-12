#ifndef __TRANSER_H__
#define __TRANSER_H__

#include "common.h"
#include <vector>
#include <string>

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>

class Transer {
public:
    Transer() { }
    virtual ~Transer() { }

    virtual bool accept() const = 0;
    virtual ssize_t transform(uint8_t action, uint8_t *data, size_t len, size_t buflen, void *extra) = 0;
    virtual bool valid() const = 0;

private:
};

class Droper : public Transer {
public:
    Droper() { }
    ~Droper() { }
    
    bool accept() const { return false; }
    ssize_t transform(uint8_t action, uint8_t *data, size_t len, size_t buflen, void *extra) { return len; }
    bool valid() const { return true; }

private:
};

class Crypto : public Transer {
public:
    Crypto(std::vector<uint8_t> &&key, const std::string &method);
    ~Crypto();

    bool accept() const { return true; }
    ssize_t transform(uint8_t action, uint8_t *data, size_t len, size_t buflen, void *extra);
    bool valid() const { return _valid; }

private:
    ssize_t __encrypt(uint8_t *data, size_t len, size_t buflen, uintptr_t id);
    ssize_t __decrypt(uint8_t *data, size_t len, size_t buflen, uintptr_t id);
    void __get_session_key(const void *tm, size_t len);
    void __get_session_iv(const void *tm, size_t len, uintptr_t id);

    bool _valid;
    mbedtls_cipher_context_t _cipher;
    uint8_t _iv[16];
    uint8_t _skey[16];
    std::vector<uint8_t> _pkey;

    mbedtls_md_context_t _md;
};

#endif

