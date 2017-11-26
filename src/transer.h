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
    virtual size_t padlen() const = 0;

private:
};

class Droper : public Transer {
public:
    Droper() { }
    ~Droper() { }
    
    bool accept() const { return false; }
    ssize_t transform(uint8_t action, uint8_t *data, size_t len, size_t buflen, void *extra) { return len; }
    bool valid() const { return true; }
    size_t padlen() const { return 0; }

private:
};

class Crypto : public Transer {
public:
    Crypto(std::vector<uint8_t> &&key, const std::string &method);
    ~Crypto();

    bool accept() const { return true; }
    ssize_t transform(uint8_t action, uint8_t *data, size_t len, size_t buflen, void *extra);
    bool valid() const { return _valid; }
    size_t padlen() const;

private:
    ssize_t __encrypt(uint8_t *data, size_t len, size_t buflen, uint8_t p);
    ssize_t __decrypt(uint8_t *data, size_t len, size_t buflen, uint8_t p);
    void __get_session_key();
    void __generate_salt();

    bool _valid;
    mbedtls_cipher_context_t _cipher;
    std::vector<uint8_t> _nonce;
    std::vector<uint8_t> _skey;  // session key
    const std::vector<uint8_t> _pkey;  // pre-shared key

    std::vector<uint8_t> _salt;
};

#endif

