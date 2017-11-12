
#include "transer.h"
#include <glog/logging.h>

Crypto::Crypto(std::vector<uint8_t> &&key, const std::string &method)
    : _valid(false), _pkey(key) {
    LOG(INFO) << "initializing cipher " << method;
    mbedtls_cipher_init(&_cipher);
    mbedtls_md_init(&_md);

    const mbedtls_cipher_info_t *cinfo = mbedtls_cipher_info_from_string(method.c_str());
    CHECK(cinfo != nullptr) << "Cipher not found: " << method;

    mbedtls_cipher_setup(&_cipher, cinfo);
    mbedtls_md_setup(&_md, mbedtls_md_info_from_type(MBEDTLS_MD_MD5), 0);
    _valid = true;
}

ssize_t Crypto::Transer::transform(uint8_t action, uint8_t *data, size_t len, size_t buflen, void *extra) {
    LOG(INFO) << (action ? "encrypting..." : "decrypting...");
    return len;
}

