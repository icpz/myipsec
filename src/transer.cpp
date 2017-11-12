
#include "transer.h"
#include <glog/logging.h>
#include <time.h>

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

Crypto::~Crypto() {
}

static const uint8_t kAdditional[] = "myipsec v1.0 made by cpz & hsy";
static const size_t tagSize = MY_TAG_SIZE;

ssize_t Crypto::transform(uint8_t action, uint8_t *data, size_t len, size_t buflen, void *extra) {
    LOG(INFO) << (action ? "encrypting..." : "decrypting...");
    uintptr_t ipId = reinterpret_cast<uintptr_t>(extra);
    ssize_t result;

    if (action) {
        result = __encrypt(data, len, buflen, ipId);
    } else {
        result = __decrypt(data, len, buflen, ipId);
    }

    return result;
}

ssize_t Crypto::__encrypt(uint8_t *data, size_t len, size_t buflen, uintptr_t id) {
    struct timespec tm;
    ssize_t result;

    if (buflen < len + tagSize + sizeof tm) {
        LOG(ERROR) << "too small buf!";
        return -1;
    }

    clock_gettime(CLOCK_REALTIME, &tm);

    __get_session_key(&tm, sizeof tm);
    __get_session_iv(&tm, sizeof tm, id);

    mbedtls_cipher_setkey(&_cipher, _skey, 8 * (sizeof _skey), MBEDTLS_ENCRYPT);
    int ret = mbedtls_cipher_auth_encrypt(&_cipher, _iv, sizeof _iv, kAdditional, sizeof kAdditional, data, len, data, &len, data + len, tagSize);
    if (ret) {
        LOG(ERROR) << "encrypt error, code: " << ret;
        return -1;
    }
    result = len + tagSize;
    memcpy(data + result, &tm, sizeof tm);
    result += sizeof tm;

    return result;
}

ssize_t Crypto::__decrypt(uint8_t *data, size_t len, size_t buflen, uintptr_t id) {
    struct timespec tm;
    ssize_t result;
    size_t cLen = len - tagSize - sizeof tm;

    if (len < tagSize + sizeof tm) {
        LOG(ERROR) << "too small buf!";
        return -1;
    }

    memcpy(&tm, data + len - sizeof tm, sizeof tm);

    __get_session_key(&tm, sizeof tm);
    __get_session_iv(&tm, sizeof tm, id);

    mbedtls_cipher_setkey(&_cipher, _skey, 8 * (sizeof _skey), MBEDTLS_DECRYPT);
    int ret = mbedtls_cipher_auth_decrypt(&_cipher, _iv, sizeof _iv, kAdditional, sizeof kAdditional, data, cLen, data, &len, data + cLen, tagSize);
    if (ret) {
        LOG(ERROR) << "decrypt error, code: " << ret;
        return -1;
    }
    result = len;

    return result;
}

void Crypto::__get_session_key(const void *tm, size_t len) {
    mbedtls_md_starts(&_md);
    mbedtls_md_update(&_md, _pkey.data(), _pkey.size());
    mbedtls_md_update(&_md, reinterpret_cast<const uint8_t *>(tm), len);
    mbedtls_md_finish(&_md, _skey);
}

void Crypto::__get_session_iv(const void *tm, size_t len, uintptr_t id) {
    mbedtls_md_starts(&_md);
    mbedtls_md_update(&_md, reinterpret_cast<uint8_t *>(&id), sizeof id);
    mbedtls_md_update(&_md, reinterpret_cast<const uint8_t *>(tm), len);
    mbedtls_md_finish(&_md, _iv);
}

