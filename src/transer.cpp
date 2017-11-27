
#include "transer.h"
#include <glog/logging.h>
#include <time.h>
#include <random>
#include <algorithm>
#include <functional>

Crypto::Crypto(std::vector<uint8_t> &&key, const std::string &method)
    : _valid(false), _pkey(key) {
    LOG(INFO) << "initializing cipher " << method;
    mbedtls_cipher_init(&_cipher);

    const mbedtls_cipher_info_t *cinfo = mbedtls_cipher_info_from_string(method.c_str());
    CHECK(cinfo != nullptr) << "Cipher not found: " << method;

    mbedtls_cipher_setup(&_cipher, cinfo);

    _nonce.assign(mbedtls_cipher_get_iv_size(&_cipher), 0);
    _skey.resize(mbedtls_cipher_get_key_bitlen(&_cipher) / 8);
    _salt.resize(_skey.size());
    _valid = true;
}

Crypto::~Crypto() {
    _valid = false;
    mbedtls_cipher_free(&_cipher);
}

static const uint8_t kAdditional[] = "myipsec v1.0 made by cpz & hsy";
static const size_t kTagSize = MY_TAG_SIZE;

ssize_t Crypto::transform(uint8_t action, uint8_t *data, size_t len, size_t buflen, void *extra) {
    VLOG(1) << (action ? "encrypting..." : "decrypting...");
    ssize_t result;
    uint8_t proto = *reinterpret_cast<uint8_t *>(extra);

    mbedtls_cipher_reset(&_cipher);
    if (action) {
        result = __encrypt(data, len, buflen, proto);
    } else {
        result = __decrypt(data, len, buflen, proto);
    }

    return result;
}

ssize_t Crypto::__encrypt(uint8_t *data, size_t len, size_t buflen, uint8_t p) {
    ssize_t result;

    if (buflen < len + padlen()) {
        LOG(ERROR) << "too small buf! "
                   << buflen << " < "
                   << len << " + " << padlen();
        return -1;
    }

    __generate_salt();
    _salt.back() = p;
    __get_session_key();

    mbedtls_cipher_setkey(&_cipher, _skey.data(), 8 * _skey.size(), MBEDTLS_ENCRYPT);
    int ret = mbedtls_cipher_auth_encrypt(&_cipher,
                        _nonce.data(), _nonce.size(),
                        kAdditional, sizeof kAdditional,
                        data, len, data, &len,
                        data + len, kTagSize);
    if (ret) {
        LOG(ERROR) << "encrypt error, code: " << ret;
        return -1;
    }
    result = len + kTagSize;
    memcpy(data + result, _salt.data(), _salt.size());
    result += _salt.size();

    return result;
}

ssize_t Crypto::__decrypt(uint8_t *data, size_t len, size_t buflen, uint8_t p) {
    ssize_t result;
    size_t cLen = len - padlen();

    if (len < padlen()) {
        LOG(ERROR) << "too small buf! " << len << " - " << padlen();
        return -1;
    }

    memcpy(_salt.data(), data + cLen + kTagSize, _salt.size());
    __get_session_key();

    mbedtls_cipher_setkey(&_cipher, _skey.data(), 8 * _skey.size(), MBEDTLS_DECRYPT);
    int ret = mbedtls_cipher_auth_decrypt(&_cipher,
                        _nonce.data(), _nonce.size(),
                        kAdditional, sizeof kAdditional,
                        data, cLen, data, &len,
                        data + cLen, kTagSize);
    if (ret) {
        LOG(ERROR) << "decrypt error, code: " << ret;
        return -1;
    }
    result = len;

    return result;
}

void Crypto::__generate_salt() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> d(0, 255);
    std::generate(std::begin(_salt), std::end(_salt),
                  std::bind(d, gen));
}

static int __hkdf(
            const mbedtls_md_info_t *md,
            const std::vector<uint8_t> &salt,
            const std::vector<uint8_t> &ikm,
            const std::vector<uint8_t> &info,
            std::vector<uint8_t> &okm);

void Crypto::__get_session_key() {
    static const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    static const std::vector<uint8_t> info = { 5, 1, 3, 1, 1, 0, 9, 0, 3, 5 };
    CHECK(__hkdf(md, _salt, _pkey, info, _skey) == 0)
        << "hkdf error!";
}

size_t Crypto::padlen() const {
    return kTagSize + _skey.size();
}

static int __hkdf_extract(
            const mbedtls_md_info_t *md,
            const std::vector<uint8_t> &salt,
            const std::vector<uint8_t> &ikm,
            std::vector<uint8_t> &prk) {
    size_t hashLen = mbedtls_md_get_size(md);
    prk.resize(hashLen);
    return mbedtls_md_hmac(md, salt.data(), salt.size(), ikm.data(), ikm.size(), prk.data());
}

static int __hkdf_expand(
            const mbedtls_md_info_t *md,
            const std::vector<uint8_t> &prk,
            const std::vector<uint8_t> &info,
            std::vector<uint8_t> &okm) {
    size_t L = okm.size();
    int hashLen = mbedtls_md_get_size(md);
    int N;
    int Tlen = 0, curr = 0, ret;
    mbedtls_md_context_t ctx;
    uint8_t T[MBEDTLS_MD_MAX_SIZE];

    N = L / hashLen;
    if (L % hashLen) {
        ++N;
    }

    mbedtls_md_init(&ctx);
    CHECK((ret = mbedtls_md_setup(&ctx, md, 1)) == 0) << "error setup md: " << ret;

    for (int i = 1; i <= N; ++i) {
        uint8_t c = i;
        ret = mbedtls_md_hmac_starts(&ctx, prk.data(), prk.size())
           || mbedtls_md_hmac_update(&ctx, T, Tlen)
           || mbedtls_md_hmac_update(&ctx, info.data(), info.size())
           || mbedtls_md_hmac_update(&ctx, &c, 1)
           || mbedtls_md_hmac_finish(&ctx, T);
        
        if (ret) {
            mbedtls_md_free(&ctx);
            return ret;
        }
        memcpy(okm.data() + curr, T, (i != N) ? hashLen : (L - curr));
        curr += hashLen;
        Tlen = hashLen;
    }
    mbedtls_md_free(&ctx);
    return 0;
}

static int __hkdf(
            const mbedtls_md_info_t *md,
            const std::vector<uint8_t> &salt,
            const std::vector<uint8_t> &ikm,
            const std::vector<uint8_t> &info,
            std::vector<uint8_t> &okm) {
    static std::vector<uint8_t> prk(MBEDTLS_MD_MAX_SIZE);
    return __hkdf_extract(md, salt, ikm, prk)
        || __hkdf_expand(md, prk, info, okm);
}

