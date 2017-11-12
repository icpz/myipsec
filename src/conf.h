#ifndef __CONF_H__
#define __CONF_H__

#include <vector>
#include <string>
#include <stdint.h>

class ConfItem {
public:
    enum class protocol : uint8_t {
        TCP,
        UDP,
        ALL
    };

    enum class action : uint8_t {
        CRYPT,
        DROP
    };

public:
    ConfItem();
    ~ConfItem();

    uint32_t ip() const { return _ip; }
    protocol proto() const { return _proto; }
    action act() const { return _action; }
    std::vector<uint8_t> key() const { return _key; }
    std::string method() const { return _method; }

private:
    uint32_t _ip;
    protocol _proto;
    action _action;
    std::vector<uint8_t> _key;
    std::string _method;

friend bool parseConfigFile(const std::string &filename, std::vector<ConfItem> &items);
};

bool parseConfigFile(const std::string &filename, std::vector<ConfItem> &items);

#endif

