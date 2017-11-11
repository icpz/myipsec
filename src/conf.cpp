
#include "conf.h"
#include <mbedtls/base64.h>
#include <fstream>
#include <glog/logging.h>
#include <sstream>
#include <iterator>
#include <algorithm>
#include <cctype>
#include <arpa/inet.h>

ConfItem::ConfItem() {
}

ConfItem::~ConfItem() {
}

static void __split(const std::string &str, std::vector<std::string> &elems) {
    std::istringstream iss(str);
    elems.clear();
    std::copy(std::istream_iterator<std::string>(iss),
              std::istream_iterator<std::string>{},
              std::back_inserter(elems));
}

static bool __fill_proto(const std::string &str, ConfItem::protocol &dst) {
    static std::string dict[] = { "all", "tcp", "udp" };
    auto itr = std::find(std::begin(dict), std::end(dict), str);
    if (itr == std::end(dict)) return false;
    dst = static_cast<ConfItem::protocol>(itr - std::begin(dict));
    return true;
}

static bool __fill_act(const std::string &str, ConfItem::action &dst) {
    static std::string dict[] = { "crypt", "drop" };
    auto itr = std::find(std::begin(dict), std::end(dict), str);
    if (itr == std::end(dict)) return false;
    dst = static_cast<ConfItem::action>(itr - std::begin(dict));
    return true;
}

static bool __fill_format(const std::string &str, uint8_t &dst) {
    static std::string dict[] = { "plain", "base64" };
    auto itr = std::find(std::begin(dict), std::end(dict), str);
    if (itr == std::end(dict)) return false;
    dst = itr - std::begin(dict);
    return true;
}

bool parseConfigFile(const std::string &filename, std::vector<ConfItem> &items) {
    std::ifstream ifs(filename);
    if (!ifs) {
        LOG(ERROR) << "error open file " << filename;
        return false;
    }
    std::string line;
    items.clear();
    std::vector<std::string> sps;
    while (std::getline(ifs, line)) {
        auto pos = line.find('#');
        if (pos != std::string::npos) {
            line.erase(pos);
        }
        VLOG(2) << "parsing " << line;
        __split(line, sps);
        if (sps.size() < 3 || (sps[2] == "crypt" && sps.size() < 6)) {
            LOG(WARNING) << "skip bad line: " << line;
            continue;
        }

        items.emplace_back();
        auto &item = items.back();
        CHECK(inet_pton(AF_INET, sps[0].c_str(), &item._ip) == 1)
            << "invalid ip address! " << sps[0];
        CHECK(__fill_proto(sps[1], item._proto))
            << "invalid protocol " << sps[1];
        CHECK(__fill_act(sps[2], item._action))
            << "invalid action " << sps[2];

        if (item.act() == ConfItem::action::CRYPT) {
            uint8_t format;
            CHECK(__fill_format(sps[4], format))
                << "invalid key format " << sps[4];
            if (format == 0) {
                std::copy(std::begin(sps[3]), std::end(sps[3]),
                        back_inserter(item._key));
            } else {
                item._key.resize(sps[3].size() / 4 * 3, '\0');
                size_t osize;
                CHECK(mbedtls_base64_decode(item._key.data(), item._key.size(), &osize,
                    reinterpret_cast<const uint8_t *>(sps[3].c_str()), sps[3].size()) == 0)
                    << "base64 decode error! " << sps[3];
                item._key.resize(osize);
            }
            std::transform(std::begin(sps[5]),
                           std::end(sps[5]),
                           std::back_inserter(item._method),
                           [](uint8_t c) {
                return std::toupper(c);
            });
        }
    }
    return true;
}

