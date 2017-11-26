#ifndef __FILTER_H__
#define __FILTER_H__

#include "common.h"
#include "conf.h"
#include "transer.h"
#include <unordered_map>
#include <memory>

class PacketFilter {
public:
    using transer_type = std::shared_ptr<Transer>;
    using key_type = union {
        uint64_t key = 0;
        struct {
            uint32_t ip;
            uint8_t proto;
        }d;
    };

    transer_type find(key_type key) const;
    bool add(const ConfItem &c);
    bool match(key_type key, uint8_t proto) const;

    static std::shared_ptr<PacketFilter> getInstance();

private:
    PacketFilter();

    std::unordered_map<uint64_t, transer_type> _filters;
    std::unordered_map<uint64_t, ConfItem::protocol> _protocols;
};

#endif

