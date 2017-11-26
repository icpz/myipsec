
#include "filter.h"
#include <glog/logging.h>
#include <mutex>

PacketFilter::PacketFilter() {
}

std::shared_ptr<PacketFilter> PacketFilter::getInstance() {
    static std::shared_ptr<PacketFilter> instance;
    static std::once_flag once;

    std::call_once(once, []() {
        instance.reset(new PacketFilter());
    });
    
    return instance;
}

PacketFilter::transer_type PacketFilter::find(key_type key) const {
    auto itr = _filters.find(key.key);

    if (itr != std::end(_filters)) {
        return itr->second;
    }

    return nullptr;
}

bool PacketFilter::add(const ConfItem &c) {
    key_type key;
    bool result = true;
    key.d.ip = c.ip();
    key.d.proto = 0;

    Transer *p = nullptr;
    switch(c.act()) {
    case ConfItem::action::DROP:
        p = new Droper();
        LOG(INFO) << "add a Droper filter";
        break;

    case ConfItem::action::CRYPT:
        p = new Crypto(c.key(), c.method());
        LOG(INFO) << "add a Crypto filter";
        break;

    default:
        result = false;
        LOG(ERROR) << "add filter error, invalid action";
        break;
    }
    _filters[key.key].reset(p);
    _protocols[key.key] = c.proto();
    VLOG(2) << "adding key: " << std::hex << key.key;

    return result;
}

bool PacketFilter::match(key_type key, uint8_t proto) const {
    auto itr = _protocols.find(key.key);
    if (itr == _protocols.end()) return false;
    using CP = ConfItem::protocol;
    bool result = false;
    switch(itr->second) {
    case CP::ALL:
        result = true;
        break;
    case CP::TCP:
        result = (proto == 6);
        break;
    case CP::UDP:
        result = (proto == 17);
        break;
    default:
        break;
    }
    return result;
}

