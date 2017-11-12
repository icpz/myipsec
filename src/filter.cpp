
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
    key.d.proto = static_cast<uint8_t>(c.proto());

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
    if (key.d.proto == static_cast<uint8_t>(ConfItem::protocol::ALL)) {
        key_type tmpKey;
        tmpKey.key = key.key;
        for (uint8_t p = 0; p < static_cast<uint8_t>(c.proto()); ++p) {
            tmpKey.d.proto = p;
            _filters[tmpKey.key] = _filters[key.key];
        }
    }

    return result;
}

