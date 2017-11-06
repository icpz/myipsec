
#include "nfq.h"
#include <glog/logging.h>

NFQ::NFQ() {
    _handle = nfq_open();
    PCHECK(_handle != nullptr) << "nfq_open error!";
}

NFQ::~NFQ() {
    for (auto &kv : _queue) {
        CHECK(kv.second.use_count() == 1) << "unexcepted release!";
        kv.second.reset();
    }
    nfq_close(native_handle());
}

NFQ::QueuePtr NFQ::create_queue(Queue::Callback cb) {
    uint16_t num = _queue.size();
    _queue[num] = std::make_shared<Queue>(shared_from_this(), num, cb);
    return _queue[num];
}

void NFQ::handle_packet(uint8_t *buf, ssize_t len) {
    nfq_handle_packet(native_handle(), (char *)buf, len);
}

