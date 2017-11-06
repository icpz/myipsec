#ifndef __NFQ_H__
#define __NFQ_H__

#include "common.h"
#include "nfqueue.h"
#include <unordered_map>

class NFQ : public std::enable_shared_from_this<NFQ> {
public:
    using Queue = NFQ_queue;
    using QueuePtr = std::shared_ptr<Queue>;
    NFQ();
    ~NFQ();

    QueuePtr create_queue(Queue::Callback cb);
    void handle_packet(uint8_t *buf, ssize_t len);
    int get_fd() {
        return nfq_fd(native_handle());
    }
    struct nfq_handle *native_handle() {
        return _handle;
    }

private:
    struct nfq_handle *_handle;
    std::unordered_map<int, QueuePtr> _queue;
};

#endif

