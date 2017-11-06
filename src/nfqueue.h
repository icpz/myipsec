#ifndef __NFQUEUE_H__
#define __NFQUEUE_H__

#include <functional>
#include <thread>
#include <mutex>
#include <memory>

#include "common.h"

class NFQ;
//int nfqueue_cb_wrapper(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

class NFQ_queue : public std::enable_shared_from_this<NFQ_queue> {
public:
    using Callback = std::function<int(std::shared_ptr<NFQ_queue>,
                                       struct nfgenmsg *,
                                       struct nfq_data *)>;

    NFQ_queue(std::shared_ptr<NFQ> nfq, uint16_t num, Callback cb);
    ~NFQ_queue();

    int set_mode(uint8_t mode, uint32_t size = 0xffff);
    int set_verdict(uint32_t id, uint32_t verdict, uint32_t len, const uint8_t *buf);
    struct nfq_q_handle *native_handle() {
        return _handle;
    }

private:
    nfq_q_handle *_handle;
    std::weak_ptr<NFQ> _nfq;
    uint16_t _num;
    mutable std::mutex _verdict_lock;
    Callback _cb;
    friend int nfqueue_cb_wrapper(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
};

#endif

