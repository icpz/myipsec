#include "nfq.h"
#include <glog/logging.h>

int nfqueue_cb_wrapper(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    NFQ_queue *handle = reinterpret_cast<NFQ_queue *>(data);
    CHECK(qh == handle->native_handle()) << "unexcepted call.";
    return handle->_cb(handle->shared_from_this(), nfmsg, nfa);
}

NFQ_queue::NFQ_queue(std::shared_ptr<NFQ> nfq, uint16_t num, Callback cb)
    :_nfq(nfq), _num(num), _cb(cb) {
    _handle = nfq_create_queue(nfq->native_handle(), num, &nfqueue_cb_wrapper, this);
    PCHECK(_handle != nullptr) << "create queue failed!";
}

NFQ_queue::~NFQ_queue() {
    nfq_destroy_queue(native_handle());
}

int NFQ_queue::set_mode(uint8_t mode, uint32_t size) {
    return nfq_set_mode(native_handle(), mode, size);
}

int NFQ_queue::set_verdict(uint32_t id, uint32_t verdict, uint32_t len, const uint8_t *buf) {
    return nfq_set_verdict(native_handle(), id, verdict, len, buf);
}

