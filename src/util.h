#ifndef __UTIL_H__
#define __UTIL_H__

#include "common.h"
#include "nfq.h"
#include <ev.h>

void set_nonblocking(int fd) {
    int flag = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flag | O_NONBLOCK);
}

struct queue_io {
    struct ev_io io;
    std::shared_ptr<NFQ> handle;
};

#endif

