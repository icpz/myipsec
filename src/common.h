#ifndef __COMMON_H__
#define __COMMON_H__

#include <fcntl.h>
#include <unistd.h>

extern "C" {
#include <linux/types.h>
#include <linux/netfilter.h>		
#include <linux/netfilter_ipv4.h>		
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
}

#define MY_TAG_SIZE 16
#define FAKE_PROTO 51

#endif

