#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <netinet/ip.h>

#include <glog/logging.h>
#include <ev.h>
#include "util.h"
#include "nfq.h"
#include "conf.h"
#include "filter.h"

void mainLoop();
void initFilter(const std::string &file);

int main(int argc, char **argv) {
    google::InitGoogleLogging(argv[0]);
    std::string configFile;
    int c;

    while ((c = getopt(argc, argv, "c:")) != -1) {
        switch(c) {
            case 'c':
                configFile = optarg;
                break;

            case '?':
                LOG(WARNING) << "unknown option: " << (char)optopt;
                break;

            default:
                break;
        }
    }
    if (configFile.empty()) {
        LOG(ERROR) << "no config file!";
        return -1;
    }

    LOG(INFO) << "get config filename: " << configFile;
    initFilter(configFile);

    mainLoop();
    return 0;
}

void initFilter(const std::string &file) {
    std::vector<ConfItem> ci;
    auto filter = PacketFilter::getInstance();
    CHECK(parseConfigFile(file, ci)) << "syntax error in config file";
    for (auto &c : ci) {
        LOG(INFO) << "got config: " << std::hex << c.ip() << " " << c.method() << std::endl;
        CHECK(filter->add(c)) << "add filter failed";
    }
}

static void processPacketData(uint8_t *data, int size) {
    struct pkt_buff *pkt;
    struct iphdr *ip;
    char buf[4096];
    pkt = pktb_alloc(AF_INET, data, size, 0);
    ip = nfq_ip_get_hdr(pkt);

    nfq_ip_snprintf(buf, sizeof buf, ip);
    fputs(buf, stdout);
}

static int queue_cb(std::shared_ptr<NFQ_queue> qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa) {
    static auto filter = PacketFilter::getInstance();
	u_int32_t id;
    struct nfqnl_msg_packet_hdr *ph;
    uint8_t *data;
    int datalen;
    struct pkt_buff *pkt;
    struct iphdr *ip;

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);
    datalen = nfq_get_payload(nfa, &data);
    pkt = pktb_alloc(AF_INET, data, datalen, 16 + 8);
    PCHECK(pkt != nullptr) << "pktb_alloc failed";
    ip = nfq_ip_get_hdr(pkt);
    uint16_t iphdrLen = 4 * ip->ihl;

    ssize_t newBodyLen;
    VLOG(2) << std::hex << ip->saddr << " -> " << ip->daddr;
    
    uint32_t verdict = NF_ACCEPT;
    PacketFilter::key_type key;
    if (ip->protocol == 6) {
        key.d.proto = static_cast<uint32_t>(ConfItem::protocol::TCP);
    } else if (ip->protocol == 17) {
        key.d.proto = static_cast<uint32_t>(ConfItem::protocol::UDP);
    } else {
        key.d.proto = static_cast<uint32_t>(ConfItem::protocol::ALL);
    }

    bool crypt;
    PacketFilter::transer_type transer;
    switch(ph->hook) {
    case NF_IP_LOCAL_OUT:
        crypt = true;
        key.d.ip = ip->daddr;
        VLOG(2) << "got an outgoing packet, key: " << std::hex << key.key;
        transer = filter->find(key);
        break;

    case NF_IP_LOCAL_IN:
        crypt = false;
        key.d.ip = ip->saddr;
        VLOG(2) << "got an incoming packet, key: " << std::hex << key.key;
        transer = filter->find(key);
        break;

    default:
        LOG(WARNING) << "unexpected hook: " << ph->hook;
        break;
    }
    if (!transer) {
        VLOG(1) << "not match, skip this packet";
        verdict = NF_ACCEPT;
    } else {
        VLOG(1) << "transforming the packet, crypt: " << crypt;
        ip->tot_len = ntohs(ip->tot_len);
        verdict = (transer->accept() ? NF_ACCEPT : NF_DROP); 
        ssize_t bodyLen = ip->tot_len - iphdrLen;
        newBodyLen = transer->transform(crypt, pktb_network_header(pkt) + iphdrLen,
                           bodyLen, bodyLen + 16 + 8,
                           reinterpret_cast<void *>(ip->id));
        if (newBodyLen > 0) {
            ip->tot_len += newBodyLen - bodyLen;
            ip->tot_len = htons(ip->tot_len);
            nfq_ip_set_checksum(ip);
            VLOG(1) << "old len: " << bodyLen << ", new len: " << newBodyLen;
        } else {
            ip->tot_len = htons(ip->tot_len);
            LOG(WARNING) << "transer failed, will skip this packet";
        }
    }

    int result;
    if (newBodyLen <= 0) {
        result = qh->set_verdict(id, verdict, 0, nullptr);
    } else {
        result = qh->set_verdict(id, verdict,
                            pktb_len(pkt), pktb_data(pkt));
    }
    pktb_free(pkt);

    return result;
}

static void pkt_arrived_cb(EV_P_ ev_io *wc, int revents) {
    uint8_t buf[65536];
    ssize_t len;
    queue_io *w = reinterpret_cast<queue_io *>(wc);

    len = recv(w->io.fd, buf, sizeof buf, 0);
    PCHECK(len >= 0) << "recv failed!";
    if (len == 0) {
        LOG(WARNING) << "fake wake up!";
        return;
    }

    VLOG(1) << len << " bytes received, start to handle packet";
    w->handle->handle_packet(buf, len);
}

static void interrupt_cb(EV_P_ ev_signal *w, int revents) {
    LOG(WARNING) << "sigint received";
    ev_signal_stop(EV_A_ w);
    ev_break(EV_A);
}


void mainLoop() {
    struct ev_loop *loop = ev_loop_new();
    queue_io queue_watcher;
    struct ev_signal intrpt;

    ev_signal_init(&intrpt, interrupt_cb, SIGINT);
    ev_signal_start(EV_A_ &intrpt);

    LOG(INFO) << "Opening handle.";
    auto h = std::make_shared<NFQ>();
	if (!h) {
        LOG(ERROR) << "error during nfq_open";
		exit(1);
	}

	LOG(INFO) << "unbinding existing nf_queue handler for AF_INET (if any)";
    PCHECK(nfq_unbind_pf(h->native_handle(), AF_INET) >= 0) << "error during nfq_unbind_pf()";

	LOG(INFO) << "binding nfnetlink_queue as nf_queue handler for AF_INET";
	PCHECK(nfq_bind_pf(h->native_handle(), AF_INET) >= 0) << "error during nfq_bind_pf()";

	LOG(INFO) << "binding this socket to queue '0'";
    auto qh = h->create_queue(queue_cb);

	LOG(INFO) << "setting copy_packet mode";
	if (qh->set_mode(NFQNL_COPY_PACKET, 0xffff) < 0) {
		LOG(ERROR) << "can't set packet_copy mode";
		exit(1);
	}

    ev_io_init(&queue_watcher.io, pkt_arrived_cb, h->get_fd(), EV_READ);
    queue_watcher.handle = h;
    set_nonblocking(queue_watcher.io.fd);
    ev_io_start(EV_A_ &queue_watcher.io);

    ev_run(EV_A_ 0);

    ev_loop_destroy(EV_A);
}

