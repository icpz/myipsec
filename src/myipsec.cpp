#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <netinet/in.h>

#include <glog/logging.h>
#include <ev.h>
#include "util.h"
#include "nfq.h"
#include "conf.h"

void main_loop();

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

    LOG(INFO) << "get configure file: " << configFile;

    std::vector<ConfItem> ci;
    CHECK(parseConfigFile(configFile, ci)) << "syntax error in config file";
    for (auto &c : ci) {
        LOG(INFO) << std::hex << c.ip() << c.method() << std::endl;
    }

    // main_loop();
    return 0;
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

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
        if (ph->hook == NF_IP_LOCAL_OUT) {
            printf("this is a outgoing packet\n");
        }
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	} else {
        printf("error: cannot get hw\n");
    }

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, (unsigned char **)&data);
	if (ret >= 0) {
		printf("payload_len=%d ", ret);
		processPacketData ((uint8_t *)data, ret);
	}
	fputc('\n', stdout);
	fputc('\n', stdout);

	return id;
}

static int queue_cb(std::shared_ptr<NFQ_queue> qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa) {
	u_int32_t id = print_pkt(nfa);

    struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);
    return qh->set_verdict(id, NF_ACCEPT, 0, nullptr);
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


void main_loop() {
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
	if (nfq_unbind_pf(h->native_handle(), AF_INET) < 0) {
		LOG(ERROR) << "error during nfq_unbind_pf()";
		exit(1);
	}

	LOG(INFO) << "binding nfnetlink_queue as nf_queue handler for AF_INET";
	if (nfq_bind_pf(h->native_handle(), AF_INET) < 0) {
		LOG(ERROR) << "error during nfq_bind_pf()";
		exit(1);
	}

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

