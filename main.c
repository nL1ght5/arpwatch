#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/rtnetlink.h>
#include <netinet/if_ether.h>
#include <getopt.h>
#include <errno.h>
#include <sys/capability.h>
#include <stdarg.h>

#define ETH_HEADER_LEN        14
#define ARP_HDR_LEN          sizeof(struct arphdr)
#define MAC_ADDR_LEN         6
#define IPV4_ADDR_LEN        4
#define MAC_ADDR_STRLEN      18   // 17 chars + 1 for null
#define IPV4_ADDR_STRLEN     INET_ADDRSTRLEN
#define PACKET_BUF_SIZE      4096

#define LOG_INFO             1
#define LOG_WARN             2
#define LOG_ERR              3
#define LOG_DEBUG            4

static int debug_enabled = 0;
static int debug_unmatched_arp = 0;

static void log_message(int level, const char *fmt, ...) {
    va_list args;
    FILE *out = (level == LOG_ERR || level == LOG_WARN) ? stderr : stdout;
    switch (level) {
        case LOG_ERR:
            fprintf(out, "[ERROR] ");
            break;
        case LOG_WARN:
            fprintf(out, "[WARN] ");
            break;
        case LOG_DEBUG:
            if (!debug_enabled) return;
            fprintf(out, "[DEBUG] ");
            break;
        case LOG_INFO:
            fprintf(out, "[INFO] ");
            break;
        default:
            break;
    }
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);
    fprintf(out, "\n");
}

static struct sock_filter bpf_code[] = {
    { 0x28, 0, 0, 0x0000000c }, // ldh [12] EtherType
    { 0x15, 0, 1, 0x00000806 }, // jne #0x806, drop
    { 0x06, 0, 0, 0x0000ffff }, // Accept all ARP
    { 0x06, 0, 0, 0x00000000 }, // Drop
};

static struct sock_fprog bpf = {
    .len = sizeof(bpf_code) / sizeof(bpf_code[0]),
    .filter = bpf_code,
};

static void print_help(const char *progname) {
    printf(
        "Usage: %s [OPTIONS] -i <interface>\n"
        "\n"
        "Options:\n"
        "  -i, --interface <interface>  Network interface to listen on (required)\n"
        "  -v, --verbose                Enable verbose output\n"
        "      --debug                  Enable debug output at runtime\n"
        "      --debug-unmatched-arp    Enable log for 'Packet is not an ARP reply, ignoring'\n"
        "  -h, --help                   Show this help message and exit\n"
        "\n"
        "Description:\n"
        "  Listens for ARP replies on the specified network interface and updates\n"
        "  neighbor entries as needed. Only ARP reply packets are processed (filtered by BPF).\n"
        "  Use -v for additional packet information on each ARP reply.\n"
        "  Use --debug to enable debug logs at runtime.\n"
        "  Use --debug-unmatched-arp to log when a received packet is not an ARP reply.\n"
        , progname);
}

static void print_capabilities(void) {
    cap_t caps = cap_get_proc();
    if (!caps) {
        log_message(LOG_WARN, "Unable to retrieve capabilities");
        return;
    }
    char *caps_text = cap_to_text(caps, NULL);
    if (caps_text) {
        log_message(LOG_INFO, "Process capabilities: %s", caps_text);
        cap_free(caps_text);
    }
    cap_free(caps);
}

static void print_euid_uid(void) {
    log_message(LOG_INFO, "UID: %d, EUID: %d", getuid(), geteuid());
}

static void debug_print_bpf(const struct sock_fprog *prog) {
    log_message(LOG_DEBUG, "sock_fprog: len=%d, filter=%p", prog->len, (void*)prog->filter);
    for (unsigned int i = 0; i < prog->len; ++i) {
        struct sock_filter f = prog->filter[i];
        log_message(LOG_DEBUG, "bpf_code[%u]: code=0x%02x jt=%u jf=%u k=0x%08x",
            i, f.code, f.jt, f.jf, f.k);
    }
}

static int safe_copy_ifname(char *dst, const char *src, size_t dstsize) {
    if (!src || strlen(src) >= dstsize) return -1;
    if (snprintf(dst, dstsize, "%s", src) >= (int)dstsize) return -1;
    return 0;
}

static int setup_raw_socket(const char *ifname, struct ifreq *ifr, struct sockaddr_ll *socket_ll) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    log_message(LOG_DEBUG, "Opening raw socket on interface %s", ifname);
    if (sockfd < 0) {
        log_message(LOG_ERR, "socket(AF_PACKET) failed: %s", strerror(errno));
        print_euid_uid();
        print_capabilities();
        return -1;
    }

    memset(ifr, 0, sizeof(*ifr));
    if (safe_copy_ifname(ifr->ifr_name, ifname, IFNAMSIZ) < 0) {
        log_message(LOG_ERR, "Invalid interface name: %s", ifname);
        close(sockfd);
        return -1;
    }
    if (ioctl(sockfd, SIOCGIFINDEX, ifr) < 0) {
        log_message(LOG_ERR, "ioctl(SIOCGIFINDEX) failed for %s: %s", ifname, strerror(errno));
        close(sockfd);
        return -1;
    }
    log_message(LOG_DEBUG, "Interface index for %s: %d", ifname, ifr->ifr_ifindex);

    memset(socket_ll, 0, sizeof(*socket_ll));
    socket_ll->sll_family = AF_PACKET;
    socket_ll->sll_protocol = htons(ETH_P_ALL);
    socket_ll->sll_ifindex = ifr->ifr_ifindex;

    if (bind(sockfd, (struct sockaddr *)socket_ll, sizeof(*socket_ll)) < 0) {
        log_message(LOG_ERR, "bind() failed for %s: %s", ifname, strerror(errno));
        close(sockfd);
        return -1;
    }
    log_message(LOG_DEBUG, "Bound socket to interface %s", ifname);

    debug_print_bpf(&bpf);

    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        log_message(LOG_ERR, "setsockopt(SO_ATTACH_FILTER) failed: %s", strerror(errno));
        print_euid_uid();
        print_capabilities();
        if (errno == EPERM) {
            log_message(LOG_ERR, "EPERM: Not enough privilege to attach filter. Are you root?");
        } else if (errno == EINVAL) {
            log_message(LOG_ERR, "EINVAL: Invalid arguments. Possible kernel or BPF issue.");
        }
        close(sockfd);
        return -1;
    }
    log_message(LOG_DEBUG, "Attached BPF filter to socket");

    return sockfd;
}

static void parse_arp_reply(
    const uint8_t *buf,
    struct ether_addr *sender_hw_addr,
    struct in_addr *sender_proto_addr,
    struct ether_addr *target_hw_addr,
    struct in_addr *target_proto_addr
) {
    memcpy(sender_hw_addr,      buf + ETH_HEADER_LEN + 8,  MAC_ADDR_LEN);
    memcpy(sender_proto_addr,   buf + ETH_HEADER_LEN + 14, IPV4_ADDR_LEN);
    memcpy(target_hw_addr,      buf + ETH_HEADER_LEN + 18, MAC_ADDR_LEN);
    memcpy(target_proto_addr,   buf + ETH_HEADER_LEN + 24, IPV4_ADDR_LEN);

    char s_mac[MAC_ADDR_STRLEN], t_mac[MAC_ADDR_STRLEN];
    char s_ip[IPV4_ADDR_STRLEN], t_ip[IPV4_ADDR_STRLEN];
    snprintf(s_mac, sizeof(s_mac), "%s", ether_ntoa(sender_hw_addr));
    snprintf(t_mac, sizeof(t_mac), "%s", ether_ntoa(target_hw_addr));
    snprintf(s_ip, sizeof(s_ip), "%s", inet_ntoa(*sender_proto_addr));
    snprintf(t_ip, sizeof(t_ip), "%s", inet_ntoa(*target_proto_addr));

    log_message(LOG_DEBUG,
        "Parsed ARP reply: sender_hw_addr=%s, sender_proto_addr=%s, target_hw_addr=%s, target_proto_addr=%s",
        s_mac, s_ip, t_mac, t_ip);
}

static int update_neighbor_entry(
    const char *ifname,
    const struct in_addr *ip,
    const struct ether_addr *mac,
    int verbose,
    int debug_enabled
) {
    int sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockfd < 0) {
        if (debug_enabled)
            log_message(LOG_DEBUG, "Failed to open netlink socket: %s", strerror(errno));
        log_message(LOG_ERR, "Failed to open netlink socket: %s", strerror(errno));
        return -1;
    }

    struct {
        struct nlmsghdr nlh;
        struct ndmsg ndm;
        char attrbuf[256];
    } req;

    memset(&req, 0, sizeof(req));

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_type = RTM_NEWNEIGH;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    req.ndm.ndm_family = AF_INET;
    req.ndm.ndm_ifindex = if_nametoindex(ifname);
    req.ndm.ndm_state = NUD_REACHABLE;
    req.ndm.ndm_flags = 0;
    req.ndm.ndm_type = RTN_UNICAST;

    struct rtattr *rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = NDA_DST;
    rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
    memcpy(RTA_DATA(rta), ip, sizeof(struct in_addr));
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_LENGTH(sizeof(struct in_addr));

    rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = NDA_LLADDR;
    rta->rta_len = RTA_LENGTH(MAC_ADDR_LEN);
    memcpy(RTA_DATA(rta), mac, MAC_ADDR_LEN);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_LENGTH(MAC_ADDR_LEN);

    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    struct iovec iov = { &req, req.nlh.nlmsg_len };
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    if (debug_enabled) {
        log_message(LOG_DEBUG, "Sending RTM_NEWNEIGH for IP: %s, MAC: %s, IF: %s (idx %d)",
            inet_ntoa(*ip), ether_ntoa(mac), ifname, req.ndm.ndm_ifindex);
    }

    ssize_t ret = sendmsg(sockfd, &msg, 0);
    if (ret < 0) {
        if (debug_enabled)
            log_message(LOG_DEBUG, "sendmsg(RTM_NEWNEIGH) failed: %s", strerror(errno));
        log_message(LOG_ERR, "sendmsg(RTM_NEWNEIGH) failed: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    char buf[PACKET_BUF_SIZE];
    struct iovec riov = { buf, sizeof(buf) };
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct msghdr rmsg = {
        .msg_name = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov = &riov,
        .msg_iovlen = 1,
    };
    ssize_t rlen = recvmsg(sockfd, &rmsg, MSG_DONTWAIT);
    if (rlen > 0) {
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(nlh, rlen); nlh = NLMSG_NEXT(nlh, rlen)) {
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
                if (err->error) {
                    log_message(LOG_ERR, "Netlink error: %s", strerror(-err->error));
                }
            }
        }
    }

    if (verbose) {
        log_message(LOG_INFO, "Updated neighbor entry: %s -> %s on %s",
            inet_ntoa(*ip), ether_ntoa(mac), ifname);
    } else if (!verbose && debug_enabled) {
        log_message(LOG_DEBUG, "Neighbor entry updated for %s", inet_ntoa(*ip));
    }

    close(sockfd);
    return 0;
}

static void process_arp_packet(const char *ifname, int verbose, const uint8_t *buf, ssize_t len) {
    log_message(LOG_DEBUG, "Received packet of length %zd", len);
    if ((size_t)len < ETH_HEADER_LEN + ARP_HDR_LEN) {
        log_message(LOG_WARN, "Packet too short for ARP");
        return;
    }

    const struct ethhdr *ethhdr = (const struct ethhdr *)buf;
    const struct arphdr *ah = (const struct arphdr *)(buf + ETH_HEADER_LEN);

    log_message(LOG_DEBUG, "EtherType: 0x%04x, ARP opcode: 0x%04x", ntohs(ethhdr->h_proto), ntohs(ah->ar_op));
    if (ntohs(ethhdr->h_proto) != ETH_P_ARP || ntohs(ah->ar_op) != ARPOP_REPLY) {
        if (debug_unmatched_arp) {
            log_message(LOG_INFO, "Packet is not an ARP reply, ignoring");
        }
        return;
    }

    struct ether_addr sender_hw_addr, target_hw_addr;
    struct in_addr sender_proto_addr, target_proto_addr;
    parse_arp_reply(buf, &sender_hw_addr, &sender_proto_addr, &target_hw_addr, &target_proto_addr);

    if (verbose) {
        char s_mac[MAC_ADDR_STRLEN], t_mac[MAC_ADDR_STRLEN];
        char s_ip[IPV4_ADDR_STRLEN], t_ip[IPV4_ADDR_STRLEN];
        snprintf(s_mac, sizeof(s_mac), "%s", ether_ntoa(&sender_hw_addr));
        snprintf(t_mac, sizeof(t_mac), "%s", ether_ntoa(&target_hw_addr));
        snprintf(s_ip, sizeof(s_ip), "%s", inet_ntoa(sender_proto_addr));
        snprintf(t_ip, sizeof(t_ip), "%s", inet_ntoa(target_proto_addr));

        log_message(LOG_INFO, "ARP reply detected:");
        log_message(LOG_INFO, "  Sender MAC: %s", s_mac);
        log_message(LOG_INFO, "  Sender IP: %s", s_ip);
        log_message(LOG_INFO, "  Target MAC: %s", t_mac);
        log_message(LOG_INFO, "  Target IP: %s", t_ip);
    }

    if (update_neighbor_entry(ifname, &sender_proto_addr, &sender_hw_addr, verbose, debug_enabled) < 0) {
        log_message(LOG_WARN, "Failed to update neighbor entry for %s", inet_ntoa(sender_proto_addr));
    }
}

int main(int argc, char *argv[]) {
    struct ifreq ifr;
    struct sockaddr_ll socket_ll;
    const char *ifname = NULL;
    int verbose = 0;
    int sockfd = -1;

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"verbose",   no_argument,       0, 'v'},
        {"debug",     no_argument,       0,  0 },
        {"debug-unmatched-arp", no_argument, 0,  1 },
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int opt, long_index = 0;

    while ((opt = getopt_long(argc, argv, "i:vh", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'i':
                ifname = optarg;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_help(argv[0]);
                return 0;
            case 0: // long option
                if (strcmp(long_options[long_index].name, "debug") == 0) {
                    debug_enabled = 1;
                } else if (strcmp(long_options[long_index].name, "debug-unmatched-arp") == 0) {
                    debug_unmatched_arp = 1;
                }
                break;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    if (!ifname) {
        print_help(argv[0]);
        return 1;
    }

    if (safe_copy_ifname((char[IFNAMSIZ]){0}, ifname, IFNAMSIZ) < 0) {
        log_message(LOG_ERR, "Invalid interface name: %s", ifname ? ifname : "(null)");
        return 1;
    }

    log_message(LOG_DEBUG, "Program started with interface: %s, verbose: %d", ifname, verbose);

    sockfd = setup_raw_socket(ifname, &ifr, &socket_ll);
    if (sockfd < 0) {
        log_message(LOG_ERR, "Failed to set up raw socket. Please ensure you are running as root or have appropriate capabilities.");
        return 1;
    }

    uint8_t buf[PACKET_BUF_SIZE];
    ssize_t len;
    while (1) {
        len = recv(sockfd, buf, sizeof(buf), 0);
        log_message(LOG_DEBUG, "recv() returned %zd", len);
        if (len <= 0) {
            log_message(LOG_ERR, "recv() failed or connection closed");
            break;
        }
        process_arp_packet(ifname, verbose, buf, len);
    }

    close(sockfd);
    log_message(LOG_DEBUG, "Socket closed, exiting");
    return 0;
}