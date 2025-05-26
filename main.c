#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/rtnetlink.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

struct sock_filter code[] = {
    { 0x28,  0,  0, 0x0000000c },
    { 0x15,  0,  1, 0x00000806 },
    { 0x06,  0,  0, 0xffffffff },
    { 0x06,  0,  0, 0000000000 },
};

struct sock_fprog bpf = {
    .len = sizeof(code)/sizeof(code[0]),
    .filter = code,
};

int check_neigh_exists(const char *ifname, struct in_addr *ip) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct {
        struct nlmsghdr n;
        struct ndmsg ndm;
        char buf[256];
    } req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type = RTM_GETNEIGH;
    req.ndm.ndm_family = AF_INET;
    req.ndm.ndm_ifindex = if_nametoindex(ifname);

    struct rtattr *rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
    rta->rta_type = NDA_DST;
    rta->rta_len = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), ip, 4);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_LENGTH(4);

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
    };

    if (sendto(sock, &req, req.n.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    char buf[8192];
    int len = recv(sock, buf, sizeof(buf), 0);
    if (len < 0) {
        perror("recv");
        close(sock);
        return -1;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    while (NLMSG_OK(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            close(sock);
            return 0; // Neighbor does not exist
        }
        if (nlh->nlmsg_type == RTM_NEWNEIGH) {
            close(sock);
            return 1; // Neighbor exists
        }
        nlh = NLMSG_NEXT(nlh, len);
    }

    close(sock);
    return 0; // Neighbor does not exist
}

void update_neigh(const char *ifname, struct in_addr *ip, struct ether_addr *mac) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket");
        return;
    }

    struct {
        struct nlmsghdr n;
        struct ndmsg ndm;
        char buf[256];
    } req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    req.n.nlmsg_type = RTM_NEWNEIGH;
    req.ndm.ndm_family = AF_INET;
    req.ndm.ndm_ifindex = if_nametoindex(ifname);
    req.ndm.ndm_state = NUD_REACHABLE;

    struct rtattr *rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
    rta->rta_type = NDA_LLADDR;
    rta->rta_len = RTA_LENGTH(6);
    memcpy(RTA_DATA(rta), mac->ether_addr_octet, 6);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_LENGTH(6);

    rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
    rta->rta_type = NDA_DST;
    rta->rta_len = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), ip, 4);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_LENGTH(4);

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
    };

    if (sendto(sock, &req, req.n.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s [-v] <interface>\n", argv[0]);
        return 1;
    }

    int verbose = 0;
    const char *ifname;

    if (argc == 3 && strcmp(argv[1], "-v") == 0) {
        verbose = 1;
        ifname = argv[2];
    } else {
        ifname = argv[1];
    }

    int socky;
    struct ifreq ifr;
    struct sockaddr_ll socket_ll;
    unsigned char buf[4096];

    memset(&ifr, 0, sizeof(ifr));
    memset(&socket_ll, 0, sizeof(socket_ll));

    socky = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socky < 0) {
        perror("socket");
        return 1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(socky, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(socky);
        return 1;
    }

    socket_ll.sll_family = AF_PACKET;
    socket_ll.sll_protocol = htons(ETH_P_ALL);
    socket_ll.sll_ifindex = ifr.ifr_ifindex;

    if (bind(socky, (struct sockaddr *)&socket_ll, sizeof(socket_ll)) < 0) {
        perror("bind");
        close(socky);
        return 1;
    }
    
    if (setsockopt(socky, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        perror("setsockopt");
        close(socky);
        return 1;
    }

    while (1) {
        ssize_t len = recv(socky, buf, sizeof(buf), 0);
        if (len <= 0) {
            perror("recv");
            break;
        }

        struct ethhdr *ethhdr = (struct ethhdr *)buf;
        struct arphdr *ah = (struct arphdr *)(buf + 14);
        int proto = ntohs(ethhdr->h_proto);

        if (proto == ETH_P_ARP && ntohs(ah->ar_op) == ARPOP_REPLY) {
            struct in_addr src_ip, tgt_ip;
            struct ether_addr src_mac, tgt_mac;
            memcpy(&src_mac, buf + 22, 6);
            memcpy(&src_ip, buf + 28, 4);
            memcpy(&tgt_mac, buf + 32, 6);
            memcpy(&tgt_ip, buf + 38, 4);

            if (verbose) {
                printf("ARP reply detected:\n");
                printf("  Sender MAC: %s\n", ether_ntoa(&src_mac));
                printf("  Sender IP: %s\n", inet_ntoa(src_ip));
                printf("  Target MAC: %s\n", ether_ntoa(&tgt_mac));
                printf("  Target IP: %s\n", inet_ntoa(tgt_ip));
            }

            if (check_neigh_exists(ifname, &src_ip)) {
                if (verbose) {
                    printf("Neighbor already exists: %s\n", inet_ntoa(src_ip));
                }
            } else {
                update_neigh(ifname, &src_ip, &src_mac);
            }
        }
    }

    close(socky);
    return 0;
}
