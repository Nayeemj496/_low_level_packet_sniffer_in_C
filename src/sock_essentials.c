#include <stdio.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>            
#include <signal.h>             // signal()
#include <sys/socket.h>         // socket(); struct sockaddr
#include <sys/ioctl.h>          // ioctl()
#include <net/if.h>             // struct ifreq
#include <arpa/inet.h>          // htons()
#include <ifaddrs.h>            // struct ifaddrs
#include <linux/filter.h>       // struct sock_fprog
#include <linux/if_ether.h>     // ETH_P_ALL
#include <linux/if_packet.h>    // struct sockaddr_ll
#include <pcap/pcap.h>
#include <sock_essentials.h>

char **ARGV = NULL;
char *ifname = NULL;
int ARGC = -1;
int raw_sock = -1;
bool is_promiscuous;

char *flags[] = {
    "--list-interfaces", "--interface", "--promiscuous", "--filter", "--hex"
};

int _change_promiscuous_mode(char * const ifname, bool mode);

void handle_sigint(int sig)
{
    printf("\n[!] Ctrl+C detected. Cleaning up and exiting...\n");

    if(is_promiscuous)
    {
        _change_promiscuous_mode(ifname, false);
    }

    if(raw_sock >= 0)
    {
        close(raw_sock);
    }

    exit(0);
}

bool _flag_present(char * const flag)
{
    for(int i = 0; i < N_FLAG; ++i)
    {
       if(strcmp(flags[i], flag) == 0)
       {
            return true;
       }
    }

    return false;
}

int _arg_present(char * const arg)
{
    for(int i = 0; i < ARGC; ++i)
    {
        if(strcmp(ARGV[i], arg) == 0)
        {
            return i;
        }
    }

    return -1;
}

int _list_interfaces(void)
{
    struct ifaddrs *ifaddr_list = NULL;

    if(getifaddrs(&ifaddr_list) < 0)
    {
        perror("getifaddrs");
        return 4;
    }

    int count = 1;

    for(struct ifaddrs *ifa = ifaddr_list; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr == NULL)
            continue;
        
        if(ifa->ifa_addr->sa_family == AF_PACKET)
        {
            char status[128] = "[";

            int is_up = (ifa->ifa_flags & IFF_UP);
            int is_running = (ifa->ifa_flags & IFF_RUNNING);
            int is_loopback = (ifa->ifa_flags & IFF_LOOPBACK);

            if(is_up)
            {
                strcat(status, "Up");
                if(is_running)
                {
                    strcat(status, ", Running");
                    if(!is_loopback)
                    {
                        strcat(status, ", Connected");
                    }
                }
                else
                {
                    strcat(status, ", Disconnected");
                }
            }
            else
            {
                strcat(status, "Down");
            }

            if(is_loopback)
            {
                strcat(status, ", Loopback");
            }

            strcat(status, "]");

            fprintf(stdout, "%d. %s %s\n", count, ifa->ifa_name, status);
            count += 1;
        }
    }

    freeifaddrs(ifaddr_list);

    return 0;
}

bool _is_ready_to_listen(unsigned int flag)
{
    // Must be administratively up
    if(flag & IFF_UP)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int _check_interface_available(char * const if_name)
{
    struct ifaddrs *ifaddr_list = NULL;

    if(getifaddrs(&ifaddr_list) < 0)
    {
        perror("getifaddrs");
        return 5;
    }

    if(strcmp(if_name, "any") == 0)
        return ALL_IF;

    unsigned int flag = IF_NONEXISTENT;

    for(struct ifaddrs *ifa = ifaddr_list; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_PACKET)
        {
            if(strcmp(ifa->ifa_name, if_name) == 0)
            {
                if(_is_ready_to_listen(ifa->ifa_flags))
                {
                    flag = ADMIN_UP;
                }
                else
                {
                    flag = ADMIN_DOWN;
                }
                
                break;
            }
        }
    }

    freeifaddrs(ifaddr_list);

    return flag;
}

int _change_promiscuous_mode(char * const ifname, bool mode)
{
    struct ifreq ethreq;
    memset(&ethreq, 0x00, sizeof(ethreq));
    strncpy(ethreq.ifr_name, ifname, IFNAMSIZ - 1);

    // Fetch current interface flags
    if(ioctl(raw_sock, SIOCGIFFLAGS, &ethreq) == -1)
    {
        perror("[-] ioctl");
        close(raw_sock);
        return -1;
    }
    
    if(mode)
    {
        ethreq.ifr_flags |= IFF_PROMISC;
    }
    else
    {
        ethreq.ifr_flags &= ~IFF_PROMISC;
    }

    // modify current interface flags
    if (ioctl(raw_sock, SIOCSIFFLAGS, &ethreq) == -1) {
        perror("[-] ioctl");
        close(raw_sock);
        return -1;
    }

    return 0;
}

int _packet_socket_enable(char * const ifname, char * const filter, bool is_promiscuous, bool hex, int flag)
{
    fprintf(stdout, "ifname: %s, filter: %s, is_promiscuous: %d, hex: %d, flag: %d\n", ifname, filter, is_promiscuous, hex, flag);

    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(raw_sock < 0)
    {
        perror("socket creation failed. Are you running with sudo?");
        return SOCK_FAILED;
    }

    if(filter != NULL && strlen(filter))
    {
        struct bpf_program fp;
        pcap_t *dead_handle = pcap_open_dead(DLT_EN10MB, MAXIMUM_SNAPLEN);
        if(!dead_handle)
        {
            fprintf(stderr, "[-] Failed to initialize dead pcap handle\n");
            return 1;
        }

        if(pcap_compile(dead_handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR)
        {
            fprintf(stderr, "[-] Filter compilation error: %s\n", pcap_geterr(dead_handle));
            pcap_close(dead_handle);
            return 1;
        }

        struct sock_fprog linux_filter = {
            .len = (unsigned short)fp.bf_len,
            .filter = (struct sock_filter *)fp.bf_insns
        };

        if (setsockopt(raw_sock, SOL_SOCKET, SO_ATTACH_FILTER, &linux_filter, sizeof(linux_filter)) == -1) {
            perror("[-] setsockopt");
            close(raw_sock);
            pcap_freecode(&fp);
            pcap_close(dead_handle);
            return 1;
        }

        // debugging purpose
        for (int i = 0; i < linux_filter.len; ++i) {
            printf("[%02d] 0x%04x 0x%02x 0x%02x 0x%08x\n",
                i,
                linux_filter.filter[i].code,
                linux_filter.filter[i].jt,
                linux_filter.filter[i].jf,
                linux_filter.filter[i].k);
        }

        pcap_freecode(&fp);
        pcap_close(dead_handle);

        fprintf(stdout, "[+] Successfully compiled and attached filter: \"%s\"\n", filter);
    }

    if(flag != ALL_IF)
    {
        // packet will run on "ifname" interface
        unsigned int ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            perror("[-] Failed to find interface index");
            close(raw_sock);
            return 1;
        }

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL); // Capture all protocols on this interface
        sll.sll_ifindex  = ifindex;          // Bind strictly to this interface index

        // Bind the socket
        if (bind(raw_sock, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
            perror("[-] Failed to bind socket to interface");
            close(raw_sock);
            return 1;
        }

        printf("[+] Socket successfully bound to interface %s (index: %u)\n", ifname, ifindex);
    }

    if(is_promiscuous)
    {
        // enable promiscuous mode
        if(_change_promiscuous_mode(ifname, true) < 0)
        {
            close(raw_sock);
            return -1;
        }
    }
    
    printf("[+] Sniffer started on interface %s", ifname);

    if(is_promiscuous)
        fprintf(stdout, " in promiscuous mode\n");
    else
        fprintf(stdout, "\n");

    printf("[+] Waiting for packets... (Press Ctrl+C to stop)\n");

    while(true)
    {
        fprintf(stdout, "hello world\n");
        sleep(2);
    }

    if(is_promiscuous)
    {
        _change_promiscuous_mode(ifname, false);
    }

    close(raw_sock);

    return 0;
}