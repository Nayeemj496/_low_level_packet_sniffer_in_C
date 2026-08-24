#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>            
#include <signal.h>             // signal()
#include <sys/socket.h>         // socket(); struct sockaddr
#include <net/if.h>             // struct ifreq
#include <arpa/inet.h>          // htons()
#include <ifaddrs.h>            // struct ifaddrs
#include <linux/if_ether.h>     // ETH_P_ALL
#include <linux/if_packet.h>    // struct sockaddr_ll
#include <sock_essentials.h>

int ARGC = -1;
char **ARGV = NULL;
int raw_sock = -1;

char *flags[] = {
    "--list-interfaces", "--interface", "--promiscuous", "--filter", "--hex"
};

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

int _check_interface_available(char * const if_name)
{
    struct ifaddrs *ifaddr_list = NULL;

    if(getifaddrs(&ifaddr_list) < 0)
    {
        perror("getifaddrs");
        return 5;
    }

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

void _packet_socket_enable(char * const filter, bool is_promiscuous, bool hex)
{
    fprintf(stdout, "filter: %s, is_promiscuous: %d, hex: %d\n", filter, is_promiscuous, hex);
}