#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h> 
#include <sock_essentials.h>


int main(int argc, char **argv)
{
    signal(SIGINT, handle_sigint);

    if(argc < 2)
    {
        fprintf(stderr, "[-] Too few arguments!\n");
        fprintf(stderr, "[-] Usage: sniff [--interface <INTERFACE> [--promiscuous] [--filter <FILTER>] [--hex]] [--list-interfaces]\n");
        return 1;
    }
    
    for(int i = 1; i < argc; ++i)
    {
        if(strncmp(argv[i], "--", 2) == 0)
        {
            if(!_flag_present(argv[i]))
            {
                fprintf(stderr, "[-] \"%s\" not a valid flag!\n", argv[i]);
                fprintf(stderr, "[-] Try: [--list-interfaces] [--interface <INTERFACE> [--promiscuous] [--filter <FILTER>] [--hex]]\n");
                return 2;
            }
        }
    }

    ARGC = argc, ARGV = argv;

    int list_interfaces_flag_index = _arg_present("--list-interfaces");
    int interface_flag_index = _arg_present("--interface");

    if(list_interfaces_flag_index > 0 && argc > 2)
    {
        fprintf(stderr, "[-] Usage: sniff --list-interfaces\n");
        return 3;
    }
    else if(list_interfaces_flag_index > 0 && argc == 2)
    {
        _list_interfaces();
    }
    else if(interface_flag_index < 0)
    {
        fprintf(stderr, "[-] Usage: sniff --interface <INTERFACE> [--filter <FILTER>] [--promiscuous] [--hex]\n");
        return 6;
    }
    else
    {
        int promiscuous_flag_index = _arg_present("--promiscuous");
        int filter_flag_index = _arg_present("--filter");
        int hex_flag_index = _arg_present("--hex");

        int flag = _check_interface_available(argv[interface_flag_index + 1]);

        if(flag == IF_NONEXISTENT)
        {
            fprintf(stderr, "[-] \"%s\" is administratively down\n", argv[interface_flag_index + 1]);
            return 7;
        }
        else if(flag == ADMIN_DOWN)
        {
            fprintf(stderr, "[-] \"%s\" interface has not been found\n", argv[interface_flag_index + 1]);
            return 8;
        }
        else
        {
            ifname = argv[interface_flag_index + 1];
            is_promiscuous = (promiscuous_flag_index > 0) ? true : false;
            bool hex = (hex_flag_index > 0) ? true : false;
            char *const filter = (filter_flag_index > 0) ? argv[filter_flag_index + 1] : NULL;

            _packet_socket_enable(ifname, filter, is_promiscuous, hex, flag);
        }
    }

    return 0;
}
