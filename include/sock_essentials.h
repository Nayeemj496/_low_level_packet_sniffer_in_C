#ifndef SOCK_ESSENTIALS_H
#define SOCK_ESSENTIALS_H

#include <stdio.h>
#include <stdbool.h>
#include <signal.h>

#define N_FLAG              5
#define ADMIN_UP            0
#define ADMIN_DOWN          1
#define IF_NONEXISTENT      2
#define ALL_IF              3
#define SOCK_FAILED         4
#define MAXIMUM_SNAPLEN     262144

extern char *flags[];
extern char **ARGV;
extern char *ifname;
extern int ARGC;
extern int raw_sock;
extern bool is_promiscuous;

void handle_sigint(int);
bool _flag_present(char * const);
int _arg_present(char * const);
int _list_interfaces(void);
int _check_interface_available(char * const);
int _packet_socket_enable(char * const, char * const, bool, bool, int);

#endif