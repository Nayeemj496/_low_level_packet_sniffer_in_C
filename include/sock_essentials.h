#ifndef SOCK_ESSENTIALS_H
#define SOCK_ESSENTIALS_H

#include <stdio.h>
#include <stdbool.h>

#define N_FLAG          5
#define ADMIN_UP        0
#define ADMIN_DOWN      1
#define IF_NONEXISTENT  2

bool _flag_present(char * const);
int _arg_present(char * const);
int _list_interfaces(void);
int _check_interface_available(char * const);
bool _is_ready_to_listen(unsigned int);
void _packet_socket_enable(char * const, bool, bool);

extern char *flags[];
extern int ARGC;
extern char **ARGV;
extern int raw_sock;

#endif