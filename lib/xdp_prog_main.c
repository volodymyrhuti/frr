#include "xdp.h"

int main(int argc, char **argv)
{
        test_lpm_map();
}


#if 0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <assert.h>
#include <arpa/inet.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#endif
