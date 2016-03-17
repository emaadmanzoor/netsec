/* 
 * Copyright 2016 Emaad Ahmed Manzoor
 * License: Apache License, Version 2.0
 * https://github.com/emaadmanzoor/netsec
 */
#define SNIFFLEN 65536

#include <stdbool.h>

struct pcap_args_t {
  bool string;
  char *mstring;
};
