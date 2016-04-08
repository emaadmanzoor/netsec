/* 
 * Copyright 2016 Emaad Ahmed Manzoor
 * License: Apache License, Version 2.0
 * https://github.com/emaadmanzoor/netsec
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "param.h"

extern char *optarg;
extern int optind;
static const char optstring[] = "l:k:";
static const char usage[] = "usage: %s [-l port] -k keyfile destination port\n";

int main(int argc, char *argv[]) {
  char c; // for getopt
  int inport;
  int outport;
  char *keyfilename;
  char key[MAX_KEY_LEN];
  char *dest;
  bool reverse = false;
  FILE *f;
  struct in_addr *addr;

  while ((c = getopt(argc, argv, optstring)) != -1) {
    switch (c) {
      case 'l':
        inport = atoi(optarg);
        reverse = true;
        break;
      case 'k':
        keyfilename = optarg;
        break;
      case '?':
        fprintf(stderr, "Invalid argument at pos: %d\n", optind);
        fprintf(stderr, usage, argv[0]);
        exit(-1);
    }
  } 

  dest = argv[argc-2];
  outport = atoi(argv[argc-1]);

  fprintf(stderr, "Starting pbproxy: (");
  if (reverse)
    fprintf(stderr, " In-port=%d ", inport);
  fprintf(stderr, " Keyfile=%s ", keyfilename);
  fprintf(stderr, " Dest=%s ", dest);
  fprintf(stderr, " Out-port=%d )\n", outport);

  // read key
  f = fopen(keyfilename, "rb");
  if (f == NULL) {
    fprintf(stderr, "Could not open keyfile: %s\n", keyfilename);
    exit(-1);
  }
  fgets(key, MAX_KEY_LEN, f);

  // convert destination host to ip address
  addr = (struct in_addr *) (gethostbyname(dest)->h_addr_list)[0];
  printf("IP %s\n", inet_ntoa(*addr));

  return 0;
}
