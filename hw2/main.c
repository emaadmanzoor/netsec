#include <getopt.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

extern char *optarg;
extern int optind;
static const char optstring[] = "i:r:s:";
static const char usage[] = "usage: %s [-i interface] [-r file] [-s string] expr\n";

int main(int argc, char *argv[]) {
  char c;
  char *iname;
  char *fname;
  char *mstring;
  bool interface = false;
  bool file = false;
  bool string = false;

  if (argc < 2) {
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  }

  while ((c = getopt(argc, argv, optstring)) != -1) {
    switch (c) {
      case 'i':
        iname = optarg;
        interface = true;
        break;
      case 'r':
        fname = optarg;
        file = true;
        break;
      case 's':
        mstring = optarg;
        string = true;
        break;
      case '?':
        fprintf(stderr, "Invalid argument at pos: %d\n", optind);
        fprintf(stderr, usage, argv[0]);
        exit(-1);
    }
  } 

  if (interface && file) {
    fprintf(stderr, "Only one of -i or -r should be specified.\n");
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  }

  if (interface)
    printf("interface: %s\n", iname);
  if (file)
    printf("file: %s\n", fname);
  if (string)
    printf("string: %s\n", mstring);
  printf("expression: %s\n", argv[argc-1]);

  return 0;
}
