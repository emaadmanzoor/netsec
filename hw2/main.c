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
  char c; // for getopt
  char *dev; // interface name, pcap device
  char *fname; // filename
  char *mstring; // matching string
  char *expr; // expression
  char errbuf[PCAP_ERRBUF_SIZE]; // pcap error buffer
  pcap_t *handle;
  struct bpf_program fexp; // compiled filter expression
  bpf_u_int32 netmask; // netmask of pcap device
  bpf_u_int32 netip; // ip of snipping device
  struct pcap_pkthdr header;
  const u_char *packet;
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
        dev = optarg;
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

  // cannot use both a interface and a file
  if (interface && file) {
    fprintf(stderr, "Only one of -i or -r should be specified.\n");
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  }

  if (interface) { // if an interface was specified
    handle = pcap_open_live(dev, BUFSIZ, 1, 65536, errbuf);
  } else if (file) { // if a file was specified
    handle = pcap_open_offline(fname, errbuf);
  } else { // if neither an interface nor a file was specified
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
      fprintf(stderr, "Couldn't find default device: (%s)\n", errbuf);
      exit(-1);
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 65536, errbuf);
  }
  
  // check if handle is valid
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: (%s)\n", dev, errbuf);
    exit(-1);
  }

  if (pcap_lookupnet(dev, &netip, &netmask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", dev);
    netip = 0;
    netmask = 0;
  }

  expr = argv[argc-1];
  printf("Using expression: %s\n", expr);
  if (pcap_compile(handle, &fexp, expr, 0, netip) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: (%s)\n", expr, pcap_geterr(handle));
    exit(-1);
  }

  if (pcap_setfilter(handle, &fexp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: (%s)\n", expr, pcap_geterr(handle));
    exit(-1);
  }

  packet = pcap_next(handle, &header);
  printf("Jacked a packet with length of [%d]\n", header.len);
  pcap_close(handle);

  return 0;
}
