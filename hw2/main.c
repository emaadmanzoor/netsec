/* 
 * Copyright 2016 Emaad Ahmed Manzoor
 * License: Apache License, Version 2.0
 * https://github.com/emaadmanzoor/netsec
 */
#include <getopt.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "ethernet.h"
#include "ip.h"
#include "param.h"

extern char *optarg;
extern int optind;
static const char optstring[] = "i:r:s:";
static const char usage[] = "usage: %s [-i interface] [-r file] [-s string] [expr]\n";

void got_packet(uint8_t *args, const struct pcap_pkthdr *header,
                const uint8_t *packet);

int main(int argc, char *argv[]) {
  char c; // for getopt
  char *dev; // interface name, pcap device
  char *fname; // filename
  char *expr; // expression
  char errbuf[PCAP_ERRBUF_SIZE]; // pcap error buffer
  pcap_t *handle;
  struct bpf_program fexp; // compiled filter expression
  bpf_u_int32 netmask; // netmask of pcap device
  bpf_u_int32 netip; // ip of sniffing device
  struct pcap_args_t pcap_args;
  bool interface = false;
  bool file = false;

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
        pcap_args.mstring = optarg;
        pcap_args.string = true;
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
    handle = pcap_open_live(dev, SNIFFLEN, 1, 0, errbuf);
  } else if (file) { // if a file was specified
    handle = pcap_open_offline(fname, errbuf);
  } else { // if neither an interface nor a file was specified
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
      fprintf(stderr, "Couldn't find default device: (%s)\n", errbuf);
      exit(-1);
    }
    handle = pcap_open_live(dev, SNIFFLEN, 1, 0, errbuf);
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
    exit(-1);
  }

  if (argc > optind) { // expr was given
    expr = argv[argc-1];
    if (pcap_compile(handle, &fexp, expr, 0, netip) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: (%s)\n", expr, pcap_geterr(handle));
      exit(-1);
    }

    if (pcap_setfilter(handle, &fexp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: (%s)\n", expr, pcap_geterr(handle));
      exit(-1);
    }
  }

  printf("Starting packet capture: ");
  if (interface)
    printf(" Device: %s ", dev);
  else
    printf(" File: %s ", fname);
  if (argc >= 2)
    printf(" BPF expression: %s\n", expr);
  pcap_loop(handle, -1, got_packet, (uint8_t *) &pcap_args);

  pcap_freecode(&fexp);
  pcap_close(handle);

  return 0;
}

void got_packet(uint8_t *args, const struct pcap_pkthdr *header,
                const uint8_t *packet) {
  time_t ts;
  long int ts_usec;
  char timebuff[20];
  struct ethernet_header_t *ethhdr;
  struct ip_header_t *iphdr;
  int i, j, ip_header_size, payload_size, payload_offset;
  uint8_t *payload;
  char *payload_string;
  char *pos;
  struct pcap_args_t *pcap_args = (struct pcap_args_t *) args;

  // check if payload has the provided string
  ethhdr = (struct ethernet_header_t *) (packet);
  iphdr = (struct ip_header_t *) (packet + sizeof(struct ethernet_header_t));

  ip_header_size = ((iphdr->version_headerlen) & 0xf) * 4;
  payload_offset = sizeof(struct ethernet_header_t) + ip_header_size;
  payload_size = header->len - payload_offset;
  payload = (uint8_t *) (packet + payload_offset);

  if (pcap_args->string) {
    payload_string = (char *) malloc(sizeof(char) * payload_size);
    strncpy(payload_string, (char *) payload, payload_size);
    pos = strstr(payload_string, pcap_args->mstring);
    if (pos == NULL) {
      // drop packet
      free(payload_string);
      return;
    }
    free(payload_string);
  }

  // print timestamp
  ts = (header->ts).tv_sec; // seconds since epoch
  ts_usec = (header->ts).tv_usec; // microseconds
  strftime(timebuff, 20, "%Y-%m-%d %H:%M:%S", localtime(&ts));
  printf("%s.%ld ", timebuff, ts_usec);

  // print source/destination MAC address
  for (i = 0; i < 6; i++) {
    printf("%02x", (ethhdr->smac)[i]);
    if (i != 5)
      printf(":");
  }
  printf(" > ");
  for (i = 0; i < 6; i++) {
    printf("%02x", (ethhdr->dmac)[i]);
    if (i != 5)
      printf(":");
  }
  printf(", ");

  // print ethertype
  printf("ethertype 0x%02x%02x, ", (ethhdr->ethertype)[0], (ethhdr->ethertype)[1]);

  // print packet length
  printf("length %u, ", header->len);

  // print source/destination IP address
  for (i = 0; i < 4; i++) {
    printf("%d", (iphdr->sip)[i]);
    if (i != 3)
      printf(".");
  }
  printf(" > ");
  for (i = 0; i < 4; i++) {
    printf("%d", (iphdr->dip)[i]);
    if (i != 3)
      printf(".");
  }
  printf(" ");

  // print protocol
  switch(iphdr->protocol) {
    case 1:
      printf("ICMP");
      break;
    case 6:
      printf("TCP");
      break;
    case 17:
      printf("UDP");
      break;
    default:
      printf("OTHER");
      break;
  }

  printf("\n");

  // print packet payload
  for (i = 0; i < header->len - payload_offset; i += 16) {
    for (j = 0; j < 16 && (i + j) < (header->len - payload_offset); j += 2) {
      printf("%02x", *(payload + i + j));
      printf("%02x ", *(payload + i + j + 1));
    }
    printf("\n");
  }
}
