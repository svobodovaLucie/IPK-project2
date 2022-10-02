/*
 * File:          ipk-sniffer.h
 * Institution:   FIT BUT
 * Academic year: 2021/2022
 * Course:        IPK - Computer Communications and Networks
 * Author:        Lucie Svobodová, xsvobo1x@stud.fit.vutbr.cz
 *
 * IPK- project 2 (ZETA variant): Packet sniffer
 */

#ifndef IPK_PROJECT2_IPK_SNIFFER_H
#define IPK_PROJECT2_IPK_SNIFFER_H

#include <pcap.h>
/**
 * Constants used in the programme.
 */
#define ETH_HEADER_SIZE   14     // size of the Ethernet header (14 bytes)
#define IPV6_HEADER_SIZE  40     // size of the IPv6 header (40 bytes)
#define MAX_TIMESTAMP_LEN 22     // max length of timestamp buffer used
#define FRAME_PRINT_LEN   16     // length of the data to be printed on one line

/**
 * Enumeration used for ether types.
 * List of ether types: https://en.wikipedia.org/wiki/EtherType
 */
enum ether_types {IPv4 = 0x0800, ARP = 0x0806, IPv6 = 0x86DD};

/**
 * Enumeration used for IP protocols.
 * List of IP protocols: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
 */
enum ip_protocols {ICMPv4 = 1, TCP = 6, UDP = 17, ICMPv6 = 58, NO_NEXT_HEADER = 59};

/**
 * Global variables used in the programme.
 */
char errbuf[PCAP_ERRBUF_SIZE];   // buffer used for storing error strings from pcap functions
int sigint_received;             // variable that indicates if a SIGINT signal was received
pcap_t *pcap;                    // pcap handler

/**
 * Structure used for storing command line options.
 */
typedef struct options {
    char *interface;    // interface to be listened on
    int port;           // port to be used for UDP and TCP filtering
    char tcp;           // TCP packets filter
    char udp;           // UDP packets filter
    char arp;           // ARP packets filter
    char icmp;          // ICMP packets filter
    unsigned num;       // number of packets to be displayed
} options_t;

#endif //IPK_PROJECT2_IPK_SNIFFER_H
