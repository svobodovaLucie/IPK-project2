/*
 * File:          ipk-sniffer.cpp
 * Institution:   FIT BUT
 * Academic year: 2021/2022
 * Course:        IPK - Computer Communications and Networks
 * Author:        Lucie Svobodová, xsvobo1x@stud.fit.vutbr.cz
 *
 * IPK- project 2 (ZETA variant): Packet sniffer
 */

#include <iostream>
#include <cstring>
#include <getopt.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <csignal>
#include "ipk-sniffer.h"

/**
 * Function prints help to the standard output.
 */
 void print_help() {
     printf("Packet sniffer for analysing TCP, UDP, ICMP, ICMPv6 and ARP packets.\n"
            "Usage:\n"
            "./ipk-sniffer [-i intrfc | --interface intrfc ] {-p port} {[--tcp | -t] [--udp | -u] [--arp] [--icmp]} {-n num}\n"
            " - i intrfc/interface intrfc - interface to listen\n"
            "     - if no interface is specified, the application prints all available interfaces and exits\n"
            " - p port\n"
            "     - if this option is not specified, the sniffer is listening on all ports\n"
            "     - if this option is specified, the sniffer filters packets on this port (source or destination port)\n"
            " - t/tcp - filters TCP packets\n"
            " - u/udp - filters UDP packets\n"
            " - icmp - filters ICMP packets\n"
            " - arp - filters ARP packets\n"
            " - n num - number of packets to be displayed\n"
            "         - implicit value for this option is 1\n"
            " If no protocol option (t/tcp, u/udp, icmp, arp) is specified the sniffer displays all of these packets that are caught.\n"
            "\n"
            "For more information see README or the documentation (manual.pdf).\n"
            "Author: Lucie Svobodová (xsvobo1x@stud.fit.vutbr.cz)\n"
            "IPK - project 2, FIT BUT 2021/2022\n");
}

/**
 * Function prints a list of active devices (interfaces).
 */
int print_interfaces() {
    pcap_if_t *alldevsp = nullptr;      // structure that stores list of all devices
    // load all devices to the structure
    int res = pcap_findalldevs(&alldevsp, errbuf);
    if (res == PCAP_ERROR) {
        printf("error: %s\n", errbuf);
        return 1;
    }
    // print all devices
    for (pcap_if_t *devs = alldevsp; devs != nullptr; devs = devs->next) {
        printf("%s\n", devs->name);
    }
    // free the structure
    pcap_freealldevs(alldevsp);
    return 0;
}

/**
 * Function loads command line options into opts structure using getopt_long() function.
 *
 * @return 0 if successful, 1 if an error occurred, 2 if the help option is present
 */
int load_opts(options_t *opts, int argc, char *argv[]) {
    // initialise the structure with default values
    opts->interface = nullptr;
    opts->port = -1;    // default value = all ports
    opts->tcp = 0;      // default value = 0 (means not present)
    opts->udp = 0;
    opts->arp = 0;
    opts->icmp = 0;
    opts->num = 1;      // default value = 1

    // define variables used in getopt_long() function
    opterr = 0;     // suppress default error messages
    char optstring[] = ":i::p:tun:h";
    struct option  longopts[]= {
            {"help", no_argument, nullptr, 'H'},
            {"interface", optional_argument, nullptr, 'I'},
            {"tcp", no_argument, nullptr, 'T'},
            {"udp", no_argument, nullptr, 'U'},
            {"arp", no_argument, nullptr, 'A'},
            {"icmp", no_argument, nullptr, 'M'},
            {0, 0, 0, 0}
    };
    int longindex;

    // parse the command line options using getopt_long() function
    int res;
    while ((res = getopt_long(argc, argv, optstring, longopts, &longindex)) != -1) {
        switch (res) {
            case 'h': case 'H':     // help
                // help will be printed in main() - returns 2
                return 2;
            case 'i': case 'I':     // interface
                // check if interface was already specified
                if (opts->interface != nullptr) {
                    fprintf(stderr, "specify one interface (-i/--interface) only\n");
                    return 1;
                }
                /* The following if statement is inspired by article:
                 * Author: Lars Erik Wik
                 * Article: Optional arguments with getopt_long(3) [online]
                 * Date: August 13, 2021
                 * Cited: April 23, 2022
                 * Availability: https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
                 */
                if (optarg == nullptr && optind < argc && argv[optind][0] != '-') {
                    optarg = argv[optind++];
                    // save name of the interface into opts structure
                    opts->interface = (char *)calloc(strlen(optarg) + 1, 1);
                    if (opts->interface == nullptr) {
                        fprintf(stderr, "allocation error\n");
                        return 1;
                    }
                    strcpy(opts->interface, optarg);
                }
                break;
            case 'p':       // port number
                // check if port was already specified
                if (opts->port !=-1) {
                    fprintf(stderr, "specify one port (-p) only\n");
                    return 1;
                }
                // convert string to number if valid
                try {
                    if (std::stoi(optarg) >= 0)
                        opts->port = std::stoi(optarg);
                    else
                        throw std::invalid_argument("");
                } catch (...) {
                    fprintf(stderr, "invalid port number in command line options\n");
                    free(opts->interface);
                    return 1;
                }
                break;
            case 't': case 'T':     // TCP protocol
                opts->tcp = 1;
                break;
            case 'u': case 'U':     // UDP protocol
                opts->udp = 1;
                break;
            case 'A':               // ARP protocol
                opts->arp = 1;
                break;
            case 'M':               // ICMP or ICMPv6 protocol
                opts->icmp = 1;
                break;
            case 'n':               // number of packets to be displayed
                // check if more n options was specified
                if (opts->num != 1) {
                    fprintf(stderr, "specify one -n only\n");
                    return 1;
                }
                // convert string to number if valid
                try {
                    if (std::stoi(optarg) >= 0)
                        opts->num = std::stoi(optarg);
                    else
                        throw std::invalid_argument("");
                } catch (...) {
                    fprintf(stderr, "invalid number in command line options\n");
                    free(opts->interface);
                    return 1;
                }
                break;
            default:        // unknown command line option
                printf("error in command line options (see -h or --help for help)\n");
                free(opts->interface);
                return 1;
        }
    }
    return 0;   // successful
}

/**
 * Function prints the formatted frame data to the standard output.
 * Format of one line:
 * 0x0000  xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  ........ ........
 * xx - hexadecimals, . - characters (non-printable character is printed as '.')
 *
 * @param length frame length
 * @param frame frame data
 */
void print_frame(size_t length, const u_char *frame) {
    size_t n = 0;       //  printed lines counter
    size_t i = 0;       // position to be printed in the frame data string
    size_t full_rows = length - (length % FRAME_PRINT_LEN); // number of rows with 16 characters
    size_t j;           // loop counter

    // print all rows with length == 16 characters (FRAME_PRINT_LEN)
    while (n < full_rows) {
        // print one row
        // print hexadecimals
        printf("0x%04lx:  ", n);
        for (unsigned k = 0; k < 2; k++) {
            for (j = 0; j < FRAME_PRINT_LEN/2; j++) {
                printf("%02x ", frame[i++]);
            }
            printf(" ");
        }
        // print characters
        i = i - FRAME_PRINT_LEN;
        for (unsigned k = 0; k < 2; k++) {
            for (j = 0; j < FRAME_PRINT_LEN/2; j++) {
                if (isprint(frame[i])) {
                    printf("%c", frame[i]);
                } else {
                    printf(".");
                }
                i++;
            }
            printf(" ");
        }
        n = n + FRAME_PRINT_LEN;
        printf("\n");
    }
    // print last row
    printf("0x%04lx:  ", n);
    while (i < length) {
        printf("%02x ", frame[i++]);
    }
    for (size_t num_of_spaces = 0; num_of_spaces < FRAME_PRINT_LEN - (length % FRAME_PRINT_LEN); num_of_spaces++) {
        printf("   ");
    }
    printf("  ");
    i = n;
    j = 0;
    while (i < length) {
        if (j++ == 8)
            printf(" ");
        if (isprint(frame[i])) {
            printf("%c", frame[i]);
        } else {
            printf(".");
        }
        i++;
    }
    printf("\n");
}

/**
 * Function prints more information about ARP packet. It prints sender and target
 * MAC addresses, sender and target IP addresses, opcode and frame data.
 *
 * @param header packet header
 * @param packet frame data
 */
void process_arp(struct pcap_pkthdr header, const u_char *packet) {
    printf("protocol: ARP\n");
    // cast frame data to ether_arp structure
    struct ether_arp *arp = (struct ether_arp*)(packet + ETH_HEADER_SIZE);

    // print opcode number
    if ((arp->ea_hdr.ar_op = htons(arp->ea_hdr.ar_op)) == 1)
        printf("opcode: 1 (request)\n");
    else if (arp->ea_hdr.ar_op == 2)
        printf("opcode: 2 (reply)\n");
    else
        printf("opcode: %hu\n", arp->ea_hdr.ar_op);
    // print sender and target MAC and IP addresses
    printf("sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
           arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
    printf("sender IP address: %d.%d.%d.%d\n",
           arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]);
    printf("target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2],
           arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
    printf("target IP address: %d.%d.%d.%d\n",
           arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], arp->arp_tpa[3]);
    // print frame data
    print_frame(header.caplen, packet);
}

/**
 * Function prints more information about UDP packet. It prints source
 * and destination ports, checksum and the frame data;
 *
 * @param header packet header
 * @param packet frame data
 * @param header_length length of the IP header
 */
void process_udp(struct pcap_pkthdr header, const u_char *packet, unsigned int header_length) {
    printf("protocol: UDP\n");
    // cast frame data to udphdr structure
    struct udphdr *udp = (struct udphdr *)(packet + header_length);

    // print source and destination ports
    printf("src port: %u\n", ntohs(udp->source));
    printf("dst port: %u\n", ntohs(udp->dest));
    // print checksum
    printf("checksum: 0x%04x\n", ntohs(udp->check));
    // print frame data
    print_frame(header.caplen, packet);
}

/**
 * Function prints more information about TCP packet. It prints source
 * and destination ports, checksum and frame data.
 *
 * @param header packet header
 * @param packet frame data
 * @param header_length length of the IP header
 */
void process_tcp(struct pcap_pkthdr header, const u_char *packet, unsigned int header_length) {
    printf("protocol: TCP\n");
    // cast frame data to tcphdr structure
    struct tcphdr *tcp = (struct tcphdr *)(packet + header_length);

    // print source and destination ports
    printf("src port: %u\n", ntohs(tcp->source));
    printf("dst port: %u\n", ntohs(tcp->dest));
    // print checksum
    printf("checksum: 0x%04x\n", ntohs(tcp->check));
    // print frame data
    print_frame(header.caplen, packet);
}

/**
 * Function prints more information about ICMP packet - type, code, checksum
 * and the frame data.
 *
 * @param header packet header
 * @param packet frame data
 * @param header_length length of the IP header
 */
void process_icmp(struct pcap_pkthdr header, const u_char *packet, unsigned int header_length) {
    // cast to icmphdr structure
    struct icmphdr *icmp = (struct icmphdr *)(packet + header_length);

    // print type, code, checksum and frame data
    if (icmp->type == 0)
        printf("type: 0 (Echo reply)\n");
    else if (icmp->type == 8)
        printf("type: 8 (Echo request)\n");
    else
        printf("type: %d\n", icmp->type);
    printf("code: %d\n", icmp->code);
    printf("checksum: 0x%04x\n", ntohs(icmp->checksum));
    print_frame(header.caplen, packet);
}

/**
 * Function processes IPv4 packet. It checks the header length and IP version,
 * prints IP addresses and call appropriate function to print more information.
 *
 * @param header packet header
 * @param packet packet data
 */
void process_ipv4(struct pcap_pkthdr header, const u_char *packet) {
    struct ip *ip = (struct ip*)(packet + ETH_HEADER_SIZE);       // IP header
    // check the IP header length and IP version number
    if (ip->ip_hl * 4 < 20 || ip->ip_v != 4) {
        printf("packet with invalid header catched\n");
        pcap_breakloop(pcap);
        return;
    }
    // print source and destination IP addresses
    printf("src IP: %s\n", inet_ntoa(ip->ip_src));
    printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));

    // check protocol type (TCP/UDP/ICMP) and print more information
    if (ip->ip_p == TCP)
        process_tcp(header, packet, ETH_HEADER_SIZE + (ip->ip_hl * 4));
    else if (ip->ip_p == UDP)
        process_udp(header, packet, ETH_HEADER_SIZE + (ip->ip_hl * 4));
    else if (ip->ip_p == ICMPv4) {
        printf("protocol: ICMP\n");
        process_icmp(header, packet, ETH_HEADER_SIZE + (ip->ip_hl * 4));
    }
}


/**
 * Function processes IPv6 packet. It prints IP addresses, checks what the
 * next header number is and loops through the extension headers if present.
 * It calls appropriate functions to process the protocols (TCP, UCP, ICMPv6).
 * If an error occurs, it calls pcap_breakloop() function, which breaks
 * pcap_loop(), that is sniffing the packets.
 *
 * @param header packet header
 * @param packet frame data
 */
void process_ipv6(struct pcap_pkthdr header, const u_char *packet) {
    // create a structure from the packet string
    struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + ETH_HEADER_SIZE);

    // process IP addresses
    char ip6address[INET6_ADDRSTRLEN] = "\0";   // stores the IP addresses in the right format
    const char *ip6address_res;                 // stores the pointer returned from convert function

    // get the src IP address
    if ((ip6address_res = inet_ntop(AF_INET6, &(ip6->ip6_src), ip6address, INET6_ADDRSTRLEN)) == nullptr) {
        fprintf(stderr, "inet_ntop: %s\n", strerror(errno));
        pcap_breakloop(pcap);
        return;
    }
    // print the src IP address
    printf("src IP: %s\n", ip6address_res);

    // get the dst IP address
    if ((ip6address_res = inet_ntop(AF_INET6, &(ip6->ip6_dst), ip6address, INET6_ADDRSTRLEN)) == nullptr) {
        fprintf(stderr, "inet_ntop: %s\n", strerror(errno));
        pcap_breakloop(pcap);
        return;
    }
    // print the dst IP address
    printf("dst IP: %s\n", ip6address_res);

    // get the position where the next header is located
    size_t current_length = ETH_HEADER_SIZE + IPV6_HEADER_SIZE;

    // print next header number
    printf("next header: %d\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);

    // check if the next header is TCP/UDP/ICMPv6 and process it
    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == TCP) {
        process_tcp(header, packet, current_length);
        return;
    } else if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == UDP) {
        process_udp(header, packet, current_length);
        return;
    } else if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == ICMPv6) {
        printf("protocol: ICMPv6\n");
        process_icmp(header, packet, current_length);
        return;
    }

    // the next header is some extension headers - create a structure for extension header
    struct ip6_ext *ext = (struct ip6_ext *)(packet + current_length);

    // loop to get through all the extension headers and try to find TCP/UDP/ICMPv6
    while (current_length < header.caplen) {
        if (ext->ip6e_nxt == TCP) {
            process_tcp(header, packet, current_length);
            return;
        }else if (ext->ip6e_nxt == UDP) {
            process_udp(header, packet, current_length);
            return;
        } else if (ext->ip6e_nxt == ICMPv6) {
            process_icmp(header, packet, current_length);
            return;
        }

        // add current extension header's length to the current length
        current_length += ext->ip6e_len;

        // there is another extension header
        // load the next extension header to the ext structure
        ext = (struct ip6_ext *)(packet + current_length);

        // print next header number
        printf("next header: %d\n", ext->ip6e_nxt);

        // if the extension header's next header is NO_NEXT_HEADER break the loop
        if (ext->ip6e_nxt == NO_NEXT_HEADER || ext->ip6e_len == 0) {
            break;
        }
    }
}

/**
 * Function creates a filter for filtering the packets. How the filter is created
 * depends on command line arguments (stored in opts structure).
 *
 * @param opts structure that stores command line options
 * @param fp pointer to the compiled filter expression
 * @return true if successful, false if an error occurred
 */
bool make_filter(options_t *opts, struct bpf_program *fp) {
    // create a string for the filter
    std::string filter;
    unsigned len = 0;

    // check if all command line options for protocols are disabled (tcp, udp, arp, icmp)
    if (opts->arp == 0 && opts->icmp == 0 && opts->tcp == 0 && opts->udp == 0) {
        // enable all of these protocols
        opts->arp = 1;
        opts->icmp = 1;
        opts->tcp = 1;
        opts->udp = 1;
    }

    // if port is enabled and TCP or UDP is not specified -> enable TCP and UDP
    if (opts->port >= 0 && opts->tcp == 0 && opts->udp == 0) {
        opts->tcp = 1;
        opts->udp = 1;
    }

    // check what protocols are enabled and create a filter for them
    if (opts->udp) {
        filter.append("udp");
        // add port option if enabled
        if (opts->port >= 0)
            filter.append(" port ").append(std::to_string(opts->port));
        len++;
    }
    if (opts->tcp) {
        if (len > 0)
            filter.append(" or ");
        // add port option if enabled
        filter.append("tcp");
        if (opts->port >= 0)
            filter.append(" port ").append(std::to_string(opts->port));
        len++;
    }
    if (opts->icmp) {
        if (len > 0)
            filter.append(" or ");
        filter.append("icmp or icmp6");
        len++;
    }
    if (opts->arp) {
        if (len > 0)
            filter.append(" or ");
        filter.append("arp");
    }

    // compile and set the filter to pcap
    if (pcap_compile(pcap, fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile: invalid filter string\n");
        return false;
    }
    if (pcap_setfilter(pcap, fp) == -1) {
        fprintf(stderr, "pcap_setfilter: Error.\n");
        return false;
    }
    return true;
}

/**
 * Function handler for handling SIGINT signal. Handler breaks the loop that is
 * sniffing packets -> resources are released and the programme exits after that.
 * Global variable sigint_received indicates that the loop in main() must end.
 *
 * @param signum signal identifier required by handler function, not used
 */
void handle_signal(int signum) {
    (void)signum;           // signum is not used here -> remove compiler warning
    sigint_received = 1;    // indicates that SIGINT was received
    pcap_breakloop(pcap);   // break the sniffing loop
}

/**
 * Function releases all of the allocated resources.
 *
 * @param fp compiled filter
 * @param opts structure that stores command line options
 */
void release_resources(struct bpf_program fp, options_t *opts) {
    pcap_close(pcap);           // global pcap handler
    pcap_freecode(&fp);         // compiled filter
    free(opts->interface);  // options structure - interface string
    free(opts);             // options structure
}

/**
 * Callback function that is called by pcap_loop() if a packet is sniffed.
 * Function processes one frame. It prints RFC3339 timestamp, source MAC address,
 * destination MAC address and frame length. By the EtherType is decided what
 * protocol should be processed and appropriate function is called to print
 * more information about the packet.
 *
 * @param args mandatory argument of the callback function, not used in this function
 * @param header packet header structure
 * @param packet frame data
 */
void process_frame(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;     // args parameter is not used in this function -> remove compiler warning

    // create an ethernet header structure
    struct ether_header *eth = (struct ether_header *)(packet);

    // count and print RFC3339 timestamp
    char ts_buf[MAX_TIMESTAMP_LEN];
    struct tm *tm = localtime(&(header->ts.tv_sec));
    if (tm == nullptr) {
        fprintf(stderr, "localtime: %s\n", strerror(errno));
        pcap_breakloop(pcap);
        return;
    }
    // get YYYY-MM-DDTHH:MM:SS from tm
    if (strftime(ts_buf, 100, "%FT%T.", tm) == 0) {
        fprintf(stderr, "main: Invalid timestamp\n");
        pcap_breakloop(pcap);
        return;
    }
    printf("%s", ts_buf);

    // count and print milliseconds (time in milliseconds == seconds * 1000)
    snprintf(ts_buf, MAX_TIMESTAMP_LEN - 1, "%lld", header->ts.tv_sec*1000LL + header->ts.tv_usec/1000);
    size_t len = strlen(ts_buf);
    printf("%c%c%c", ts_buf[len-3], ts_buf[len-2], ts_buf[len-1]);

    // count and print time zone offset
    long tz_off = tm->tm_gmtoff / 3600;
    if (tz_off >= 0)
        printf("+%02lu.00\n", tz_off);
    else
        printf("-%02lu.00\n", (-tz_off));

    // print src MAC address
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    // print dst MAC address
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    // print frame length
    printf("frame length: %d\n", header->caplen);

    // get etherType
    eth->ether_type = ntohs(eth->ether_type);
    // process and print the packet
    if (eth->ether_type == ARP)
        process_arp(*header, packet);
    else if (eth->ether_type == IPv4)
        process_ipv4(*header, packet);
    else if (eth->ether_type == IPv6)
        process_ipv6(*header, packet);
    printf("\n");
}

/**
 * Main function.
 * Function loads command line options and sets the signal handling.
 * Depending on what the options are then prints help, prints a list
 * of active devices or starts sniffing packets.
 * If an error occurred error message is printed to standard error (stderr).
 *
 * @param argc command line argument count
 * @param argv command line argument vector
 * @return 0 if the program ends successfully
 *         1 if an error occurred
 */
int main(int argc, char *argv[]) {
    int res;                    // variable used for storing results from functions
    sigint_received = 0;        // global variable - 0 means SIGINT signal wasn't caught
    int link_layer_header_type; // number of link-layer header type

    // create opts structure for storing command line options
    options_t *opts = (options_t *)malloc(sizeof (options_t));
    if (opts == nullptr) {
        fprintf(stderr, "malloc: allocation error\n");
        return 1;
    }
    // load command line options to the opts structure
    if ((res = load_opts(opts, argc, argv)) != 0) {
        // free allocated resources
        if (opts->interface != nullptr)
            free(opts->interface);
        free(opts);
        // if help was printed - return 0
        if (res == 2) {
            print_help();
            return 0;
        }
        // error occurred - return 1
        return 1;
    }

    // if interface wasn't specified print all active interfaces and exit
    if (opts->interface == nullptr) {
        free(opts);
        return print_interfaces();
    }

    // exit if no packets should be printed
    if (opts->num == 0) {
        free(opts->interface);
        free(opts);
        return 0;
    }

    // create SIGINT handler
    struct sigaction sigint_handler;
    sigint_handler.sa_handler = handle_signal;
    sigemptyset(&sigint_handler.sa_mask);
    sigint_handler.sa_flags = 0;
    sigaction(SIGINT, &sigint_handler, nullptr);

    // repeat the following loop until link-layer header type isn't equal to Ethernet
    // or until SIGINT wasn't received
    do {
        // create pcap handle
        pcap = pcap_create(opts->interface, errbuf);
        if (pcap == nullptr) {
            fprintf(stderr, "pcap_create: %s", errbuf);
            free(opts->interface);
            free(opts);
            return 1;
        }

        // set timeout
        pcap_set_timeout(pcap, 100);
        // set promiscuous mode
        pcap_set_promisc(pcap, 1);

        // activate the pcap handle
        res = pcap_activate(pcap);
        if (res != 0) {
            fprintf(stderr, "pcap_activate: %s\n", pcap_statustostr(res));
            pcap_close(pcap);
            free(opts->interface);
            free(opts);
            return 1;
        }

        // get the link-layer header type
        // list of link types: https://www.tcpdump.org/linktypes.html
        link_layer_header_type = pcap_datalink(pcap);
        if (link_layer_header_type != DLT_EN10MB) {
                pcap_close(pcap);
        }
    } while (link_layer_header_type != DLT_EN10MB && !sigint_received);

    // if SIGINT was received -> release resources and exit
    if (sigint_received) {
        fprintf(stderr, "Interrupted system call\n");
        if (pcap_activate(pcap) != PCAP_ERROR_ACTIVATED)
            pcap_close(pcap);
        free(opts->interface);
        free(opts);
        return 1;
    }

    // create a filter
    struct bpf_program fp;  // structure used for the compiled filter
    if (!make_filter(opts, &fp)) {
        release_resources(fp, opts);
        return 1;
    }

    // process opts->num packets -> print information about every packet
    if (pcap_loop(pcap, opts->num, process_frame, NULL) != 0) {
        // fewer packets were processed
        fprintf(stderr, "pcap_loop: %s\n", strerror(errno));
    }

    // release resources and exit
    release_resources(fp, opts);
    return 0;
}
