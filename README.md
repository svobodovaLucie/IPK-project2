## IPK - project 2 (ZETA): Packet sniffer
Author: Lucie Svobodová, xsvobo1x@stud.fit.vutbr.cz  
Institution: FIT BUT  
Academic year: 2021/2022  
Course: IPK - Computer Communications and Networks  

Evaluation: 20/20 points  

Packet sniffer for analysing TCP, UDP, ICMP, ICMPv6 and ARP packets. These packets can be filtered using various options. The application is implemented in C++ language using the Packet Capture library ([PCAP](https://www.tcpdump.org/)).

### Build

Before building the project make sure you have installed The Packet Capture library (see [libpcap](https://www.tcpdump.org/)).  

To build the project use command:
```shell
$ make
```

To remove executable files use: 
```shell
$ make clean
```

### Usage

The packet sniffer supports various command line options:

```shell
$ ./ipk-sniffer [-i intrfc | --interface intrfc ] {-p port} {[--tcp | -t] [--udp | -u] [--arp] [--icmp]} {-n num}
```

- `i intrfc`/`interface intrfc` - interface to listen
  - if no interface is specified, the application prints all available interfaces
- `p port` - port
  - if this option is not specified, the sniffer is listening on all ports
  - if this option is specified, the sniffer filters packets on this port (source or destination port)
- `t`/`tcp` - filters TCP packets
- `u`/`udp` - filters UDP packets
- `icmp` - filters ICMP packets
- `arp` - filters ARP packets
- `n num` - number of packets to be displayed
  - implicit value for this option is `1`

If the option `i`/`interface` is not specified the application prints all the available interfaces and exits.  
If no protocol option (`t`/`tcp`, `u`/`udp`, `icmp`, `arp`) is specified the packet sniffer displays all of these packets that are sniffed.  

### Usage examples
```shell
# prints all available interfaces
$ ./ipk-sniffer

# prints information about one packet sniffed on wlo1 interface
$ ./ipk-sniffer -i wlo1

# prints 3 ARP packets sniffer on wlo1 interface
$ ./ipk-sniffer --interface wlo1 --arp -n 3

# prints 5 packets with TCP or UDP protocol that were sniffed on port 443 on wlo1 interface
$ ./ipk-sniffer -i wlo1 -n 5 -p 443 --tcp --udp

# prints 100 packets that were sniffed on interface wlo1 with ICMP protocol or packets with UDP or TMP protocol sniffed on port 443
$ ./ipk-sniffer -i wlo1 -n 100 -p 443 --icmp
```

### Example output
Packet sniffer prints information about sniffed packets - timestamp, source and destination MAC and IP addresses,
source and destination ports if available, frame lengths, information specific for the protocols and all the frame data.  
```shell
# prints all available interfaces
$ ./ipk-sniffer -i
wlo1
lo
any
bluetooth-monitor
nflog
nfqueue
bluetooth0

# prints two packets sniffed on interface wlo1 on port 80
$ ./ipk-sniffer -i wlo1 -n 2 -p 443
2022-04-24T10:49:26.626+02.00
src MAC: 62:32:b1:09:04:6b
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 56
protocol: ARP
opcode: 1 (request)
sender MAC address: 62:32:b1:09:04:6b
sender IP address: 192.168.0.17
target MAC address: 00:00:00:00:00:00
target IP address: 192.168.0.1
0x0000:  ff ff ff ff ff ff 62 32  b1 09 04 6b 06 08 00 01  ......b2 ...k.... 
0x0010:  08 00 06 04 01 00 62 32  b1 09 04 6b c0 a8 00 11  ......b2 ...k.... 
0x0020:  00 00 00 00 00 00 c0 a8  00 01 00 00 00 00 00 00  ........ ........ 
0x0030:  00 00 00 00 00 00 00 00                           ........

2022-04-24T10:49:29.392+02.00
src MAC: dc:53:7c:27:9f:48
dst MAC: c0:3c:59:cf:34:33
frame length: 93
src IP: 34.120.52.64
dst IP: 192.168.0.110
protocol: TCP
src port: 443
dst port: 43098
checksum: 0xf546
0x0000:  c0 3c 59 cf 34 33 dc 53  7c 27 9f 48 00 08 45 00  .<Y.43.S |'.H..E. 
0x0010:  00 4f 14 dd 00 00 78 06  15 fe 22 78 34 40 c0 a8  .O....x. .."x4@.. 
0x0020:  00 6e 01 bb a8 5a f8 ee  6a 1b 79 0e 61 c1 80 18  .n...Z.. j.y.a... 
0x0030:  04 1a f5 46 00 00 01 01  08 0a 5e e7 6a b8 d1 8a  ...F.... ..^.j... 
0x0040:  2b 90 17 03 03 00 16 89  fe 5c 81 6d 14 09 b7 a4  +....... .\.m.... 
0x0050:  6f 65 b5 20 8a 31 76 fb 59 92 e3 75 d8            oe. .1v. Y..u.
```

### Licence

[MIT license](https://choosealicense.com/licenses/mit/)
