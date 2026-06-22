
# Mini-Wireshark: Command-Line Network Packet Sniffer

## Overview
A lightweight, command-line network packet sniffer built in pure Python to demonstrate  packet inspection and TCP/IP protocol parsing. This tool does not use pre-built GUI applications and interacts directly with the network hardware to capture and decode raw binary network traffic and unpack it layer-by-layer.

## Usage
Download the file named Mini_Wireshark.py
Run the sniffer using Python. By default, it will capture all incoming and outgoing IPv4 traffic indefinitely.

```bash
python Mini_Wireshark.py
```
Run this command to see the available filtering options
```bash
python Mini_Wireshark.py -h
``` 
![](/Images/image.png)

Here's what a sample output looks like
![alt text](/Images/image-1.png)
Note - This script needs to run in administrator mode
## Technical debrief
* This project was built from scratch in pure Python using ```socket``` and ```struct```  libraries

* Raw sockets are configured to capture all network traffic at hardware-level promiscuous mode

* Captured raw binary network traffic is parsed layer-by-layer using the ```struct``` module.

* Big-Endian byte order is decoded to extract IPv4 headers, TCP/UDP ports, and ICMP data.

* The host machine's active internet-facing IP address is automatically resolved by a dummy UDP socket mechanism.

* Live traffic is filtered by protocol, IP, or packet limit using a dynamic command-line interface built with argparse

## Prerequisites
* **Python 3.x:** Only built-in libraries (`socket`, `struct`, `os`, `argparse`) are used. No external dependencies required!
* **OS:** Windows (The promiscuous mode implementation currently utilizes Windows-specific `ioctl` controls).
* **Administrator Privileges:** Raw sockets require deep system-level access to the network interface card (NIC). You must run your terminal/PowerShell as an Administrator.
