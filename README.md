# DHCP Server Implementation from Scratch

## Overview

This project involves the construction of a **Dynamic Host Configuration Protocol (DHCP)** server from scratch. The DHCP server dynamically assigns IP addresses and other network configuration parameters to devices on a network, allowing them to communicate efficiently. 

By building a DHCP server from the ground up, this project aims to provide a deep understanding of networking concepts, the DHCP protocol, and the process of automating IP address allocation.

---

## Features

- **Dynamic IP Allocation**: Automatically assigns IP addresses from a predefined range (IP pool) to clients.
- **Lease Management**: Manages IP lease durations and renewals.
- **Static IP Assignment**: Optionally reserves specific IP addresses for particular devices based on MAC addresses.
- **Configuration Management**: Provides a customizable configuration file to set up network ranges, lease times, and reserved addresses.
- **Error Handling**: Includes mechanisms for handling common errors like address exhaustion or invalid requests.

---

## Protocol Implementation

The server implements the following core DHCP protocol steps:

1. **DHCP Discover**: Detects broadcast requests from new clients.
2. **DHCP Offer**: Responds with an available IP address and configuration options.
3. **DHCP Request**: Receives confirmation from clients for the offered IP.
4. **DHCP Acknowledgment**: Finalizes the lease agreement and assigns the IP address.

---

## Prerequisites

Before running this project, ensure the following dependencies are installed:

- A compatible programming environment (e.g., Python, C++)
- Basic networking tools (e.g., Wireshark for debugging)
- Administrative access to the network (for binding to ports)

---

