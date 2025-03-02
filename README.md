# Ethernet Switch with STP and VLAN Support

## Overview
This project implements a software-based Layer 2 Ethernet switch that supports:
- **Spanning Tree Protocol (STP)** to prevent network loops.
- **MAC learning and forwarding** for efficient packet delivery.
- **VLAN tagging and untagging** to support network segmentation.

## Features
- **BPDU Handling**: Processes Bridge Protocol Data Units (BPDUs) to determine the best path in the network and block redundant links.
- **MAC Learning**: Dynamically builds a MAC address table to forward packets efficiently.
- **VLAN Support**: Handles tagged and untagged VLAN frames, supports both trunk and access ports.
- **Multithreading**: Uses a separate thread to send periodic BPDUs.
- **Packet Forwarding**: Learns MAC addresses and forwards packets based on VLAN and STP rules.
- 
## How It Works
1. **Initializes Interfaces**: Reads port configuration and sets up VLANs.
2. **Starts BPDU Thread**: If the switch is the root, it sends BPDUs every second.
3. **Processes Incoming Packets**:
   - **BPDU Packets**: Updates STP state and forwards BPDUs.
   - **Unicast Packets**: Forwards based on MAC learning.
   - **Broadcast/Unknown Packets**: Floods to active interfaces.
4. **Updates STP States**: Blocks redundant links based on received BPDUs.

## STP Implementation
- Ports can be in `BLOCKING` or `LISTENING` state.
- The switch elects the root bridge based on the lowest Bridge ID.
- The root port is selected based on the lowest path cost.
- Designated ports forward traffic, while blocked ports prevent loops.

## VLAN Handling
- **Trunk Ports (T)**: Forward frames with VLAN tags.
- **Access Ports**: Remove VLAN tags and only accept frames for a specific VLAN.
