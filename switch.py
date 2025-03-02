#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# global variables for stp algorithm
root_bridge_id = 0
own_bridge_id = 0
root_port = -1
path_cost = 0
interfaces = []
port_vlan = {}
port_states = {}
designated_ports = []

def create_bpdu(root_bridge_id, sender_bridge_id, path_cost):
    dest_mac = bytes([0x01, 0x80, 0xc2, 0, 0, 0])
    return (dest_mac + get_switch_mac() + struct.pack("!H", root_bridge_id) + struct.pack("!H", sender_bridge_id) + struct.pack("!H", path_cost))

def receive_bpdu(interface, data, length):
    global root_bridge_id, path_cost, root_port, port_states, designated_ports
    # Unpack the BPDU fields from the byte array
    root_bridge_ID, port_bridge_ID, path_to_root_cost = struct.unpack("!3H", data[12:18])
    
    # If the received BPDU is better than the current one
    if root_bridge_ID < root_bridge_id:
        root_bridge_id = root_bridge_ID
        path_cost = path_to_root_cost + 10
        root_port = interface
        if own_bridge_id == root_bridge_id:
            for port in interfaces:
                if port != interface and port_vlan[get_interface_name(port)] == "T":
                    port_states[port] = "BLOCKING"
                    if port in designated_ports:
                        designated_ports.remove(port)
        
        if port_states[root_port] == "BLOCKING":
            port_states[root_port] = "LISTENING"
        
        new_data = create_bpdu(root_bridge_ID, own_bridge_id, path_cost)
        for port in interfaces:
            if port != interface and port_vlan[get_interface_name(port)] == "T":
                send_to_link(port, len(new_data), new_data)

    elif root_bridge_ID == root_bridge_id:
        if interface == root_port and port_bridge_ID + 10 < path_cost:
            path_cost = path_to_root_cost + 10
        elif interface != root_port:
            if path_to_root_cost > path_cost:
                if interface not in designated_ports:
                    port_states[interface] = "LISTENING"
                    designated_ports.append(interface)

    elif port_bridge_ID == own_bridge_id:
        port_states[interface] = "BLOCKING"
        if interface in designated_ports:
            designated_ports.remove(interface)
    
    if own_bridge_id == root_bridge_id:
        for port in interfaces:
            if port != root_port and port_vlan[get_interface_name(port)] == "T":
                designated_ports.append(port)
                port_states[port] = "LISTENING"

def get_active_interfaces():
    return [i for i in interfaces if port_states[i] != "BLOCKING"]

def is_unicast(mac):
    least = int(mac.split(":")[0], 16)
    # if the least significant bit of the first byte is 0, then it is a unicast address
    return (least & 0x01) == 0

def is_multicast(mac: str) -> bool:
    first_octet = int(mac.split(":")[0], 16)
    # if the least significant bit of the first byte is 1, then it is a multicast address
    return (first_octet & 0x01) == 1

def send_packet_vlan(interface, data, length, port_vlan, vlan_id, vlan_in):
    vlan_out = port_vlan[get_interface_name(interface)]

    # If the outgoing port is a trunk port
    if vlan_out == "T":
        # If the incoming port is an access port
        if vlan_id == -1:
            data = data[:12] + create_vlan_tag(vlan_in) + data[12:]
        send_to_link(interface, len(data), data)

    # If the outgoing port is an access port
    elif int(vlan_out) == vlan_in:
        # If the incoming port is a trunk port
        if vlan_id != -1:
            data = remove_vlan_tag(data)
        send_to_link(interface, len(data), data)

def create_vlan_tag(vlan_id):
    tpid = 0x8200
    vlan_tci = vlan_id & 0x0FFF
    vlan_tag = struct.pack('!HH', tpid, vlan_tci)
    return vlan_tag

def remove_vlan_tag(data):
    return data[:12] + data[16:]    

def get_ports_data(switch_id):
    global own_bridge_id, root_bridge_id, port_vlan
    filename = f"configs/switch{switch_id}.cfg"

    with open(filename, "r") as f:
        lines = f.readlines()
        own_bridge_id = int(lines[0].strip())
        root_bridge_id = own_bridge_id
        for line in lines[1:]:
            parts = line.strip().split(" ")
            port = parts[0]
            vlan_type = parts[1]
            port_vlan[port] = vlan_type

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        if own_bridge_id == root_bridge_id:
            for port in interfaces:
                if port_vlan.get(get_interface_name(port), -1) == "T":
                    new_data = create_bpdu(root_bridge_id, own_bridge_id, 0)
                    send_to_link(port, len(new_data), new_data)
        time.sleep(1)

def main():
    global interfaces, port_states
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    MAC_table = {}
    
    get_ports_data(switch_id)
    port_states = {i: "BLOCKING" if port_vlan[get_interface_name(i)] == "T" else "LISTENING" for i in interfaces}

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning

        MAC_table[src_mac] = interface

        # Check if the frame is a BPDU
        if (is_multicast(dest_mac)):
            receive_bpdu(interface, data, length)
            continue

        # Save the VLAN ID of the incoming frame
        if vlan_id != -1:
            vlan_in = vlan_id
        else:
            vlan_in = int(port_vlan[get_interface_name(interface)])

        # Send the frame to unique MAC address if it is in the MAC table
        if is_unicast(dest_mac):
            if dest_mac in MAC_table:
                send_packet_vlan(MAC_table[dest_mac], data, length, port_vlan, vlan_id, vlan_in)
            else:
                # Flood the frame to all interfaces except the incoming one
                for port in get_active_interfaces():
                    if port != interface:
                        send_packet_vlan(port, data, length, port_vlan, vlan_id, vlan_in)
        else:
            # Broadcast the frame to all interfaces except the incoming one
            for port in get_active_interfaces():
                if port != interface:
                    send_packet_vlan(port, data, length, port_vlan, vlan_id, vlan_in)

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
