# Network Scanning tool | August 23, 2025

"""
- Network scanner:
    - software tool that can scan a network for devices that are connected to it
    - Can be used for investigation for security purposes
    - This tool can take an IP address or a range of IP addresses as input and then scans each IP addresses sequentially and determines 
      whether a device is present on the specified IP address or not. 

    - Similar to nmap it will scan the network of ip addresses and returns an IP address and its corresponding MAC address if the device is pressent.

    - MODULES NEEDED:   
        - argparse
        - Scapy; Enables users to send, sniff and dissect and forge network packets. This will allow a creation of tools that
          can probe, scan, or attack networks


"""

import argparse 
import scapy.all as scapy 


# Add command line arguemens function 

def cmd_arg():

    parsarg = argparse.ArgumentParser()
    parsarg.add_argument('-t', '--target', dest='target', help='Target IP Address/Addresses')
    args = parsarg.parse_args()

    # Apply error handling if user does not specify the needed target address 
    # exit program with an error message if the arg is not specified 

    if not args.target:
        parsarg.error("[-] A specified target IP Address or Addresses is needed, use '--help' for more info")
    return args



# Add scanner function 

def scanner(IP):
    # Create a ARP request using scapy ARP class with the destination IP address (pdst)
    arp_req = scapy.ARP(pdst = IP) 

    # set ehternet frame using the MAC address format since its a MAC address we want to communicate with
    # the ARP request is needed to be broadcast to the entire network, thus broadcast the ARP request to dst address which in MAC address
    eth_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")

    # scapy allow combination by division 
    # this will allow us to see the functional output for the scapy ARP request and response for ARP and ethernet
    eth_arp_req = eth_frame/arp_req


    # Use srp() to capture the responses in a tuple
    # First elemnt of the tuple holds the intended response and the rest are unanswered response
    # allow scapy a mininum of 1 sec of response wait time. If not responded then the it will move futher to send 
    # the packet to the next IP address
    responses = scapy.srp(eth_arp_req, timeout = 1, verbose = False)[0]

    # Create a list to store the results of the responses 
    # Ctreate a dictionary that holds the IP address and MAC address for the list of the response 
    result = []
    for i in range(0,len(responses)):
        Target_dict = {"IP" : responses[i][1].psrc, "MAC" : responses[i][1].hwsrc}
        result.append(Target_dict)

    return result


def show_result(result):
    print("-----------------------------\nIP Address\tMAC Address\n-----------------------------")
    for i in result:
        print("{}\t{}".format(i["IP"], i["MAC"]))


args = cmd_arg()
scanner_show = scanner(args.target)
show_result(scanner_show)










