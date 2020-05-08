# Naman Gupta (2017070)
# Porvil (2017304)

import socket
import base64
import getpass
import pickle
from datetime import datetime,timedelta
from hashlib import sha256
import AES
import json
import functions
import codecs
import webbrowser,os

def sendmsg(message,socket):
	msg = pickle.dumps(message)
	socket.send(msg)

def recvmsg(socket):
	msg = socket.recv(2**15)
	recv = pickle.loads(msg)
	return recv


def authenticator(keyS,idc,adc):
	ts = str(datetime.now())
	key = AES.generateKey(keyS)
	authc = {"idc":idc,"adc":adc,"ts":ts}
	encrypted_auth = functions.dict_encryption(authc,key)
	return encrypted_auth

def generateHtml(text):
	filename = "homepage.html"
	file = codecs.open(filename,"w")
	file2 = file.write(text)
	return filename


def client_has_key(idc):
	if idc in clientInfo.keys():
		return True

	else:
		return False


def download_homepage(idc,flag):
	keycv = clientInfo[idc]['keycv']
	if(not flag):
		msg_to_send = AES.encrypt(download_request,keycv)

	else:

		msg_to_send = AES.encrypt(str(idc),keycv)
	
	sendmsg(msg_to_send,s_v)
	msg_recv_v = recvmsg(s_v)
	if(msg_recv_v == "-1"):
		clientInfo[idc] = None
		print("Your session key has expired!!!")
	else:
		print("Homepage is downloaded.\n")
		msg_decode = (AES.decrypt(msg_recv_v,keycv))
		filename = generateHtml(msg_decode.decode())


def server_comm(idc):
	ticketv = clientInfo[idc]['ticketv']
	authc2 = clientInfo[idc]['authc2']
	kcv = clientInfo[idc]['kcv']

	msg_to_V = {"ticketv":ticketv,"authenticatorC": authc2}
	sendmsg(msg_to_V,s_v)
	print("Message sent to Application Server")

	v_msg_recv = recvmsg(s_v)
	keycv = AES.generateKey(kcv)
	final_msg = (AES.decrypt(v_msg_recv,keycv)).decode()
	print("This is the final_msg: ", final_msg)
		
	return final_msg


s = socket.socket()
host = socket.gethostname()
port_as = 8001
s.connect((host,port_as))

s_tgs = socket.socket()
port_tgs = 8002
s_tgs.connect((host,port_tgs))

s_v = socket.socket()
port_v = 8003
s_v.connect((host,port_v))

isRunning = True
idtgs = 1101

ip_add = socket.gethostbyname(host)
clientInfo = {}
download_request = "DownloadHome"

while isRunning:
	print("1) Run the Client")
	print("2) Exit")
	choice = int(input())
	if(choice == 1):
		idc = int(input("Enter the ClientID: "))
		password = getpass.getpass()
		hashed_password = functions.generatePassword(password)

		if(client_has_key(idc) and (clientInfo[idc] != None)):
			user_input = input("\nDo you want to download the homepage? (y/n): ")
			if(user_input == 'y' or user_input == 'Y'):
				download_homepage(idc,True)

			else:
				continue


		else:
			keyc = AES.generateKey(hashed_password)

			package = {"idc": idc, "idtgs":idtgs, "timestamp":functions.generateTimestamp()}
			sendmsg(package,s)
			print("Message sent to AS")

			msg_recv = recvmsg(s)
			print("Message received from AS")
			# print(msg_recv,"\n")
			ASresp = (AES.decrypt(msg_recv,keyc)).decode()
			ASpackage = json.loads(ASresp)
			kctgs = ASpackage['kctgs']
			keyctgs = AES.generateKey(kctgs)

			if(not functions.checkTimestamp(ASpackage['ts2'])):
				ticket = ASpackage['ticket_tgs']
				authenticatorC = authenticator(ASpackage['kctgs'],idc,str(ip_add))
				idv = 100
				msg_to_tgs = {"idv": idv, "ticket_tgs": ticket,"authenticatorC":authenticatorC}
				sendmsg(msg_to_tgs,s_tgs)
				print("\nMessage sent to TGS")

				tgs_msg_recv = recvmsg(s_tgs)
				print("Message received from TGS\n")
				# print(tgs_msg_recv,"\n")

				TGSresp = (AES.decrypt(tgs_msg_recv,keyctgs)).decode()
				TGSpackage = json.loads(TGSresp)

				if(not functions.checkTimestamp(TGSpackage['ts4'])):
					ticketv = TGSpackage['ticketv']
					kcv = TGSpackage['kcv']

					authc2 = authenticator(kcv,idc,str(ip_add))
					keycv = AES.generateKey(kcv)

					new_dict = {"ticketv":ticketv,"kcv":kcv,"authc2":authc2,'keycv':keycv}
					clientInfo[idc] = new_dict
					
					final_msg = server_comm(idc)
					take_input = input("\nDo you want to download the homepage of the webserver (y/n): ")
					if(take_input == 'y' or take_input == 'Y'):
						download_homepage(idc,False)

				else:
					print("Taking too much time to respond.")

			else:
				print("Taking too much time to respond.")

	else:
		isRunning = False


