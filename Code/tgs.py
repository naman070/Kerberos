# Naman Gupta (2017070)
# Porvil (2017304)

import AES
import socket
from hashlib import sha256
import base64
from datetime import datetime,timedelta
import pickle
import json
import functions
from random import randint
import uuid

def recvmsg(clientsocket):
	msg = clientsocket.recv(2**10)
	info = pickle.loads(msg)
	return info

def sendmsg(message):
	msg = pickle.dumps(message)
	clientsocket.send(msg)

def response(kctgs,auth):
	idc = auth['idc']
	adc = auth['adc']
	ts4,lt4 = functions.timeterms()

	string_v = uuid.uuid4().hex[:6].lower()
	# print(string_v)
	kcv = functions.generatePassword(string_v)
	ticket = {"kcv":kcv,"idc":idc,"adc":adc,"idv":idv,"ts4":str(ts4),"lt4":str(lt4)}

	kv = functions.generatePassword("Vsecret")
	keyv = AES.generateKey(kv)

	encrypted_ticket = functions.dict_encryption(ticket,keyv)

	final_pkg = {"kcv":kcv,"idv":idv,"ts4":str(ts4),"ticketv":encrypted_ticket.decode()}
	return final_pkg


s = socket.socket()
host = socket.gethostname()
port = 8002
s.bind((host,port))
s.listen(5)
iterator = 0

clientsocket,address = s.accept()
print(f"Connection from {address} has been established")
idtgs = 1101
ktgs = functions.generatePassword("TGSsecret")
keytgs = AES.generateKey(str(ktgs))


while True:
	try:
		package = recvmsg(clientsocket)
		print("Message received from client")
		# print(package,"\n")
		ticket_tgs_bytes = AES.decrypt(package['ticket_tgs'],keytgs)
		ticket_tgs = json.loads(ticket_tgs_bytes.decode())
		kctgs = ticket_tgs['kctgs']
		keyctgs = AES.generateKey(kctgs)

		authc = functions.getauth(kctgs,package['authenticatorC'])
		if(not functions.checkTimestamp(authc['ts'])):
			if(functions.verify(authc,ticket_tgs)):
				idv = package['idv']
				resp = response(kctgs,authc)
				# print("Message before encryption\n",resp,"\n")
				resp_to_send = functions.dict_encryption(resp,keyctgs)
				sendmsg(resp_to_send)
				print("Encrypted message sent back to the client")
				# print(resp_to_send)


			else:
				print("Breach detected!!")



		else:
			print("Taking too long to respond")

	except:
		print("TGS has closed down")
		break



