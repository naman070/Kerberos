# Naman Gupta (2017070)
# Porvil (2017304)

import AES
import socket
from hashlib import sha256
import base64
from datetime import datetime,timedelta
import database as db
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


def response(package,address):
	ts2,lt2 = functions.timeterms()
	idc = package["idc"]
	adc = address[0]
	stringtgs = uuid.uuid4().hex[:6].lower()
	# print(stringtgs)
	kctgs = functions.generatePassword(stringtgs)
	ticket = {"kctgs": kctgs, "idc":idc, "adc":adc, "idtgs":idtgs,"ts2":str(ts2),"lt2":str(lt2)}
	
	ktgs = functions.generatePassword("TGSsecret")
	keytgs = AES.generateKey(ktgs)

	encrypted_ticket = functions.dict_encryption(ticket,keytgs)

	final_pkg = {"kctgs":kctgs,"idtgs":idtgs,"ticket_tgs":encrypted_ticket.decode(),"ts2":str(ts2),"lt2":str(lt2)}
	return final_pkg

	
def clientKey(idc):
	val = db.searchDatabase(idc)
	password = ""
	if(val==-1):
		print("User not found!!!")
	else:
		password = str(val[1])

	keyc = AES.generateKey(password)
	return keyc


s = socket.socket()
host = socket.gethostname()
port = 8001
s.bind((host,port))
s.listen(5)

clientsocket,address = s.accept()
print(f"Connection from {address} has been established")
idtgs = 1101

while True:
	try:
		package = recvmsg(clientsocket)
		print("Packet received from client\n")
		resp = response(package,address)

		resp_to_send = functions.dict_encryption(resp,clientKey(package["idc"]))
		sendmsg(resp_to_send)
		print("Message sent to the client")

	except:
		print("AS has closed down")
		break



