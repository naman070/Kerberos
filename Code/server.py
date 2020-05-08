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
import time
import codecs

def recvmsg(clientsocket):
	msg = clientsocket.recv(2**10)
	info = pickle.loads(msg)
	return info

def sendmsg(message):
	msg = pickle.dumps(message)
	clientsocket.send(msg)


def prepareHtml():
	file = codecs.open("sample.html","r")
	file_read = file.read()
	return str(file_read)



def sendhomepage(clientsocket,keycv):
	req_recv = recvmsg(clientsocket)
	download_request = (AES.decrypt(req_recv,keycv)).decode()
	encrypted_text = ""
	if(download_request=="DownloadHome"):
		html_text = prepareHtml()
		encrypted_text = AES.encrypt(html_text,keycv)

	return encrypted_text



s = socket.socket()
host = socket.gethostname()
port = 8003
s.bind((host,port))
s.listen(5)

clientsocket,address = s.accept()
print(f"Connection from {address} has been established")
idv = 100
kv = functions.generatePassword("Vsecret")
keyv = AES.generateKey(str(kv))

clientInfo = {}

loop = True

while loop:
	try:
		package = recvmsg(clientsocket)
		print("Message received from the client")

		if(type(package) == type({})):
			ticket_v_bytes = AES.decrypt(package['ticketv'],keyv)
			ticketv = json.loads(ticket_v_bytes.decode())

			kcv = ticketv['kcv']
			idc = ticketv['idc']
			keycv = AES.generateKey(kcv)

			authc = functions.getauth(kcv,package['authenticatorC'])

			if(not functions.checkTimestamp(authc['ts'])):
				if(functions.verify(authc,ticketv)):
					print("User verified\n")
					ts5 = str(round(time.time())+1)
					msg_to_client = AES.encrypt(ts5,keycv)
					clientInfo[idc] = {'keycv':keycv,'lt':ticketv['lt4']}

					sendmsg(msg_to_client)	
					print("Encrypted Message sent back to the client")

					encrypted_homepage = sendhomepage(clientsocket,keycv)
					sendmsg(encrypted_homepage)
					

				else:
					print("Breach detected")

			else:
				print("Taking too long to respond")


		else:
			found = False
			id_found = None
			for key in clientInfo:
				decryption = (AES.decrypt(package,clientInfo[key]['keycv'])).decode()
				if(decryption==str(key)):
					id_found = key
					print("Existing UserID (",key,") found")
					found = True
					break


			if(found):
				encrypted_text = ""
				if(functions.checkValidity(clientInfo[id_found]['lt'])):
					print("Session Key is Valid")
					html_text = prepareHtml()
					encrypted_text = AES.encrypt(html_text,clientInfo[id_found]['keycv'])

				else:
					encrypted_text = AES.encrypt("-1",clientInfo[id_found]['keycv'])
					

				sendmsg(encrypted_text)

			else:
				print("Authentication Failed!!!")
				print("Terminating the connection with this user")
				loop = False
				break

	except:
		print("Application Server has closed down")
		loop = False
		break






