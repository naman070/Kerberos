# Naman Gupta (2017070)
# Porvil (2017304)

import AES
import socket
from hashlib import sha256
from datetime import datetime,timedelta
import pickle
import json

def generateTimestamp():
	timestamp = str(datetime.now())
	return timestamp

def generatePassword(password):
	hashed = sha256(password.encode())
	hashed_password = int(hashed.hexdigest(),16)
	return str(hashed_password)

def timeterms():
	ts4 = datetime.now()
	lt4 = ts4 + timedelta(hours=(24*30))
	return ts4,lt4


def checkTimestamp(timestamp):
	compromised = False
	current = datetime.now()
	if(timestamp>str(current)):
		compromised = True

	else:
		edited = current - timedelta(seconds=2)
		if(timestamp<str(edited)):
			compromised = True

	return compromised

def getauth(kctgs,encrypted_auth):
	keyctgs = AES.generateKey(kctgs)
	decrypted_auth = AES.decrypt(encrypted_auth,keyctgs)
	authC = json.loads(decrypted_auth.decode())
	return authC


def dict_encryption(my_dict,key):
	dict_str = json.dumps(my_dict)
	encrypted_dict = AES.encrypt(dict_str,key)
	return encrypted_dict


def verify(authenticator,ticket):
	id1 = ticket['idc']
	id2 = authenticator['idc']
	ad1 = ticket['adc']
	ad2 = authenticator['adc']
	if(id1==id2 and ad1==ad2):
		return True
	else:
		return False


def checkValidity(lifetime):
	current_time = str(datetime.now())
	if(current_time>=lifetime):
		return False
	else:
		return True