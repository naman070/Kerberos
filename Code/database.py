# Naman Gupta (2017070)
# Porvil (2017304)

from hashlib import sha256

database = []

def addData(entry):
	Id = entry[0]
	hashed = sha256(entry[1].encode())
	password = int(hashed.hexdigest(),16)
	val = (Id,password)
	database.append(val)


def makeDatabase():
	addData((2017070,"naman"))
	addData((2017023,"Caliban#Dante"))
	addData((2017192,"Kal_EL070"))
	addData((2017304,"JediKnights"))
	addData((2017356,"RedCobra"))
	addData((2017075,"ThugLife@inf"))
	addData((2017053,"Primus"))

def showDatabase():
	for item in database:
		print(item)

def searchDatabase(id):
	for item in database:
		if id == item[0]:
			return item

	return -1


makeDatabase()
