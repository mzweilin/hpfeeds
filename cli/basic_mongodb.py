#!/usr/bin/python

import sys
import logging
logging.basicConfig(level=logging.WARNING)

from  gridfs  import GridFS
import hpfeeds
import pymongo
import ast
import datetime
import hashlib
from ConfigParser import ConfigParser

config=ConfigParser()
CONFIGFILE = "basic_mongodb.cfg"
config.read(CONFIGFILE)
HOST=config.get("hpfeeds","HOST")
PORT=config.get("hpfeeds","PORT")
IDENT=config.get("hpfeeds","IDENT")			
SECRET=config.get("hpfeeds","SECRET")
CHANNELS = ['dionaea.connections', 'geoloc.events','dionaea.dcerpcrequests','dionaea.shellcodeprofiles','mwbinary.dionaea.sensorunique','dionaea.capture',
'dionaea.offer','dionaea.emu_services','dionaea.mssql_command','dionaea.mssql_fingerprint','dionaea.logins','dionaea.dcerpcbind',
'dionaea.p0f','dionaea.bistream','kippo.malware','kippo.sessions']
	
MONGOHOST=config.get("database","MONGOHOST")	
MONGOPORT=config.get("database","MONGOPORT")
MONGODBNAME=config.get("database","MONGODBNAME")	
MONGOUSER=config.get("database","MONGOUSER")	
MONGOPWD=config.get("database","MONGOPWD")
	
def get_db(host, port, name, user = '', passwd = ''):
        dbconn = pymongo.Connection(host, port)
        db = pymongo.database.Database(dbconn, name)
	if user != '' or passwd != '':
        	db.authenticate(user, passwd)
        return db

def main():
	
	hpc = hpfeeds.new(str(HOST), int(PORT), str(IDENT), str(SECRET))
	print >>sys.stderr, 'connected to', hpc.brokername

	db = get_db(str(MONGOHOST), int(MONGOPORT), str(MONGODBNAME), str(MONGOUSER), str(MONGOPWD))
	collection = None

	def on_message(identifier, channel, payload):
		if channel == 'dionaea.connections':
			try:
				msg = ast.literal_eval(str(payload))
			except:
				print 'exception processing dionaea.connections event', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print msg
				msg['remote_port'] = int(msg['remote_port'])
				msg['local_port'] = int(msg['local_port'])
				print 'inserting...', msg
				collection = db['dionaea.connections']
				collection.insert(msg)
		elif channel == 'geoloc.events':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing geoloc.events', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection =  db['geoloc.events']
				collection.insert(msg)
		elif channel == 'dionaea.dcerpcrequests':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.dcerpcrequests', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.dcerpcrequests']
				collection.insert(msg)
		elif channel == 'dionaea.shellcodeprofiles':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.shellcodeprofiles', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.shellcodeprofiles']
				collection.insert(msg)
		elif channel == 'mwbinary.dionaea.sensorunique' :
			try:
				payload_python = str(payload)
			except:
				print 'exception processing mwbinary.dionaea.sensorunique', repr(payload)
			else:
				hash = hashlib.sha1()
				hash.update(payload_python)
				msg = hash.hexdigest()
				print 'inserting dionaea.mwbinary...', msg
				gfsData=GridFS(db,'malwareSample')
				if(gfsData.exists(filename=msg))
					print 'skip sha1 %s dionaea.malwareSample'%msg
				else
					gfsData.put(payload_python,filename=msg)
		elif channel == 'dionaea.capture':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.capture', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.capture']
				collection.insert(msg)
		elif channel == 'dionaea.offer':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.offer', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.offer']
				collection.insert(msg)
		elif channel == 'dionaea.emu_services':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.emu_services', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.emu_services']
				collection.insert(msg)
		elif channel == 'dionaea.mssql_command':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.mssql_command', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.mssql_command']
				collection.insert(msg)
		elif channel == 'dionaea.mssql_fingerprint':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing mssql_fingerprint', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.mssql_fingerprint']
				collection.insert(msg)
		elif channel == 'dionaea.logins':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.logins', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.logins']
				collection.insert(msg)
		elif channel == 'dionaea.dcerpcbind':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.dcerpcbind', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.dcerpcbind']
				collection.insert(msg)
		elif channel == 'dionaea.p0f':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.p0f', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.p0f']
				collection.insert(msg)
		elif channel == 'dionaea.bistream':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.bistream', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.bistream']
				collection.insert(msg)
		elif channel == 'kippo.sessions':
			try:
				payload_python = str(payload)
				replaceNone=payload_python.replace("null", "None")
				replaceTrue=replaceNone.replace("true", "True")
				replaceFalse=replaceTrue.replace("false", "False")
				msg = ast.literal_eval(replaceFalse)
			except Exception ,e:
				print 'exception processing kippo.sessions {0}'.format(e)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['kippo.sessions']
				collection.insert(msg)
		elif channel == 'kippo.malware' :
			try:
				payload_python = str(payload)
			except:
				print 'exception processing kippo.malware', repr(payload)
			else:
				hash = hashlib.sha1()
				hash.update(payload_python)
				msg = hash.hexdigest()
				print 'inserting kippo.mwbinary...', msg
				gfsData=GridFS(db,'malwareSample')
				if(gfsData.exists(filename=msg))
					print 'skip sha1 %s kippo.malwareSample'%msg
				else
					gfsData.put(payload_python,filename=msg)
		else:
			print channel+" Not exists!! "+str(payload)
	def on_error(payload):
		print >>sys.stderr, ' -> errormessage from server: {0}'.format(payload)
		hpc.stop()

	hpc.subscribe(CHANNELS)
	hpc.run(on_message, on_error)
	hpc.close()
	return 0

if __name__ == '__main__':
	try: sys.exit(main())
	except KeyboardInterrupt:sys.exit(0)

