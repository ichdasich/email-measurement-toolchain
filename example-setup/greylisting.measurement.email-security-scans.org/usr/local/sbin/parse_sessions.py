#!/usr/local/bin/python3

import sys
import re
import datetime
import hashlib

re_session = re.compile(r'greylisting postfix/smtpd\[[0-9]+\]: (<|>) ')
re_rcpt = re.compile(r'[rR][cC][pP][tT] ?[tT][oO]')
re_from = re.compile(r'[Mm][aA][iI][lL] ?[Ff][Rr][oO][mM]')
re_mail = re.compile(r'<([^<]+@[^>]+)>')

def parse_sessions():
	f = open('/var/log/maillog','r')
	data = []
	tmp_data = []
	for line in f:
		if re_session.findall(line):
			if '220 greylisting.measurement.email-security-scans.org' in line:
				if tmp_data:
					data.append(tmp_data)
				tmp_data = []
				tmp_data.append(line)
			else:
				tmp_data.append(line)
			
	if tmp_data:
		data.append(tmp_data)
	return data

def store_sessions(data):
	for session in data:
		mailfrom = 'NOT SUPPLIED'
		rcptto = 'NOT SUPPLIED'
		now = datetime.datetime.now()
		time = datetime.datetime.strptime(session[0][0:15]+' '+str(now.year), '%b %d %H:%M:%S %Y').strftime('%s')
		for line in session:
			rcpt = re_rcpt.findall(line)
			frm  = re_from.findall(line)
			if frm:
				try:
					mailfrom = re_mail.findall(line)[0]
				except:
					pass
			if rcpt:
				try:
					rcptto = re_mail.findall(line)[0]
				except:
					pass
		if not mailfrom == 'NOT SUPPLIED':
			uuid = time+':'+hashlib.sha256((mailfrom).encode('ASCII')).hexdigest()
		else:
			uuid = time+':'+hashlib.sha256((mailfrom+time).encode('ASCII')).hexdigest()
		sfile = open('/srv/sessions/'+uuid, 'w')
		for line in session:
			sfile.write(line)

data = parse_sessions()
store_sessions(data)
