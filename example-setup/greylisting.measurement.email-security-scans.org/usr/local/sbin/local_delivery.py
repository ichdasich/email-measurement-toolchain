#!/usr/bin/env python3
import sys
import os
import socket
import string
import queue as Queue
import threading
import ipaddress
import timeit
import smtplib
#import MySQLdb
import json
import time

from email.parser import BytesParser, Parser
from email.policy import default
import re
from random import choice

import dns as dns
import dns.resolver
import hashlib

socket.setdefaulttimeout(15)
#db = MySQLdb.connect("db.measurement.email-security-scans.org","mail","LithorathBedad","measurements" )
#cursor = db.cursor()

HOST='greylisting.measurement.email-security-scans.org'
TIME=str(int(time.time()))

tmp_mail = []

# List of DNS blacklists
serverlist = [
#	"0spam.fusionzero.com",
#	"access.redhawk.org",
#	"all.rbl.webiron.net",
#	"all.s5h.net",
#	"b.barracudacentral.org",
#	"bad.psky.me",
#	"bhnc.njabl.org",
#	"bl.blocklist.de",
#	"bl.deadbeef.com",
#	"bl.emailbasura.org",
#	"bl.mailspike.net",
#	"bl.spamcannibal.org",
	"bl.spamcop.net",
#	"bl.spameatingmonkey.net",
#	"bl.technovision.dk",
#	"blackholes.five-ten-sg.com",
	"blackholes.mail-abuse.org",
#	"blacklist.sci.kun.nl",
#	"blacklist.woody.ch",
	"bogons.cymru.com",
#	"cbl.abuseat.org",
#	"cdl.anti-spam.org.cn",
	"cidr.bl.mcafee.com",
#	"combined.abuse.ch",
	"combined.rbl.msrbl.net",
#	"db.wpbl.info",
#	"dnsbl-1.uceprotect.net",
#	"dnsbl-2.uceprotect.net",
#	"dnsbl-3.uceprotect.net",
#	"dnsbl.anticaptcha.net",
#	"dnsbl.cobion.com",
#	"dnsbl.cyberlogic.net",
#	"dnsbl.dronebl.org",
#	"dnsbl.inps.de",
#	"dnsbl.kempt.net",
#	"dnsbl.njabl.org",
#	"dnsbl.solid.net",
#	"dnsbl.sorbs.net",
#	"dnsrbl.org",
#	"drone.abuse.ch",
#	"duinv.aupads.org",
#	"dul.dnsbl.sorbs.net",
#	"dul.ru",
#	"dyna.spamrats.com",
#	"dynip.rothen.com",
#	"forbidden.icm.edu.pl",
#	"hostkarma.junkemailfilter.com",
#	"hil.habeas.com",
#	"images.rbl.msrbl.net",
	"ips.backscatterer.org",
#	"ix.dnsbl.manitu.net",
#	"korea.services.net",
#	"mail-abuse.blacklist.jippg.org",
#	"no-more-funn.moensted.dk",
#	"noptr.spamrats.com",
#	"ohps.dnsbl.net.au",
#	"omrs.dnsbl.net.au",
#	"orvedb.aupads.org",
#	"osps.dnsbl.net.au",
#	"osrs.dnsbl.net.au",
#	"owfs.dnsbl.net.au",
#	"owps.dnsbl.net.au",
	"phishing.rbl.msrbl.net",
#	"probes.dnsbl.net.au",
#	"proxy.bl.gweep.ca",
#	"proxy.block.transip.nl",
#	"psbl.surriel.com",
#	"rbl.abuse.ro",
#	"rbl.interserver.net",
#	"rbl.megarbl.net",
#	"rbl.orbitrbl.com",
#	"rbl.realtimeblacklist.com",
#	"rbl.schulte.org",
#	"rdts.dnsbl.net.au",
#	"relays.bl.gweep.ca",
#	"relays.bl.kundenserver.de",
#	"relays.nether.net",
	"residential.block.transip.nl",
#	"ricn.dnsbl.net.au",
#	"rmst.dnsbl.net.au",
#	"short.rbl.jp",
#	"singular.ttk.pte.hu",
	"spam.abuse.ch",
#	"spam.dnsbl.sorbs.net",
	"spam.rbl.msrbl.net",
#	"spam.spamrats.com",
#	"spamguard.leadmon.net",
#	"spamlist.or.kr",
#	"spamrbl.imp.ch",
#	"spamsources.fabel.dk",
#	"spamtrap.drbl.drand.net",
#	"srnblack.surgate.net",
#	"t3direct.dnsbl.net.au",
#	"tor.dnsbl.sectoor.de",
#	"torserver.tor.dnsbl.sectoor.de",
#	"truncate.gbudb.net",
#	"ubl.lashback.com",
#	"ubl.unsubscore.com",
#	"virbl.dnsbl.bit.nl",
#	"virus.rbl.jp",
	"virus.rbl.msrbl.net",
#	"wormrbl.imp.ch",
	"pbl.spamhaus.org",
	"css.spamhaus.org",
	"sbl.spamhaus.org",
]

####

queue = Queue.Queue()
debug = False
global on_blacklist
on_blacklist = []
class ThreadRBL(threading.Thread):
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.queue = queue

	def run(self):
		while True:
			# Grab hosts from queue
			hostname, root_name = self.queue.get()
			check_host = "%s.%s" % (hostname, root_name)
			start_time = timeit.default_timer()
			try:
				check_addr = socket.gethostbyname(check_host)
			except socket.error:
				check_addr = None
			if check_addr is not None and "127.0.0." in check_addr:
				on_blacklist.append(root_name)

			elapsed = timeit.default_timer() - start_time
			# If debug option is set it prints the time it took to get an answer from each RBL
			if debug: print("It took %s seconds to get a response from the DNSBL %s" % (elapsed,root_name))

			# Signal queue that job is done
			self.queue.task_done()


for line in sys.stdin:
	tmp_mail.append(line)

def check_uuid(headers):
	re_uuid = re.compile(r'[0-9]{10}:[a-f0-9]{64}:[0-9]+')
	if not headers['from']:
		return TIME+':'+hashlib.sha256('nofrom'.encode('utf-8')).hexdigest()
	try:
		if re_uuid.findall(headers['subject']):
			return headers['subject'].strip()
		else:
			return TIME+':'+hashlib.sha256(headers['from'].encode('utf-8')).hexdigest()
	except:
		return TIME+':'+hashlib.sha256(headers['from'].encode('utf-8')).hexdigest()


def log(line):
	log_file = open('/tmp/log','a')
	log_file.write(str(line).strip()+'\n')
	log_file.close()

def store_mail(tmp_mail):
	headers = Parser(policy=default).parsestr(''.join(tmp_mail))
	f = open('/srv/mails/'+check_uuid(headers)+'-'+headers['delivered-to'], 'w')
	try:
		log('Storing mail from '+headers['from']+' to '+headers['delivered-to']+' with id '+check_uuid(headers))
	except:
		log('Storing mail from NOFROM to '+headers['delivered-to']+' with id '+check_uuid(headers))
	
	for line in tmp_mail:
		f.write(line)
	
	f.close()
	return headers

def get_dns_record(name, rr='A'):
	result_set = []
	try:
		result = dns.resolver.query(name.strip('.')+'.', rr)
		for val in result:
			result_set.append(val.to_text())
	except Exception as e:
		result_set.append(str(e))
	return result_set

def get_ehlo(headers):
	re_by = re.compile(r'from ([^ ]+) \(([^ ]+) \[([^ ]+)\]\)')
	rec_headers = headers.get_all('Received')
	ehlo_record = {}
	for h in rec_headers:
		if 'by '+HOST in h:
			ehlo = re_by.findall(h)[0]
			ehlo_record['ehlo'] = ehlo[0]
			ehlo_record['rdns'] = ehlo[1]
			ehlo_record['ip'] = ehlo[2].replace('IPv6:','')
	ehlo_record['ehlo_A'] = get_dns_record(ehlo_record['ehlo'],'A')
	ehlo_record['ehlo_AAAA'] = get_dns_record(ehlo_record['ehlo'],'AAAA')
	ehlo_record['ehlo_TLSA'] = get_dns_record('_25._tcp.'+ehlo_record['ehlo'],'TLSA')
	ehlo_record['rdns_A'] = get_dns_record(ehlo_record['rdns'],'A')
	ehlo_record['rdns_AAAA'] = get_dns_record(ehlo_record['rdns'],'AAAA')
	ehlo_record['rdns_TLSA'] = get_dns_record('_25._tcp.'+ehlo_record['ehlo'],'TLSA')
	
	return ehlo_record

def get_mx(headers):
	sender_domain = headers['from'].split('@')[-1].strip('>')
	return get_dns_record(sender_domain, 'MX')

def get_spf(headers):
	res = {}
	sender_domain = headers['from'].split('@')[-1].strip('>')
	res['IN_SPF'] = get_dns_record(sender_domain, 'SPF')
	res['IN_TXT'] = get_dns_record(sender_domain, 'TXT')
	return res

def get_srv(headers):
	sender_domain = headers['from'].split('@')[-1].strip('>')
	return get_dns_record('_smtp._tcp.'+sender_domain, 'SRV')

def get_dmarc(headers):
	sender_domain = headers['from'].split('@')[-1].strip('>')
	return get_dns_record('_dmarc.'+sender_domain, 'TXT')

def normalize_dkim(header):
	res = {}
	re_selector = re.compile(r's=([^;]+);')
	re_domain = re.compile(r'd=([^;]+);')
	header = header.replace('\t','').replace('\t','')
	res['selector'] = re_selector.findall(header)[0]
	res['domain'] = re_domain.findall(header)[0]
	
	return res

def get_dkim(headers):
	sender_domain = headers['from'].split('@')[-1].strip('>')
	if headers['DKIM-Signature']:
		dkim = normalize_dkim(headers['DKIM-Signature'])
		dkim['sender_domain_key'] = get_dns_record(dkim['selector']+'._domainkey.'+sender_domain, 'TXT')
		dkim['dkim_domain_key'] = get_dns_record(dkim['selector']+'._domainkey.'+dkim['domain'], 'TXT')
	else:
		dkim = {'N/A':True}
	
	if headers['DomainKey-Signature']:
		domkey = normalize_dkim(headers['DomainKey-Signature'])
		domkey['sender_domain_key'] = get_dns_record(domkey['selector']+'._domainkey.'+sender_domain, 'TXT')
		domkey['domkey_domain_key'] = get_dns_record(domkey['selector']+'._domainkey.'+domkey['domain'], 'TXT')
	else:
		domkey = {'N/A':True}
	
	return {'dkim':dkim, 'domkey':domkey}


def dnssec_trace(ehlo, rdns, sender):
	hosts = {'ehlo':{'domain':ehlo, 'res':{}}, 'rdns':{'domain':rdns, 'res':{}}, 'sender':{'domain':sender, 'res':{}}}
	for host in hosts.keys():
		cleaned_myhost = hosts[host]['domain'].split('.')
		if not cleaned_myhost[-1].endswith('.'):
			cleaned_myhost.extend('.')
		cleaned_myhost.reverse()
		if '' in cleaned_myhost:
			cleaned_myhost.remove('')
		i = 1
		while i < len(cleaned_myhost):
			if i == 1:
				cleaned_myhost[i] = cleaned_myhost[i]+cleaned_myhost[i-1]
			else:
				cleaned_myhost[i] = cleaned_myhost[i]+'.'+cleaned_myhost[i-1]
			i += 1
		for domain in cleaned_myhost[1:]:
			hosts[host]['res'][domain] = {}
			hosts[host]['res'][domain]['DS'] = get_dns_record(domain, 'DS')
			hosts[host]['res'][domain]['DNSKEY'] = get_dns_record(domain, 'DNSKEY')
	return hosts

def check_open_relay(host='198.51.100.186'):
	sndr = 'OpenRelayTest@mail.measurement.email-security-scans.org'
	rcpt = 'OpenRelayTest@mail.measurement.email-security-scans.org'
	message = """From: OpenRelayTest <OpenRelayTest@mail.measurement.email-security-scans.org>
				To: OpenRelayTest <OpenRelayTest@mail.measurement.email-security-scans.org>
				Subject: Open Relay Test
				
				This is an automated open relay test. It should fail.
				
			"""
	try:
		smtpObj = smtplib.SMTP(host,25)
		smtpObj.sendmail(sndr, rcpt, message)
		return "Open Relay detected at "+host
	except Exception as e:
		return host+" says: "+str(e)


def check_rbl(addr='198.51.100.186'):
	global on_blacklist
	on_blacklist = []
	ip = ipaddress.ip_address(addr)
	if ip.version == 4:
		addr_parts = addr.split('.')
		addr_parts.reverse()
		check_name = '.'.join(addr_parts)
	else:
		addr_exploded = ip.exploded
		check_name = '.'.join([c for c in addr_exploded if c != ':'])[::-1]
# ##### Start thread stuff

	# Spawn a pool of threads then pass them the queue
	for i in range(10):
		t = ThreadRBL(queue)
		t.setDaemon(True)
		t.start()

	# Populate the queue
	for blhost in serverlist:
		queue.put((check_name, blhost))

	# Wait for everything in the queue to be processed
	queue.join()

# ##### End thread stuff
	host = addr
	res = {}
	res['count'] = len(on_blacklist)
	res['lists'] = on_blacklist
	return res


# cursor.execute('INSERT INTO mails (uuid, target, mail, senddate) VALUES (%s, %s, %s, "%s");', (uuid, tgid, dst_mail, int(time.time())))
# db.commit()

#def store_ehlo(headers, ehlo):
#	cursor.execute('INSERT INTO ehlo (mid, dstaddr, ehlo, rdns, ip, ehlo_a, ehlo_aaaa, ehlo_tlsa, rdns_a, rdns_aaaa, rdns_tlsa) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);', (headers['subject'], headers['delivered-to'], ehlo['ehlo'], ehlo['rdns'], ehlo['ip'], str(ehlo['ehlo_A']), str(ehlo['ehlo_AAAA']), str(ehlo['ehlo_TLSA']), str(ehlo['rdns_A']), str(ehlo['rdns_AAAA']), str(ehlo['rdns_TLSA'])))
#	db.commit()

data = {}
try:
	headers = store_mail(tmp_mail)
	ehlo = get_ehlo(headers)
	data['ehlo'] = ehlo
	data['dnssec_trace'] = dnssec_trace(ehlo['ehlo'], ehlo['rdns'], headers['from'].split('@')[-1].strip('>'))
	data['mx'] = get_mx(headers)
	data['spf'] = get_spf(headers)
	data['dmarc'] = get_dmarc(headers)
	data['srv'] = get_srv(headers)
	data['dkim'] = get_dkim(headers)
	if "OpenRelayTest@" in headers['delivered-to']:
		data['open_relay'] = "deprecated" #anti catch-all loop
	else:
		data['open_relay'] = check_open_relay(ehlo['ip'])
	data['rbl'] = check_rbl(ehlo['ip'])
	f = open('/srv/json/'+check_uuid(headers)+'-'+headers['delivered-to'], 'w')
	f.write(json.dumps(data)+'\n')
	f.close()


	log('Finished storing mail from '+headers['from']+' to '+headers['delivered-to']+' with id '+check_uuid(headers))

	#log(" ")
	#log(dnssec_trace)
	#log(" ")


	#store_ehlo(headers, ehlo)
except:
	data = {'status':'FAILED'}
	f = open('/tmp/failed_mails','a')
	for l in tmp_mail:
		f.write(l)
	log('### FAILED storing mail to '+headers['delivered-to']+' with id '+check_uuid(headers))

