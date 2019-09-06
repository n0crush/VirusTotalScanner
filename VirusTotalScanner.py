"""
completed on Jully 25, 2019
change 1: Sep 06, 2019
#Usage:     python [namefile] [type] [object]
"""
import requests
import sys
import time

class VirusTotal:
	"""
		Analyze suspicious files and URLs to detect types of malware through VirusTotal API v2
	"""

	apiKey = 'Insert Public Key Here'
	baseURL = "https://www.virustotal.com/vtapi/v2"

	def __init__(self, typeObject, obj):
		self.typeObject = typeObject
		self.obj = obj		
	def scanFile(self):
		url = self.baseURL+'/file/scan'
		files = {'file':open(self.obj, 'rb')}
		params = {'apikey':self.apiKey}
		#
		res = requests.post(url, files=files, params=params)

		test = self.checkStatus(res)
		if test:
			resource = res.json()['resource']
			return resource
	def scanURL(self):
		url = self.baseURL+'/url/scan'
		params = {'apikey':self.apiKey, 'url':self.obj}
		#
		res = requests.post(url, data=params)

		test = self.checkStatus(res)
		if test:
			scan_id = res.json()['scan_id']
			return scan_id
	def reportDomain(self):									#DONE
		url = self.baseURL+'/domain/report'
		params = {'apikey':self.apiKey, 'domain':self.obj}
		#
		res = requests.get(url, params=params)

		test = self.checkStatus(res)
		if test:
			return res.json()
	def reportIP(self):										#DONE
		url = self.baseURL+'/ip-address/report'
		params = {'apikey':self.apiKey, 'ip':self.obj}
		#
		res = requests.get(url, params=params)

		test = self.checkStatus(res)
		if test:
			response_data = res.json()
			data = {}
			#
			data['country'] = response_data['country']
			data['detected_urls'] = response_data['detected_urls']
			data['detected_downloaded_samples'] = response_data['detected_downloaded_samples']
			#
			return data
	def reportFile(self):									#DONE
		resource = self.scanFile()
		url = self.baseURL+'/file/report'
		params = {'apikey':self.apiKey, 'resource':resource}
		#
		res = requests.get(url, params=params)

		test = self.checkStatus(res)
		if test:
			return self.formReport(res)	
	def reportURL(self):									#DONE
		url = self.baseURL+'/url/report'
		resource = self.scanURL()
		params = {'apikey':self.apiKey, 'resource':resource}
		#
		res = requests.get(url, params=params)

		test = self.checkStatus(res)
		if test:
			return self.formReport(res)
	def showIP(self, data):									#DONE
		print('-'*18*3)
		print('Country: ',data['country'])
		print('-'*18*3)
		detected_urls = data['detected_urls']
		print('Detected URLS')
		print('-'*18*3)
		for d in detected_urls:
			print('URL:'.ljust(15, ' '),d['url'])
			print('Detected:'.ljust(15, ' '),d['positives'])
			print('Scan Date:'.ljust(15, ' '), d['scan_date'])
			print('-'*9*3)
		print('-'*18*3)
		if ('detected_downloaded_samples' in data.keys()):
			detected_downloaded_samples = data['detected_downloaded_samples']
			print('Detected Download')
			print('-'*18*3)
			for d in detected_downloaded_samples:
				print(d['sha256'])
				print('Downloaded Date:'.ljust(15, ' '),d['date'])
				print('Detected:'.ljust(15, ' '), d['positives'])
				print('-'*9*3)
			print('-'*18*3)
		#
	def showDomain(self, data):								#DONE
		data['country'] = "NULL"			#search for domain not include Country
		self.showIP(data)
	def showURL(self, data):								#DONE
		print('*'*40)
		print('Total detected: ', data[0])
		print('*'*20)
		engines = data[1].keys()
		for p in engines:
			print(p.ljust(20, ' '),'-'*5,data[1][p])
		print('*'*20)		
		print('*'*40)
	def showFile(self, data):								#DONE
		#
		return self.showURL(data)
	def checkStatus(self, res):
		if res.status_code != 200:	#request failed
			res.raise_for_status()
			sys.exit('Escape script')
		#
		def g(s):			#get Object Name :))
			regex = ['Domain', 'URL,', 'IP']
			l_s = s.split(' ')
			for i in l_s:
				if i in regex:
					if i=='URL,':
						return i[:-1]
					return i
		#
		try:
			response_code = res.json()['response_code']
			verbose_msg = res.json()['verbose_msg']
		except Exception as x:
			pass
		else:
			if response_code != 1:		#scan requests UNsuccessfully 
				ex = {'response_code':response_code, 'verbose_msg':verbose_msg}
				print('Error Code: %d\nMessage   : %s. Check %s again.' %(ex['response_code'], ex['verbose_msg'], g(ex['verbose_msg'])))
				sys.exit()
			else:
				return True
	def formReport(self, res):
		response_data = res.json()
		#
		scan_date = response_data['scan_date']
		scans = response_data['scans']
		engines = list(scans.keys())			#list keys of dict['scans'] ex: CLEAN MX, DNS8,...
		#
		count = 0
		engines_data = {}
		for x in engines:
			if scans[x]['detected']:
				count += 1
				engines_data[x] = scans[x]['result']
		return (count, engines_data)
def main():
	#
	def caution():
		print('Usage:'.ljust(10, ' '), 'python [namefile] [type] [object]')
		print('-'*10)
		print('namefile:'.ljust(10, ' '), 'name of python script')
		print('type:'.ljust(10, ' '), 'type of object to scan. Ex: file, domain, url, ip-address')
		print('object:'.ljust(10, ' '), 'specific object')
		print('-'*10)
		print('Note:\n', ' '*9, 'with ip-address: IPv4 only')
		print(' '*10, 'with domain: you must to put domain name in double-quotes and only \'www.DomainName\'')
		print(' '*10 ,'with file: you must to put \'object\' in double-quotes Ex: "sample.exe"')
	#
	try:
		t = sys.argv[1]
		o = sys.argv[2]
	except Exception as x:
		caution()
	else:
		vt = VirusTotal(t, o)
		tp = t.upper()
		timeS = time.time()
		if tp == 'URL' or tp == 'URLS':
			vt.showURL(vt.reportURL())
		elif tp == 'IP' or tp == 'IP-ADDRESS':
			vt.showIP(vt.reportIP())
		elif tp == 'DOMAIN':
			vt.showDomain(vt.reportDomain())
		elif tp == 'FILE' or tp == 'FILES':
			vt.showFile(vt.reportFile())
		else:
			print('DELL BIET DKM')
		timeE = time.time()
		print('*'*30)
		print('Script finished in %f (s)' %(timeE-timeS))
	
if __name__ == '__main__':
	try:
		main()
	except Exception as ex:
		print(ex)

		



