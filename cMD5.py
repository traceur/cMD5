#!/usr/bin/env python
# -*- coding: utf-8 -*- 
# File_name: cMD5
# Writin by: lnxg33k <ahmed[at]isecur1ty.org>
# Chage by:乔3少 <traceurq@gmail.com>
# 修改了原版的本地破解函数，直接导入字典源文件，程序自动将字典中的字符串加密与密码对比。
# 原版地址：http://lnxg33k.wordpress.com/2011/03/05/scripts-md5-hash-cracker-online-offline/
import sys
import os
import urllib2
import urllib 
import re
import hashlib
 
def banner():
  print '''
        |-----------------------------------------------|
        |[+] cMD5.py (online | local)                   |
        |-----------------------------------------------|
'''
banner()
 
def usage():
  if len(sys.argv) < 2:
    print ''
    print 'Usage:' 
    print '  python cMD5.py --online [MD5]'
    print '  python cMd5.py --local [MD5] [password file]'
    sys.exit(1)
usage()
 
option   = sys.argv[1]
MD5   = sys.argv[2]
 
if option == '--online':
  try:
    def myaddr():
      site = 'http://md5.my-addr.com/'
      rest = 'md5_decrypt-md5_cracker_online/md5_decoder_tool.php'
      para = urllib.urlencode({'md5':MD5})
      req = urllib2.Request(site+rest)
      fd = urllib2.urlopen(req, para)
      data = fd.read()
      match = re.search('(Hashed string</span>: )(\w+.\w+)', data)
      if match: print '[-] site: %s\t\t\tPassword: %s' %(site, match.group(2))
      else: print '[-] site: %s\t\t\tPassword: Not found\n' %site
    myaddr()
 
    def victorov():
      try:
        site = 'http://www.victorov.su/'
        para = 'md5/?md5e=&md5d=%s' %MD5
        req = urllib2.Request(site+para)
        req.add_header
        opener = urllib2.urlopen(req)
        data = opener.read()
        match = re.search('(\w+)(</b>)', data)
        if match: print '\n[-] site: %s\t\t\tPassword: %s\n' %(site, match.group(1))
        else: print '[-] site: %s\t\t\tPassword: Not found\n' %site
      except urllib2.URLError,e: print '[+] site: %s \t\t\t seems to be down\n' %site
    victorov()
    
    def md5crack():
      site = 'http://www.md5crack.com/'
      rest = 'crackmd5.php'
      para = urllib.urlencode({'term':MD5})
      req = urllib2.Request(site+rest)
      try: 
        fd = urllib2.urlopen(req, para)
        data = fd.read()
        match = re.search('(Found: md5)(..)(\w+.\w+)', data)
        if match: print '[-] site: %s\t\t\tPassword: %s\n' %(site, match.group(3))
        else: print '[-] site: %s\t\t\tPassword: Not found\n' %site
      except urllib2.HTTPError: print '[*] Check your connection\n'
    md5crack()
 
    def rednoize():
      site = 'http://md5.rednoize.com/'
      para = 'p&s=md5&q=%s&_=' %MD5
      req = urllib2.urlopen(site+'?'+para)
      data = req.read()
      if not len(data): print '[-] site: %s\t\t\tPassword: Not found\n' %site
      else: print '[-] site: %s\t\t\tPassword: %s\n' %(site, data)
    rednoize()
 
    def md5pass():
      site = 'http://www.md5pass.info/'
      para = urllib.urlencode({'hash':MD5, 'get_pass':'Get+Pass'})
      req = urllib2.Request(site)
      fd = urllib2.urlopen(req, para)
      data = fd.read()
      match = re.search('(Password - <b>)(\w+)', data)
      if match: print '[-] site: %s\t\t\tPassword: %s\n' %(site, match.group(2))
      else: print '[-] site: %s\t\t\tPassword: Not found\n' %site
    md5pass()
 
    def md5decryption():
      site = 'http://md5decryption.com/'
      para = urllib.urlencode({'hash':MD5,'submit':'Decrypt+It!'})
      req = urllib2.Request(site)
      fd = urllib2.urlopen(req, para)
      data = fd.read()
      match = re.search(r'(Decrypted Text: </b>)(.+[^>])(</font><br/><center>)', data)
      if match: print '[-] site: %s\t\t\tPassword: %s\n' %(site, match.group(2))
      else: print '[-] site: %s\t\t\tPassword: Not found\n' %site
    md5decryption()

    '''def hashkiller():
      site = 'http://opencrack.hashkiller.com/'
      para = urllib.urlencode({'oc_check_md5':MD5,'oc_submit':'Search+MD5'})
      req = urllib2.Request(site)
      fd = urllib2.urlopen(req, para)
      data = fd.read()
      match = re.search('(<div class="result">)(\w+)(:)(\w+.\w+)', data)
      if match:
        print '[-] site: %s\t\t\tPassword: %s\n' %(site.replace('http://', ''), match.group(4).replace('<br',''))
      else: print '[-] site: %s\t\t\tPassword: Not found\n' %site.replace('http://', '')
    hashkiller()'''
 
    def bigtrapeze():
      site = 'http://www.bigtrapeze.com/'
      rest = 'md5/index.php?query=%s' %MD5
      req = urllib2.Request(site+rest)
      req.add_header('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.2)\
      Gecko/20100316 AskTbSPC2/3.9.1.14019 Firefox/3.6.2')
      opener = urllib2.build_opener()
      data = opener.open(req).read()
      match = re.search('(=> <strong>)(\w+.\w+)', data)
      if match: print '[-] site: %s\t\t\tPassword: %s\n' %(site, match.group(2))
      else: print '[-] site: %s\t\t\tPassword: Not found\n' %site
    bigtrapeze()
 
    def cloudcracker():
      site = 'http://www.netmd5crack.com/'
      para = 'cgi-bin/Crack.py?InputHash=%s' %MD5
      req = urllib.urlopen(site+para)
      data = req.read()
      match = re.search(r'<tr><td class="border">[^<]+</td><td class="border">\
      (?P<hash>[^>]+)</td></tr></tbody></table>', data)
      if match: print '[-] site: %s\t\t\tPassword: %s\n' %(site, match.group(hash))
      else: print '[-] site: %s\t\t\tPassword: Not found\n' %site
    cloudcracker()
 
    def hashchecker():
      site = 'http://www.hashchecker.com/'
      para = urllib.urlencode({'search_field':MD5, 'Submit':'search'})
      req = urllib2.Request(site)
      fd = urllib2.urlopen(req, para)
      data = fd.read()
      match = re.search('(is <b>)(\w+)', data)
      if match: print '[-] site: %s\t\t\tPassword: %s\n' %(site, match.group(2))
      else: print '[-] site: %s\t\t\tPassword: Not found\n' %site
    hashchecker()  
 
    def hashcracking():
      site = 'http://md5.hashcracking.com/'
      rest = 'search.php'
      para = 'md5=%s' %MD5
      req = urllib2.urlopen(site+rest+'?'+para)
      data = req.read()
      match = re.search('(is)(.)(\w+.\w+)', data)
      if match: print '[-] site: %s\t\t\tPassword: %s\n' %(site, match.group(3))
      else: print '[-] site: %s\t\t\tPassword: Not found\n' %site
    hashcracking()
 
    def cloudcracker():
      site = 'http://www.cloudcracker.net/'
      para = urllib.urlencode({'inputbox':MD5, 'submit':'Crack+MD5+Hash!'})
      req = urllib2.Request(site)
      fd = urllib2.urlopen(req, para)
      data = fd.read()
      match = re.search('(this.select)(....)(\w+=")(\w+.\w+)', data)
      if match: print '[-] site: %s\t\t\tPassword: %s\n' %(site, match.group(4))
      else: print '[-] site: %s\t\t\tPassword: Not found\n' %site
    cloudcracker()
  except KeyboardInterrupt: print '\nTerminated by', str(os.uname()[1])
  
elif option == '--local':
  def local():
    fname = sys.argv[3]
    for passwd in open(fname,'rU'):
        passwd=passwd.rstrip()
        if hashlib.md5(passwd).hexdigest() == sys.argv[2]:
            print '[-] %s \t--->\t  %s\n' %(sys.argv[2],passwd)
            exit(0)
        else: print '[-] %s \t--->\t  failed\n' %hashlib.md5(passwd).hexdigest()
  local()
  
else: pass
