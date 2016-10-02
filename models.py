


#==================================================================
# Methods

from kitty.model import *

http_get_v1 = Template(name='HTTP_GET_V1', fields=[
    String('GET', name='method'),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1'),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.0', name='protocol'),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom'),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])


#==================================================================
# Request- URI





#==================================================================
# Headers




#==================================================================
# Cookies



#==================================================================
# Post-data

