# http_server


Useage: 

Change the HOST and PORT in test.py 156, 157, and start fuzzing





#--------------------------------------------------------------
# caddy: 		192.168.146.131		2015


                         --------------------------------------------------
                         Finished fuzzing session
                         Target: TcpTarget

                         Tested 1521 mutations
                         Mutation range: 0 to 1520
                         Failure count: 196
                         --------------------------------------------------


#--------------------------------------------------------------
# jexus: 		192.168.146.131		2016
	                     --------------------------------------------------
                         Finished fuzzing session
                         Target: TcpTarget

                         Tested 1521 mutations
                         Mutation range: 0 to 1520
                         Failure count: 3
                         --------------------------------------------------

#--------------------------------------------------------------
# monkey:		192.168.146.131		2017
                         --------------------------------------------------
                         Finished fuzzing session
                         Target: TcpTarget

                         Tested 1521 mutations
                         Mutation range: 0 to 1520
                         Failure count: 63
                         --------------------------------------------------



#--------------------------------------------------------------
# lighttpd:		192.168.146.131		2018


                         --------------------------------------------------
                         Finished fuzzing session
                         Target: TcpTarget

                         Tested 1521 mutations
                         Mutation range: 0 to 1520
                         Failure count: 0
                         --------------------------------------------------



# Instructions for starting server
#====================================
# Server	Start					Port
Apache2		default					80

caddy		cd caddy				2015
			./caddy

jexus		cd /usr/jexus				2016
			sudo ./jws start


monkey		cd /home/user/monkey-1.6.9		2017	
			build/monkey

lighttpd	sudo /etc/init.d/lighttpd start		2018


#====================================
# test server:

localhost:2015



sudo lsof -i -n -P


sudo sh -c "ulimit -n 8192 && exec su user"




