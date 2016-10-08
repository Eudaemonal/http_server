#!/usr/bin/python



import socket
import os
import sys
from kitty.model import Template
from kitty.model import GraphModel
from kitty.fuzzers import ServerFuzzer
from kitty.targets.server import ServerTarget
from kitty.interfaces import WebInterface
from kitty.controllers.base import BaseController
from kitty.controllers import EmptyController
from kitty.targets import ServerTarget
from kitty.remote import RpcServer

import models


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
		print "data:"+ data
		print self.host
		print self.port
		self.socket.send(data)

	def _receive_from_target(self):
		return self.socket.recv(10000)
#=====================================================================
class LocalProcessController(BaseController):
	def __init__(self, name, process_path, process_args, logger=None):
		'''
		:param name: name of the object
		:param process_path: path to the target executable
		:param process_args: arguments to pass to the process
		:param logger: logger for this object (default: None)
		'''
		super(ClientProcessController, self).__init__(name, logger)
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
	test_name = 'Server fuzzer 0.1'
	test_session='fuzz'					# 'test' or 'fuzz'

	'''	
	apache2:	192.168.146.131		80
	caddy: 		192.168.146.131		2015
	jexus: 		192.168.146.131		2016
	monkey:		192.168.146.131		2017
	lighttpd:	192.168.146.131		2018

	'''
	NAME="target"
	HOST="192.168.146.131"
	PORT=2015

	#---------------------------------------------
	# initialize fuzzer
	target=TcpTarget(NAME,HOST,PORT)
	target.pre_test(1)
	

	
	if test_session is 'test':
		# Simple test to verify connections
		buf=models.http_get_v1.render().tobytes()
		target.transmit(buf)
		print target._receive_from_target()
		sys.exit(0)


	fuzzer=ServerFuzzer(test_name)
	fuzzer.set_interface(WebInterface(HOST, PORT))

	# Set controller 
	#controller = LocalProcessController()
	#target.set_controller(controller)
	#target.set_mutation_server_timeout(20)

	controller = EmptyController('EmptyController')
	target.set_controller(controller)
	#---------------------------------------------

	model = GraphModel('model_01')
	model.connect(models.http_post_01)
	model.connect(models.http_post_01, models.http_req_01)
	model.connect(models.http_req_01, models.http_xss_01)

	#--------------------------------------------
	# Ready to fuzz
	fuzzer.set_model(model)
	fuzzer.set_target(target)


	fuzzer.start()




