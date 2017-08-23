import logging
import datetime
import time
from random import randint
from uniflex.core import modules
from uniflex.core import events
from rem_events.sensing_events import *

__author__ = "Daniel Denkovski"
__copyright__ = "Copyright (c) 2017, Faculty of Electrical Engineering and Information Technologies, UKIM, Skopje, Macedonia"
__version__ = "0.1.0"
__email__ = "{danield}@feit.ukim.edu.mk"

'''
Local controller of WiFi flex device.
sudo uniflex-agent --config config_slave.yaml
'''

class WifiFlexLocalController(modules.ControlApplication):
	def __init__(self):
		super(WifiFlexLocalController, self).__init__()
		self.log = logging.getLogger('WifiFlexLocalController')
		self._mydev = None
		self.running = False

	@modules.on_start()
	def my_start_function(self):
		self.log.info("start local wifi flex controller")
		self.running = True

		try:
			node = self.localNode
			#self.log.info(node)
			#self.log.info("My local node: {}, Local: {}".format(node.hostname, node.local))
			device = node.get_device(0)
			if device:
				self._mydev = device
			#self.log.info(self._mydev)

			while (not self._mydev.get_macaddr()): {}

			#self.log.info("HWADDR = " + self._mydev.get_macaddr())
			#self.log.info("CAPABILITIES = ")
			#self.log.info(self._mydev.get_capabilities())

			for dev in node.get_devices():
				print("Dev: ", dev.name)
				#self.log.info(dev)

			for m in node.get_modules():
				print("Module: ", m.name)
				#self.log.info(m)

			for apps in node.get_control_applications():
				print("App: ", apps.name)
				#self.log.info(apps)

		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

		self.log.info('... done')

	@modules.on_exit()
	def my_stop_function(self):
		self.log.info("stop local wifi flex controller")
		self.running = False

	#@modules.on_event(WiFiGetCapabilities)
	def serve_get_capabilities(self, event):
		node = self.localNode
		if (node.uuid == event.receiverUuid):
			try:
				cap_event = WiFiCapabilities(self._mydev.get_macaddr(), self._mydev.get_capabilities())
				self.send_event(cap_event)
			except Exception as e:
				self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
