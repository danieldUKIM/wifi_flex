import logging
import datetime
import time
import os
import signal

from uniflex.core import modules
import uniflex_module_wifi
from uniflex_module_net_linux import NetworkModule
from uniflex.core import events
from uniflex.core import exceptions
from pyric import pyw # for iw functionality
from pyric.utils.channels import rf2ch
from pyric.utils.channels import ch2rf
from uniflex.core.timer import TimerEventSender

from .wifi_pkt_sniffer import PacketSnifferPyShark, WiFiRssiSink
from rem_events.sensing_events import *

__author__ = "Daniel Denkovski"
__copyright__ = "Copyright (c) 2017, Faculty of Electrical Engineering and Information Technologies, UKIM, Skopje, Macedonia"
__version__ = "0.1.0"
__email__ = "{danield}@feit.ukim.edu.mk"

class WifiModuleFlex(uniflex_module_wifi.WifiModule):
	def __init__(self, mode, ipaddr, dnsserv, country):
		super(WifiModuleFlex, self).__init__()
		self.log = logging.getLogger('WifiModuleFlex')
		self._moniface = None
		self._maniface = None
		self._w0 = None
		self._macad = None
		self._stds = None
		self._channels = None
		self._capabilities = None
		self._haiface = None
		self._dpid = None
		self._timeInterval = 0.1
		self._current_chInd = 0
		self._used_channel = None
		self._packetSniffer = None
		self._csa = False
		self._wmode = None
		self._gwiface = None
		self._rssi_results = {}
		#self.device = device
		self._startmode = mode
		self._ipaddr = ipaddr
		self._dnsserv = dnsserv
		self._coninfo = {}
		self._apconfig = {}
		self.timer = None
		self._country = country

	def add_all_ifaces(self):
		ifaces = self.get_interfaces()
		for ifs in ifaces:
			dinfo = pyw.devinfo(ifs)
			if (dinfo['mode'] == 'monitor'):
				self._moniface = dinfo['card'].dev
			elif (dinfo['mode'] in ['managed', 'AP']):
				self._maniface = dinfo['card'].dev

		if (not self._moniface and 'monitor' in pyw.devmodes(self._w0)):
			self._moniface = 'mon-' + self.phyName
			if not self._moniface in pyw.winterfaces():
				self._moniface = pyw.devadd(self._w0, self._moniface, 'monitor').dev
	
		if (not self._maniface and ('managed' in pyw.devmodes(self._w0) or 'AP' in pyw.devmodes(self._w0))):
			self._maniface = 'man-' + self.phyName
			if not self._maniface in pyw.winterfaces():
				self._maniface = pyw.devadd(self._w0, self._maniface, 'managed').dev

	def set_all_ifaces_down(self):
		ifaces = self.get_interfaces()
		for ifs in ifaces:
			self.set_interface_down(ifs)

	def get_supported_channels(self):
		#self._channels = pyw.devchs(self._w0)
		self._stds = pyw.devstds(self._w0)
		rfs = pyw.phyinfo(self._w0)['bands']
		self._channels = []
		for d in rfs:
			if (d == '5GHz'):
				self._csa = True
			for (freq, chsettings) in zip(rfs[d]['rfs'], rfs[d]['rf-data']):
				if chsettings['enabled']: self._channels.append(rf2ch(freq))

	def get_capabilities(self):
		#self._channels = pyw.devchs(self._w0)
		self._stds = pyw.devstds(self._w0)
		rfs = pyw.phyinfo(self._w0)['bands']
		self._capabilities = {}
		self._channels = []
		for d in rfs:
			if (d == '5GHz'):
				self._csa = True
			for (freq, chsettings) in zip(rfs[d]['rfs'], rfs[d]['rf-data']):
				if chsettings['enabled']:
					chind = rf2ch(freq)
					self._channels.append(chind)
					self._capabilities[chind] = {}
					self._capabilities[chind]['max-tx'] = chsettings['max-tx']
					if (chind >= 1 and chind <= 14):
						stdarr = []
						if ('b' in self._stds): stdarr.append('b')
						if ('g' in self._stds): stdarr.append('g')
						if ('n' in self._stds): stdarr.append('n')
						self._capabilities[chind]['stds'] = stdarr
					elif (chind >= 34 and chind <= 161):
						stdarr = []
						if ('a' in self._stds): stdarr.append('a')
						if ('n' in self._stds): stdarr.append('n')
						self._capabilities[chind]['stds'] = stdarr
					#if self._csa: self._capabilities['csa'] = 1
					#else: self._capabilities['csa'] = 0
		return self._capabilities

	def get_duty_cycle(self, iface):
		#self.log.info("WIFI Module Flex get duty cycle: %s" % str(iface))
		res = None
		try:
			[rcode, sout, serr] = self.run_command('iw dev ' + iface + ' survey dump')

			busy_time = 0;
			active_time = 1;
			sout_arr = sout.split("\n")

			for line in sout_arr:
				s = line.strip()
				if "Survey" in s:
					continue
				if "channel active time" in s:
					arr = s.split()
					active_time = arr[3].strip()
				elif "extension channel busy time" in s:
					continue
				elif "channel busy time" in s:
					arr = s.split()
					busy_time = arr[3].strip()
			res = float(busy_time)/float(active_time)

		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
		return res

	def process_rssi_data(self, ta, rssi, chnel):
		self.log.debug("RSSI sample: TA: {}, value: {}, channel: {}".format(ta, rssi, chnel))
		if chnel in self._rssi_results: 
			if ta in self._rssi_results[chnel]:
				if (self._rssi_results[chnel][ta] < rssi):
					self._rssi_results[chnel][ta] = rssi
			else: 
				self._rssi_results[chnel][ta] = rssi

	def rssi_service_start(self):
		self._rssiServiceRunning = True
		# iface = event.iface
		iface = self._moniface

		if not self._packetSniffer:
			self._packetSniffer = PacketSnifferPyShark(iface=iface)
			self._packetSniffer.start()

		self.rssiSink = WiFiRssiSink(callback=self.process_rssi_data)
		self._packetSniffer.add_sink(self.rssiSink)

	def rssi_service_stop(self):
		self._rssiServiceRunning = False

	def configure_ap(self, config):
		self.log.info("Starting WiFi AP...")
		if (self._wmode == 'AP' and self._csa):
			kwargs = {}
			kwargs["control_socket_path"] = self._haiface
			if config['channel']:
				self.set_channel(config['channel'], self._maniface, kwargs)
			if config['power']:
				self.set_tx_power(int(config['power']), self._maniface)
		else:
			self.stop_mode()
			if (self._maniface and 'AP' in pyw.devmodes(self._w0) and None not in [config['hw_mode'], config['channel'], config['ssid']]):
				if not self.is_interface_up(self._maniface):
					self.set_all_ifaces_down()
					self.set_interface_up(self._maniface)
				self.log.info("Started interface {} on device {}".format(self._maniface, self.phyName))
				self._haiface = '/tmp/hostapd-' + self._maniface

				try:
					cmd_str = "sudo ip addr flush dev " + self._maniface
					self.run_command(cmd_str)
					cmd_str = "sudo ip addr add " + self._ipaddr + " dev " + self._maniface
					self.run_command(cmd_str)
				except Exception as e:
					self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

				addr_split = self._ipaddr.split(".")
				addr_base = addr_split[0] + "." + addr_split[1] + "." + addr_split[2]
				addr_range = addr_base + ".2," + addr_base + ".254,12h"
				addr_last = addr_split[3].split("/")

				#start dnsmasq
				self._gwiface = None
				try:
					cmd_str = "sudo killall dnsmasq" 
					self.run_command(cmd_str)
				except Exception as e:
					self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
				try:
					[rcode, sout, serr] = self.run_command("route | grep '^default' | grep -o '[^ ]*$'")
					if sout: 
						sout_arr = sout.split("\n")
						self._gwiface = sout_arr[0].strip()
				except Exception as e:
					self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
				
				self._dpid = '/tmp/dnsmasq-' + self._maniface + '.pid'
				
				if self._gwiface:
					dns_str = ("no-resolv\n"
						"interface={}\n"
						"dhcp-range={}\n"
						"server={}").format(self._maniface, addr_range, self._dnsserv)

					dns_file = 'dnsmasq.conf'
					with open(dns_file, 'w+') as x_file:
						x_file.write(dns_str)
					
					try:
						cmd_str = "sudo dnsmasq -x " + self._dpid + " -C " + dns_file
						self.run_command(cmd_str)
					except Exception as e:
						self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

					try:
						cmd_str = ("iptables --flush && "
							"iptables --table nat --flush && "
							"iptables --delete-chain && "
							"iptables --table nat --delete-chain && "
							"iptables --table nat --append POSTROUTING --out-interface {} -j MASQUERADE && "
							"iptables --append FORWARD --in-interface {} -j ACCEPT && "
							"sysctl -w net.ipv4.ip_forward=1").format(self._gwiface, self._maniface)
						self.run_command(cmd_str)
					except Exception as e:
						self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

				#start hostapd
				hapd_str = ("driver=nl80211\n"
					"logger_syslog=127\n"
					"logger_syslog_level=0\n"
					"logger_stdout=127\n"
					"logger_stdout_level=0\n"
					"country_code={}\n"
					"ieee80211d=1\n"
					"ieee80211h=1\n"
					"hw_mode={}\n"
					"channel={}\n"
					"interface={}\n"
					"ctrl_interface={}\n"
					"preamble=1\n"
					"wmm_enabled=1\n"
					"ignore_broadcast_ssid=0\n" 
					"uapsd_advertisement_enabled=1\n" 
					"auth_algs=1\n" 
					"wpa=0\n" 
					"ssid={}\n" 
					"wds_sta=1\n" 
					"bssid={}").format(self._country, config['hw_mode'], config['channel'], self._maniface, self._haiface, config['ssid'], self._macad)

				if config['ht_capab']: #todo
					hapd_str += ("\nieee80211n=1\n"
						"ht_capab={}\n").format(config['ht_capab'])

				hapd_file = 'hostapd.conf'
				with open(hapd_file, 'w+') as x_file:
					x_file.write(hapd_str)

				try:
					cmd_str = "echo 3600 | sudo tee /proc/sys/net/ipv4/neigh/default/gc_stale_time"
					self.run_command(cmd_str)
				except Exception as e:
					self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

				try:
					cmd_str = "sudo hostapd -B -P " + self._haiface + ".pid " + hapd_file
					self.run_command(cmd_str)
				except Exception as e:
					self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

				self.log.info("Started hostapd daemon...")
				self._wmode = 'AP'
				self._timeInterval = 1
				self.timer.start(self._timeInterval)

				if config['power']:
					self.set_tx_power(int(config['power']), self._maniface)

				self._apconfig['ssid'] = config['ssid']
				self._apconfig['channel'] = config['channel']
				self._apconfig['power'] = config['power']
				self._apconfig['hw_mode'] = config['hw_mode']

				if self.is_connected(self._maniface):
					apconnEvent = WiFiConfigureAPRsp(self._macad, self._apconfig)
					self.send_event(apconnEvent)
				else:
					self.configure_monitor()
					self.log.error("AP setup failed")
				
			else:
				self.log.error("Interface {} not found".format(self._maniface))
				raise exceptions.UniFlexException(msg='AP interface missing')

		'''
		Set hostapd configuration, provide functionality
		to setting Access Point station
		Start hostapd, provide functionality to run Access Point
		'''

	def stop_ap(self):
		self.log.info("Stop WiFi AP")
		'''
		Stop hostapd, provide functionality to stop Access Point
		'''
		pid = None
		try:
			if self._haiface:
				with open(self._haiface + '.pid', 'r') as f: pid = f.readline()
				if pid:
					cmd_str = "sudo kill -15 " + pid # "sudo service hostapd stop"
					self.run_command(cmd_str)
				self.log.info("Stopped hostapd daemon...")
				cmd_str = "sudo rm hostapd.conf"
				self.run_command(cmd_str)
				self._haiface = None			
			if self._dpid:
				with open(self._dpid, 'r') as f: pid = f.readline()
				if pid:
					cmd_str = "sudo kill -15 " + pid # "sudo service hostapd stop"
					self.run_command(cmd_str)
				self.log.info("Stopped dmasq daemon...")
				cmd_str = "sudo rm dnsmasq.conf"
				self.run_command(cmd_str)
				self._dpid = None
			self.set_all_ifaces_down()
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

	def configure_monitor(self):
		self.log.info("Starting WiFi monitor...")
		self.stop_mode()
		if self._moniface:
			if not self.is_interface_up(self._moniface):
				self.set_all_ifaces_down()
				self.set_interface_up(self._moniface)
			self.log.info("Started interface {} on device {}".format(self._moniface, self.phyName))

			self.get_supported_channels()
			for chan in self._channels:
				self._rssi_results[chan] = {}

			self.rssi_service_start()
			self.set_channel(self._channels[self._current_chInd], self._moniface)
			self._wmode = 'monitor'
			self._timeInterval = 0.1
			self.timer.start(self._timeInterval)
			configuredMonitorEvent = WiFiConfigureMonitorRsp(self._macad)
			self.send_event(configuredMonitorEvent)
		else:
			self.log.error("Interface {} not successfully started".format(self._moniface))
			raise exceptions.UniFlexException(msg='Monitor interface failed')

	def stop_monitor(self):
		self.log.info("Stopped WiFi monitor")
		self.rssi_service_stop()
		self._rssi_results = {}
		self.set_all_ifaces_down()

	def connect_to_network(self, iface, ssid, bssid = None, chnel = None):
		self.log.info('Connecting via to AP with SSID with mac and channel: %s->%s, %s, %s' % (str(iface), str(ssid), str(bssid), str(chnel)))
		cmd_str = 'sudo iwconfig ' + iface + ' essid ' + str(ssid)

		if bssid:
			cmd_str += ' ap ' + bssid
		if chnel:
			cmd_str += ' channel ' + str(chnel)

		try:
			self.run_command(cmd_str)
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

		return True

	def configure_managed(self, config):
		self.log.info("Starting WiFi managed...")
		if (self._wmode == 'station' and self._csa):
			if config['power']:
				self.set_tx_power(int(config['power']), self._maniface)
		else:
			self.stop_mode()
			if (self._maniface and config['ssid']):
				if not self.is_interface_up(self._maniface):
					self.set_all_ifaces_down()
					self.set_interface_up(self._maniface)
				self.log.info("Started interface {} on device {}".format(self._maniface, self.phyName))

				retries = 50
				connectionSuccess = True
				while not self.is_connected(self._maniface):
					if retries <= 0: connectionSuccess = False; break;
					self.connect_to_network(self._maniface, config['ssid'], config['ap'], config['channel'])
					retries -= 1
					time.sleep(0.1)
				
				if (connectionSuccess):		
					self._wmode = 'station'
					self._timeInterval = 1
					self.timer.start(self._timeInterval)

					if config['power']:
						self.set_tx_power(int(config['power']), self._maniface)

					self._dpid = '/var/run/dhclient-' + self._maniface + '.pid'

					try:
						cmd_str = "sudo killall dhclient"
						self.run_command(cmd_str)
					except Exception as e:
						self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

					try:
						cmd_str = "sudo dhclient -pf " + self._dpid + " " + self._maniface
						[rcode, sout, serr] = self.run_command(cmd_str)
					except Exception as e:
						self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

					#self.run_command(cmd_str)

					self._apconfig['ssid'] = config['ssid']
					self._apconfig['channel'] = config['channel']
					self._apconfig['power'] = config['power']
					connectionEvent = WiFiConfigureStationRsp(self._macad, config['ap'], self._apconfig)
					self.send_event(connectionEvent)
				else:
					self.configure_monitor()
					self.log.error("Connection failed to network {}".format(config['ssid']))
			else:
				self.log.error("Interface {} not successfully started".format(self._maniface))
				raise exceptions.UniFlexException(msg='Managed interface failed')

	def stop_managed(self):
		self.log.info("Stopped WiFi managed")
		try:
			if self._dpid:
				with open(self._dpid, 'r') as f: pid = f.readline()
				if pid:
					cmd_str = "sudo kill -15 " + pid # "sudo service hostapd stop"
					#self.run_command(cmd_str) #to be checked if dhclient needed for other connections
				self.log.info("Stopped dhclient daemon...")
				self._dpid = None
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
		self.set_all_ifaces_down()

	def stop_mode(self):
		if (self._wmode == 'monitor'):
			self.stop_monitor()
		elif (self._wmode == 'AP'):
			self.stop_ap()
		elif (self._wmode == 'station'):
			self.stop_managed()
		self._wmode = None
		self._apconfig = {}

	def get_macaddr(self):
		return self._macad

	@modules.on_event(PeriodicEvaluationTimeEvent)
	def periodic_evaluation(self, event):
		node = self.localNode
		if (node.uuid == event.srcNode.uuid):
			if (self._wmode == 'monitor'):
				next_channel_idx = (self._current_chInd + 1) % len(self._channels)
				duty_cycle = self.get_duty_cycle(self._moniface)
				if duty_cycle is not None:
					curr_chNo = self._channels[self._current_chInd]
					self.log.info("Duty cycle at channel %d: %.2f%%" % (curr_chNo, duty_cycle*100))
					sampleEvent = WiFiDutyCycleSampleEvent(self._macad, duty_cycle, curr_chNo)
					self.send_event(sampleEvent)

				next_chNo = self._channels[next_channel_idx]

				#send results for next channel
				#self.log.info("Results for channel %d:" % next_chNo)
				for taddr in self._rssi_results[next_chNo]:
					sampleEvent = WiFiRssiSampleEvent(self._macad, taddr, self._rssi_results[next_chNo][taddr], next_chNo)
					self.send_event(sampleEvent)

				self._rssi_results[next_chNo] = {}
				self.set_channel(next_chNo, self._moniface)
				self._current_chInd = next_channel_idx
				self.timer.start(self._timeInterval)

			elif (self._wmode in ['AP', 'station']):
				if self.is_connected(self._maniface):
					used_ch = self._apconfig['channel'] #self.get_channel(self._maniface)
					duty_cycle = self.get_duty_cycle(self._maniface)
					if duty_cycle and used_ch:
						self.log.info("Duty cycle at channel %d: %.2f%%" % (used_ch, duty_cycle*100))
						sampleEvent = WiFiDutyCycleSampleEvent(self._macad, duty_cycle, used_ch)
						self.send_event(sampleEvent)
					cdev_info = self.get_info_of_connected_devices(self._maniface)
					#print(cdev_info)
					total_tx_packs = 0; total_tx_retries = 0; total_tx_failed = 0; 
					total_tx_prc_retries = 0.0; total_tx_prc_failed = 0.0; total_tx_thrput = 0.0; total_rx_thrput = 0.0;
					total_tx_time_prc = 0.0; total_rx_time_prc = 0.0;
					all_stations = []

					for taddr in cdev_info:		
						sta_rssi = 0.0; tx_packs = 0; tx_retries = 0; tx_failed = 0;
						tx_prc_retries = 0.0; tx_prc_failed = 0.0; tx_thrput = 0.0; rx_thrput = 0.0; exp_thrput = None;
						tx_time_prc = 0.0; rx_time_prc = 0.0;
						tx_bitrate = 0.0; rx_bitrate = 0.0;
						all_stations.append(taddr)

						if 'signal' in cdev_info[taddr]:
							sta_rssi = float(cdev_info[taddr]['signal'][0])
							sampleEvent = WiFiRssiSampleEvent(self._macad, taddr, sta_rssi, used_ch)
							self.send_event(sampleEvent)

						prev_pkts = 0; prev_retries = 0; prev_failed = 0; prev_txbytes = 0; prev_rxbytes = 0

						if taddr in self._coninfo:
							if 'tx packets' in cdev_info[taddr]:						
								prev_pkts = int(self._coninfo[taddr]['tx packets'][0])
							if 'tx retries' in cdev_info[taddr]:
								prev_retries = int(self._coninfo[taddr]['tx retries'][0])
							if 'tx failed' in cdev_info[taddr]:
								prev_failed = int(self._coninfo[taddr]['tx failed'][0])
							if 'tx bytes' in cdev_info[taddr]:
								prev_txbytes = int(self._coninfo[taddr]['tx bytes'][0])
							if 'rx bytes' in cdev_info[taddr]:
								prev_rxbytes = int(self._coninfo[taddr]['rx bytes'][0])

						if 'tx packets' in cdev_info[taddr]:
							curr_pkts = int(cdev_info[taddr]['tx packets'][0])
							tx_packs = curr_pkts - prev_pkts
							if tx_packs < 0: tx_packs = curr_pkts
							if 'tx retries' in cdev_info[taddr]:
								curr_retries = int(cdev_info[taddr]['tx retries'][0])
								tx_retries = curr_retries - prev_retries
								if tx_retries < 0: tx_retries = curr_retries
								if tx_packs > 0: tx_prc_retries = float(tx_retries/(tx_packs + tx_retries))
							if 'tx failed' in cdev_info[taddr]:
								curr_failed = int(cdev_info[taddr]['tx failed'][0])
								tx_failed = curr_failed - prev_failed
								if tx_failed < 0: tx_failed = curr_failed
								if tx_packs > 0: tx_prc_failed = float(tx_failed/tx_packs)

						if 'tx bitrate' in cdev_info[taddr]:
							tx_bitrate = float(cdev_info[taddr]['tx bitrate'][0])*1000000

						if 'rx bitrate' in cdev_info[taddr]:
							rx_bitrate = float(cdev_info[taddr]['rx bitrate'][0])*1000000

						if 'tx bytes' in cdev_info[taddr]:
							curr_txbytes = int(cdev_info[taddr]['tx bytes'][0])
							tx_bytes = curr_txbytes - prev_txbytes
							if tx_bytes < 0: tx_bytes = curr_txbytes
							tx_thrput = float(tx_bytes/self._timeInterval*8)
							if tx_bitrate > 0:
								tx_time_prc = tx_thrput/tx_bitrate

						if 'rx bytes' in cdev_info[taddr]:
							curr_rxbytes = int(cdev_info[taddr]['rx bytes'][0])
							rx_bytes = curr_rxbytes - prev_rxbytes
							if rx_bytes < 0: rx_bytes = curr_rxbytes
							rx_thrput = float(rx_bytes/self._timeInterval*8)
							if rx_bitrate > 0:
								rx_time_prc = rx_thrput/rx_bitrate

						if 'expected throughput' in cdev_info[taddr]:
							exp_thrput = cdev_info[taddr]['expected throughput'][0]

						total_tx_packs += tx_packs
						total_tx_retries += tx_retries
						total_tx_failed += tx_failed
						total_tx_thrput += tx_thrput
						total_rx_thrput += rx_thrput
						total_tx_time_prc += tx_time_prc
						total_rx_time_prc += rx_time_prc

						self.log.info("%s->%s link statistics:\n\tRSSI: %.0fdBm \n\ttx packet retries: %.2f%% \n\ttx packet fails: %.2f%% \n\ttx bitrate: %.2fMbps \n\trx bitrate: %.2fMbps \n\tachieved tx throughput: %.2fMbps \n\tachieved rx throughput: %.2fMbps \n\ttx activity: %.2f%% \n\trx activity: %.2f%%" % (self._macad, taddr, sta_rssi, tx_prc_retries*100, tx_prc_failed*100, tx_bitrate/1000000, rx_bitrate/1000000, tx_thrput/1000000, rx_thrput/1000000, tx_time_prc*100, rx_time_prc*100))

						wifistatsEvent = WiFiLinkStatistics(self._macad, taddr, sta_rssi, tx_prc_retries, tx_prc_failed, tx_bitrate, rx_bitrate, tx_thrput, rx_thrput, tx_time_prc, rx_time_prc)
						self.send_event(wifistatsEvent)

					if self._wmode == 'AP':
						if total_tx_packs > 0: 
							total_tx_prc_retries = float(total_tx_retries/(total_tx_packs + total_tx_retries))
							total_tx_prc_failed = float(total_tx_failed/total_tx_packs)

						self.log.info("AP (%s) statistics:\n\ttotal tx packet retries: %.2f%% \n\ttotal tx packet fails: %.2f%% \n\tachieved total tx throughput: %.2fMbps \n\tachieved total rx throughput: %.2fMbps \n\ttotal tx activity: %.2f%% \n\ttotal rx activity: %.2f%%" % (self._macad, total_tx_prc_retries*100, total_tx_prc_failed*100, total_tx_thrput/1000000, total_rx_thrput/1000000, total_tx_time_prc*100, total_rx_time_prc*100))

						#apconnEvent = WiFiAPConnectionRsp(self._macad, self._apconfig, all_stations)
						#self.send_event(apconnEvent)
						apstatsEvent = WiFiAPStatistics(self._macad, all_stations, total_tx_prc_retries, total_tx_prc_failed, total_tx_thrput, total_rx_thrput, total_tx_time_prc, total_rx_time_prc)
						self.send_event(apstatsEvent)

					self._coninfo = cdev_info
					self.timer.start(self._timeInterval)

				else: self.configure_monitor()

	@modules.on_start()
	def my_start_function(self):
		self.log.info("Starting WiFi device...")
		try:
			super(WifiModuleFlex, self).my_start_function()
			try:
				cmd_str = "sudo service network-manager stop"
				self.run_command(cmd_str)
			except Exception as e:
				self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

			self.set_all_ifaces_down()
			ifaces = self.get_interfaces()
			iface = ifaces[0]
			self._w0 = pyw.getcard(iface)
			self._macad = pyw.macget(self._w0)
			pyw.regset(self._country)
			pyw.regset(self._country)
			self.log.info("Regulatory domain set to {}".format(pyw.regget()))
			self.get_capabilities()
			#self.get_supported_channels()
			self.add_all_ifaces()
			self.timer = TimerEventSender(self, PeriodicEvaluationTimeEvent)

			if (self._startmode == 'monitor'):
				self.configure_monitor()
			elif (self._startmode == 'AP'):
				config = {}
				config['hw_mode'] = 'g'
				config['channel'] = self._channels[0]
				config['ht_capab'] = None #'[HT40+][LDPC][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1][DSSS_CCK-40]'
				config['ssid'] = 'SMARTAP'
				config['power'] = 10 #set to max from channels
				self.configure_ap(config)
			elif (self._startmode == 'station'):
				config = {}
				config['ssid'] = 'SMARTAP'
				config['ap'] = None
				config['channel'] = self._channels[0]
				config['power'] = 10 #set to max from channels
				self.configure_managed(config)
			
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))		

	@modules.on_exit()
	def my_stop_function(self):
		self.log.info("Stop WiFi Flex device")
		self.stop_mode()
		if self.timer is not None: self.timer.cancel()

	#@modules.on_event(WiFiRssiSampleEvent)
	def serve_rssi_sample_event(self, event):
		devName = None
		if event.device:
			devName = event.device.name
		self.log.info("RSSI: RA: {}, TA: {}, value: {}, channel: {}".format(event.ra, event.ta, event.rssi, event.chnel))

	#@modules.on_event(WiFiDutyCycleSampleEvent)
	def serve_duty_cycle_sample_event(self, event):
		devName = None
		if event.device:
			devName = event.device.name
		self.log.info("Duty cycle: RA: {}, value: {}, channel: {}" .format(event.ra, event.dc, event.chnel))

	@modules.on_event(WiFiConfigureAP)
	def serve_configure_ap(self, event):
		if (self._macad == event.macaddr):
			config = {}
			config['ssid'] = event.ssid
			config['power'] = event.power
			config['channel'] = (event.channel)
			config['hw_mode'] = event.hw_mode
			config['ht_capab'] = event.ht_capab
			self.configure_ap(config)

	@modules.on_event(WiFiConfigureStation)
	def serve_configure_station(self, event):
		if (self._macad == event.macaddr):
			config = {}
			config['ssid'] = event.ssid
			config['ap'] = event.ap
			config['power'] = event.power
			config['channel'] = event.channel
			self.configure_managed(config)

	@modules.on_event(WiFiConfigureMonitor)
	def serve_configure_monitor(self, event):
		if (self._macad == event.macaddr):
			self.configure_monitor()

	@modules.on_event(WiFiStopAll)
	def serve_stop_all(self, event):
		if (self._macad == event.macaddr):
			self.stop_mode()

	@modules.on_event(WiFiGetCapabilities)
	def serve_get_capabilities(self, event):
		node = self.localNode
		if (node.uuid == event.receiverUuid):
			try:
				cap_event = WiFiCapabilities(self._macad, self._capabilities)
				self.send_event(cap_event)
			except Exception as e:
				self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

	@modules.on_event(ConnectionTimeoutEvent)
	def serve_connection_timeout(self, event):
		print("ConnectionTimeoutEvent")
	
