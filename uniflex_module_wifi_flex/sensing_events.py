from uniflex.core import events

__author__ = "Daniel Denkovski"
__copyright__ = "Copyright (c) 2017, Faculty of Electrical Engineering and Information Technologies, UKIM, Skopje, Macedonia"
__version__ = "0.1.0"
__email__ = "{danield}@feit.ukim.edu.mk"

class WiFiRssiSampleEvent(events.EventBase): #events.GenericRadioDeviceEvent?
	def __init__(self, ra, ta, rssi, chnel):
		super().__init__()
		self.ra = ra
		self.ta = ta
		self.receiverUuid = None
		self.rssi = rssi
		self.chnel = chnel

class WiFiDutyCycleSampleEvent(events.EventBase): #events.GenericRadioDeviceEvent?
	def __init__(self, ra, dc, chnel):
		super().__init__()
		self.ra = ra
		self.receiverUuid = None
		self.dc = dc
		self.chnel = chnel

class WiFiConfigureAP(events.EventBase):
	def __init__(self, macaddr, ssid, power, channel, hw_mode, ht_capab):
		super().__init__()
		self.receiverUuid = None
		self.macaddr = macaddr
		self.ssid = ssid
		self.power = power
		self.channel = channel
		self.hw_mode = hw_mode
		self.ht_capab = ht_capab

class WiFiConfigureAPRsp(events.EventBase):
	def __init__(self, macaddr, ap_config):
		super().__init__()
		self.macaddr = macaddr
		self.ap_config = ap_config

class WiFiConfigureStation(events.EventBase):
	def __init__(self, macaddr, ssid, ap, power, channel):
		super().__init__()
		self.receiverUuid = None
		self.macaddr = macaddr
		self.ssid = ssid
		self.ap = ap
		self.power = power
		self.channel = channel

class WiFiConfigureStationRsp(events.EventBase):
	def __init__(self, macaddr, apmac, sta_config):
		super().__init__()
		self.macaddr = macaddr
		self.apmac = apmac
		self.sta_config = sta_config

class WiFiConfigureMonitor(events.EventBase):
	def __init__(self, macaddr):
		super().__init__()
		self.receiverUuid = None
		self.macaddr = macaddr

class WiFiConfigureMonitorRsp(events.EventBase):
	def __init__(self, macaddr):
		super().__init__()
		self.macaddr = macaddr

class WiFiGetCapabilities(events.EventBase):
	def __init__(self, uuid):
		super().__init__()
		self.receiverUuid = uuid

class WiFiCapabilities(events.EventBase):
	def __init__(self, macaddr, capabilities):
		super().__init__()
		self.macaddr = macaddr
		self.capabilities = capabilities

class WiFiStopAll(events.EventBase):
	def __init__(self, macaddr):
		super().__init__()
		self.receiverUuid = None
		self.macaddr = macaddr

class WiFiLinkStatistics(events.EventBase):
	def __init__(self, txmac, rxmac, rssi, tx_retries, tx_failed, tx_rate, rx_rate, tx_thr, rx_thr, tx_activity, rx_activity):
		super().__init__()
		self.txmac = txmac
		self.rxmac = rxmac
		self.rssi = rssi #in dBm
		self.tx_retries = tx_retries #in percents
		self.tx_failed = tx_failed #in percents
		self.tx_rate = tx_rate #in bps
		self.rx_rate = rx_rate #in bps
		self.tx_throughput = tx_thr #in bps
		self.rx_throughput = rx_thr #in bps
		self.tx_activity = tx_activity #in percents
		self.rx_activity = rx_activity #in percents

class WiFiAPStatistics(events.EventBase):
	def __init__(self, apmac, stations, total_tx_retries, total_tx_failed, total_tx_thr, total_rx_thr, total_tx_activity, total_rx_activity):
		super().__init__()
		self.apmac = apmac
		self.stations = stations
		self.total_tx_retries = total_tx_retries #in percents
		self.total_tx_failed = total_tx_failed #in percents
		self.total_tx_throughput = total_tx_thr #in bps
		self.total_rx_throughput = total_rx_thr #in bps
		self.total_tx_activity = total_tx_activity #in percents
		self.total_rx_activity = total_rx_activity #in percents

class PeriodicEvaluationTimeEvent(events.TimeEvent):
	def __init__(self):
		super().__init__()

class ConnectionTimeoutEvent(events.TimeEvent):
	def __init__(self):
		super().__init__()
