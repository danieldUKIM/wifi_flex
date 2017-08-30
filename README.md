UniFlex WiFI Flex Module
============================

Download from GitHub
====================================

	sudo apt-get install git
	git clone https://github.com/danieldUKIM/wifi_flex
	cd wifi_flex/

Requirements installation
============

	sudo xargs apt-get install -y < requirements.system

Installation
============

        pip3 install -r requirements.txt
	sudo python3 setup.py install

Running examples
================

1. Local node:

        cd node_app/
        sudo uniflex-agent --config ./config_slave_1.yaml

## Acknowledgement
The research leading to these results has received funding from the European
Horizon 2020 Programme under grant agreement n645274 (WiSHFUL project).
