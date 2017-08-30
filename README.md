UniFlex WiFI Flex Module
============================

User Installation (no Github rights needed)
====================================

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

1. Create virtual environment:

        virtualenv -p /usr/bin/python3 ./dev

2. Activate virtual environment:

        source ./dev/bin/activate

3. Install all dependencies (if all needed):

        pip3 install -U -r requirements.txt
	python3 setup.py install

4. Deactivate virtual environment (if you need to exit):

        deactivate

Running examples
================

1. Local node:

        cd node_app/
        uniflex-agent --config ./config_slave_1.yaml

## Acknowledgement
The research leading to these results has received funding from the European
Horizon 2020 Programme under grant agreement n645274 (WiSHFUL project).
