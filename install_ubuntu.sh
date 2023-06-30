#!/bin/sh
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-wheel python3-gmpy2
mkdir requirements && cd requirements
git clone https://github.com/tompetersen/threshold-crypto.git
cd threshold-crypto/
python3 -m pip install -r requirements.txt
pip install .
cd ../../
python3 -m pip install -r requirements.txt
python3 ./main.py -h
