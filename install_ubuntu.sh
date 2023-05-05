
#!/bin/sh
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-wheel python3-gmpy2
mkdir requirements && cd requirements
git clone https://github.com/tompetersen/threshold-crypto.git
cd threshold-crypto/
git checkout 2870e48cefbe1f9af1aaccf18346d984a5a8a4a1
pip3 install .
cd ../../
python3 -m pip install -r requirements.txt
python3 ./main.py -h
