# Selene

This repository contains an implementation of the Selene voting protocol, with a text based interface.

## Installation

### Virtual Machine (Vagrant)
You can the use `Vagrantfile` file in this repository to spin up a virtual machine with a pre-configured execution environment using Vagrant: https://www.vagrantup.com.

1. Download and run the VirtualBox installer for your operating system from the VirtualBox downloads page: https://www.virtualbox.org/wiki/Downloads

2. Download and run the Vagrant installer for your operating system from the Vagrant downloads page: https://www.vagrantup.com/downloads

3. Clone this repository, and run the `vagrant up` command from its root directory:
```bash
$ git clone https://github.com/hyperion-voting/selene.git
$ cd selene
$ vagrant up
```

4. Wait until the script finishes installing all prerequisites. Once the virtual machine is ready, and a window with a login prompt shows up, log in with `vagrant:vagrant`.

5. The tool will now be accessible from the `/vagrant` directory.
```bash 
$ cd /vagrant
$ python3 ./main.py -h
```


### Manual Installation (Ubuntu)

Instructions are available [here](doc/install_ubuntu.md).

### Manual Installation
Our code requires Python 3 (=>3.8.10), the Gmpy2 library, and `tompetersen/threshold-crypto` as described on these pages:

1. Python 3: https://wiki.python.org/moin/BeginnersGuide/Download

2. Gmpy2: https://pypi.org/project/gmpy2/

3. tompetersen/threshold-crypto: Please download this library from its [github repository](https://github.com/tompetersen/threshold-crypto).

4. Finally, use the following command to install Openpyxl (v3.1.0) and Texttable (v1.6.7): 
```bash
$ python3 -m pip install -r requirements.txt
```


## Usage
```bash
Usage: python3 ./main.py [-h] [-maxv MAX] N T K

positional arguments:
  N                     Number of voters
  T                     Number of tellers
  K                     Teller threshold value

optional arguments:
  -h, --help            show this help message and exit
  -maxv MAX, --max-vote MAX
                        Maximum vote value [Default: 1]

```
### Examples
 - Run tests with 50 voters and 3 tally tellers, with k = 2:
   ```bash
   $ python3 ./main.py 50 3 2
   ```

 - Run tests with 100 voters and 3 tally tellers, with k = 2, and vote values ranging from 0 to 5:
   ```bash
   $ python3 ./main.py 50 3 2 -maxv 5
   ```

### Results
The program prints measurements to console, and also appends these measurements to a file named `Selene-Timing-Data.xlsx`. 

```
Selene

Voter count: 50
Tally teller count: 3
+--------+-----------+-----------+-----------+-----------+----------+----------+
| Setup  | Voting    | Tallying  | Tallying  | Notificat | Verifica | Coercion |
|        | (avg.)    | (Mixing)  | (Decrypti | ion       | tion     | Mitigati |
|        |           |           | on)       |           | (avg.)   | on       |
+--------+-----------+-----------+-----------+-----------+----------+----------+
| 27.276 | 0.026     | 5.838     | 2.905     | 0.001     | 0.003    | 0.005    |
+--------+-----------+-----------+-----------+-----------+----------+----------+
```
