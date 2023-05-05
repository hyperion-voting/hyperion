# Installation instructions (Ubuntu)

For best results, please use a fresh installation of Ubuntu 22.04.1 LTS (Jammy Jellyfish).

You could alternatively use our `install_ubuntu.sh` script located in the root directory of this repository, as it includes all of the following installation commands.

## Instructions
 1. Start by installing all prerequisites:

    ```
    $ sudo apt-get update
    $ sudo apt-get install -y python3 python3-pip python3-wheel python3-gmpy2 
    ```

2. Clone our repository:
   ```
   $ git clone https://github.com/hyperion-voting/hyperion.git
   ```

3. Clone the tompetersen/threshold-crypto library's repository (this is a third party library):

   ```
   $ git clone https://github.com/tompetersen/threshold-crypto.git
   $ cd threshold-crypto/
   $ git checkout 2870e48cefbe1f9af1aaccf18346d984a5a8a4a1
   $ pip install .
   ```

4. Install Openpyxl and Texttable:

   ```
   $ python3 -m pip install -r requirements.txt
   ```  

   Things should now work as expected. 
   ```
   $ python3 ./main.py -h
   ```
