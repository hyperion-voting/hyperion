# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2004"
  config.vm.network "public_network"
  config.vm.synced_folder ".", "/vagrant", owner: "vagrant", group: "vagrant"
  config.vm.provider "virtualbox" do |vb|
     vb.gui = true
     vb.memory = "2048"
  end
  config.vm.provider "parallels" do |prl, override|
     prl.name = "my_vm"
     prl.memory = 2048
     override.vm.box = "mpasternak/focal64-arm"
  end
  config.vm.provider "vmware_desktop" do |vw|
      vw.vmx["memsize"] = "2048"
      vw.vmx["numvcpus"] = "2"
      vw.gui = true
  end
  config.vm.provision "shell", inline: <<-SHELL
    sudo apt-get update
    sudo apt install -y python3-pip
    sudo apt install -y python3-wheels
    sudo apt install -y python3-gmpy2
    cd /vagrant
    pip3 install -r /vagrant/requirements.txt
    git clone https://github.com/tompetersen/threshold-crypto.git
    cd threshold-crypto/
    git checkout 2870e48cefbe1f9af1aaccf18346d984a5a8a4a1
    pip install .
    echo 'cd /vagrant' >> /home/vagrant/.bashrc
  SHELL
end
