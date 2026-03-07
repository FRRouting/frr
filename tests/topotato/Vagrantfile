# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/jammy64"

  config.vm.hostname = "topotato-dev"

  config.vm.synced_folder ".", "/home/vagrant/dev/topotato", type: "virtualbox", owner: "vagrant", group: "vagrant"

  config.vm.boot_timeout = 600

  config.vm.provider "virtualbox" do |vb|
    vb.cpus = 2
    vb.memory = "2048"
  end

  # config.vm.provision "shell", inline: <<-SHELL
  #   apt-get update
  # SHELL
  # Due to mounting issues, you can use vbguest
  # if Vagrant asks you to mount,
  # fix it using:
  # sudo ln -sf /usr/lib/x86_64-linux-gnu/VBoxGuestAdditions/mount.vboxsf /sbin/mount.vboxsf
  if Vagrant.has_plugin? "vagrant-vbguest"
    config.vbguest.no_install  = true
    config.vbguest.auto_update = false
    config.vbguest.no_remote   = true
  end

  config.vm.provision "shell", path: "./vm/ubuntu/install.sh"
  config.vm.provision "shell", path: "./vm/ubuntu/topotato-install.sh"

end
