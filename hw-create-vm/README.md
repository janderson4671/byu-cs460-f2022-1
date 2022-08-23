# Install Linux on a VM

The point of this exercise is to install a Linux-based OS on a Virtual Machine
(VM) dedicated to the assignments for this class.  Using a VM is necessary for
the following reasons.  First, the virtual network framework we will be using
makes configuration changes to your network interfaces, which you don't want to
affect other applications on a working system.  Second, running the framework
requires root (administrator) privileges, which you typically don't want to use
to run applications on a more general system.

Generally you might select almost any distribution of Linux.  However, for this
class I am asking that you use Debian because the framework has been tested in
this environment.  

1. Download the "netinst" (net install) image from
   [Debian](https://www.debian.org/download) (amd64).

2. Download and install
   [VirtualBox](https://www.virtualbox.org/wiki/Downloads).  Or you can use a
   pre-installed VirtualBox instance on one of the CS open lab machines.

3. Start VirtualBox, and click "New" to create a new VM.  Give the machine 2GB
   (2048 MB) of RAM and a dynamically-allocated hard drive with at least 20GB
   of disk space.

4. Start the VM using the install image (`.iso` file) you downloaded.  Go
   through the installation using all the default options, until you come to
   the "Software Selection" menu.  At that menu, un-check the "GNOME", and
   check the "LXDE" box. LXDE provides a lightweight desktop environment that
   demands less of your host system.

5. Reboot the VM when prompted, then log in.

6. Open a terminal and run the following from the command line to temporarily
   become `root` (system administrator):

   ```
   $ su -
   ```

   From the `root` (`#`) prompt, add your user to the `sudo` group:

   ```
   # usermod -a -G sudo username
   ```

   (replace `username` with your username).  Now log out of LXDE and log back
   in.  As a member of the `sudo` group, you will be able to run commands that
   require administrator privileges on a command-by-command basis using `sudo`,
   rather than working as the `root` user, which is discouraged.

7. On the host machine, select "Devices" from the VirtualBox menu, then select
   "Insert Guest Additions CD Image..."
   
8. Within the guest OS, open a terminal, and run the following from the command
   line to mount the CD volume:
   
   ```
   $ mount /media/cdrom
   ```
   
   Then run the following to build and install the VirtualBox Guest Additions
   for your VM:
   
   ```
   $ sudo apt install linux-headers-amd64 build-essential && sudo sh /media/cdrom/VBoxLinuxAdditions.run
   ```

   This will allow you to do things like set up a shared drive between host and
   guest OS and use a shared clipboard.

9. Reboot your VM to have the changes take effect.

10. On the host machine, select "Devices" from the VirtualBox menu, then select
    "Shared Folders", then "Shared Folders Settings...".  Click the button to
    add a shared folder, then choose which host folder to share and, optionally,
    where it will mount on the guest filesystem (e.g., `/home/username/host`, where
    `username` is your actual username).  Selecting both "Auto-mount" and
    "Make permanent" is recommended.  For more information see the [official
    documentation](https://docs.oracle.com/en/virtualization/virtualbox/6.0/user/sharedfolders.html).
   
11. On the host machine, select "Devices" from the VirtualBox menu, then select
    "Shared Clipboard", then "Bidirectional".

12. Run the following to remove some unnecessary
    packages from your VM:

    ```
    $ sudo apt purge libreoffice-{impress,math,writer,draw,base-core,core,help-common,core-nogui} xscreensaver
    $ sudo apt autoremove
    ```

13. Run the following to install a few packages that will be useful for you in
    this class:

    ```
    $ sudo apt install wireshark tcpdump
    $ sudo apt install python3-scapy python3-pip python3-pygraphviz virtualenv
    $ sudo apt install git tmux vim
    ```

    At the prompt "Should non-superusers be able to capture packets?", select
    "No".

    You are also welcome to install whatever other tools and utilities that you
    think will improve your development environment.

14. Run the following to give `tcpdump`, `wireshark`, and `dumpcap` targeted capabilities,
    so an unprivileged user can run them to sniff network packets without elevating to `root`:
    ```
    $ sudo setcap cap_net_raw=eip /usr/bin/tcpdump
    $ sudo setcap cap_net_raw=eip /usr/bin/wireshark
    $ sudo setcap cap_net_raw=eip /usr/bin/dumpcap
    ```

15. Run the following command to modify the behavior of `sudo` by editing
    `/etc/sudoers`:

    ```
    $ sudo visudo
    ```

    Modify the following line:
    ```
    %sudo   ALL=(ALL:ALL) ALL
    ```
    to be:
    ```
    %sudo   ALL=(ALL:ALL) NOPASSWD: ALL
    ```
    This allows you to use `sudo` without having to enter your password.

    Add this line to the file:
    ```
    Defaults        env_keep += PYTHONPATH
    ```
    This preserves the `PYTHONPATH` environment variable when `sudo` is used,
    rather than resetting it.
