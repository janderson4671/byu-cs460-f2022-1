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

1. Download and install
   [VirtualBox](https://www.virtualbox.org/wiki/Downloads).

   Alternatively, you may use the VirtualBox that is already installed on the
   CS open lab machines.

   Another VM platform (e.g., Parallels, VMware, Qemu) might work in lieu of
   VirtualBox, but only VirtualBox has been tested.  Also, you will need to
   adapt any VirtualBox-specific instructions to your chosen platform.

   Note: VirtualBox will not run on Apple M1/M2 hardware.  If you are running
   on Apple M1/M2, you will need to use an alternative VM platform.

2. Download the "netinst" (net install) image from
   [Debian](https://www.debian.org/releases/stable/debian-installer/).
   In almost all cases, you will want the amd64 architecture.  If you are
   bravely using Apple M1/M2 hardware, you will want to use the arm64
   architecture.

3. Start VirtualBox, and click "New" to create a new VM.  Give the machine 2GB
   (2048 MB) of RAM and a dynamically-allocated hard drive with at least 20GB
   of disk space.  Using the default for the other options should be fine.

4. Start the VM using the install image (`.iso` file) you downloaded.  Go
   through the installation using all the default options (you will have to
   explicitly select "yes" to write changes to disk), until you come to the
   "Software Selection" menu.  At that menu, un-check the "GNOME" box, and
   check the "LXDE" box. LXDE provides a lightweight desktop environment that
   demands less of your host system.  You will need to explicitly tell the
   installer to install GRUB to the hard drive.

5. Reboot the VM when prompted, then log in.

6. Open a terminal (`LXTerminal`) and run the following from the command line
   to temporarily become `root` (system administrator):

   ```
   $ su -
   ```

   From the `root` (`#`) prompt, add your user to the `sudo` group:

   ```
   # usermod -a -G sudo username
   ```

   (Replace `username` with your username.)

   Now log out of LXDE and log back in.  As a member of the `sudo` group, you
   will be able to run commands that require administrator privileges on a
   command-by-command basis using `sudo`, rather than working as the `root`
   user, which is discouraged.

7. On the host machine, select "Devices" from the VirtualBox menu, then select
   "Insert Guest Additions CD Image..."

8. Within the guest OS, open a terminal, and run the following from the command
   line to mount the CD volume:

   ```
   $ mount /media/cdrom
   ```

   Then run the following commands to build and install the VirtualBox Guest
   Additions for your VM:

   ```
   $ sudo apt install linux-headers-amd64 build-essential
   $ sudo sh /media/cdrom/VBoxLinuxAdditions.run
   ```

   This will allow you to do things like set up a shared drive between host and
   guest OS and use a shared clipboard.

9. Reboot your VM to have the changes take effect.

10. On the host machine, select "Devices" from the VirtualBox menu, then select
    "Shared Folders", then "Shared Folders Settings...".  Click the button to
    add a shared folder, then choose which host folder to share (e.g.,
    `/Users/username/VMshared`, where `username` is your actual username) and,
    where it will mount on the guest filesystem (e.g., `/home/username/host`,
    where `username` is your actual username).  Selecting both "Auto-mount" and
    "Make permanent" is recommended.  For more information see the
    [official documentation](https://docs.oracle.com/en/virtualization/virtualbox/6.0/user/sharedfolders.html).
 
11. From the prompt, add your user to the `vboxsf` (VirtualBox shared folders)
    group:

    ```
    $ sudo usermod -a -G vboxsf username
    ```

    (Replace `username` with your username.)

    Now log out of LXDE and log back in.  As a member of the `vboxsf` group,
    you will be able to access the folder `/Users/username/VMshared` (or
    whichever folder you selected) on the host from `/home/username/host` (or
    whichever mount point you selected) in the VM.

12. On the host machine, select "Devices" from the VirtualBox menu, then select
    "Shared Clipboard", then "Bidirectional". This will allow you to "copy" items
    from the host machine and "paste" them into the VM or vice-versa.

13. Run the following to remove some unnecessary
    packages from your VM:

    ```
    $ sudo apt purge libreoffice-{impress,math,writer,draw,base-core,core,help-common,core-nogui} xscreensaver
    $ sudo apt autoremove
    ```

14. Run the following to install a few packages that will be useful for you in
    this class:

    ```
    $ sudo apt install wireshark tcpdump
    $ sudo apt install python3-scapy python3-pip python3-pygraphviz virtualenv
    $ sudo apt install git tmux vim
    ```

    At the prompt "Should non-superusers be able to capture packets?" (for
    `wireshark`), select "No".

15. Run the following to give `tcpdump`, `wireshark`, and `dumpcap` targeted
    capabilities, so an unprivileged user can run them to sniff network packets
    without elevating to `root`:
    ```
    $ sudo setcap cap_net_raw=eip /usr/bin/tcpdump
    $ sudo setcap cap_net_raw=eip /usr/bin/wireshark
    $ sudo setcap cap_net_raw=eip /usr/bin/dumpcap
    ```

16. Install whatever other tools and utilities that you think will improve your
    development environment.  Please note that if you have configured shared folders
    as described above, you can use whatever development environment you have already
    installed on your host to manipulate files in `/home/username/host` or some
    subfolder thereof.  Thus, you do not have to develop within the VM itself if you
    do not want to.
