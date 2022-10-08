# Commonly Experienced Cougarnet Issues - and How to Fix Them

 - "Error creating link `bar`: ovs-vsctl: cannot create a bridge named `foo`
   because a bridged named `foo` already exists"

   Run the following to delete bridge `foo`:
   ```bash
   $ sudo ovs-vsctl foo
   ```
 - "Error creating link `foo`: RTNETLINK answers: File exists"

   Run the following to delete the link `foo`:
   ```bash
   $ sudo ip link del foo
   ```
   Note that you can list all network devices by running the following:
   ```bash
   $ ip link
   ```
 - "Namespace already exists: /run/netns/foo"

   Run the following to unmount (if necessary) and then delete the namespace
   `foo`:
   ```
   $ sudo umount /run/netns/foo
   $ sudo rm /run/netns/foo
   ```

Rebooting the system will reset all of the issues mentioned above--except the
existence of the Open vSwitch bridge (i.e., the one requiring `ovs-vsctl`).
