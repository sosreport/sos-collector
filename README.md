# sos-collector
Collect sosreports from multiple (cluster) nodes simultaneously

# Description
sos-collector is a utility designed to collect sosreports from multiple nodes simultaneously and package them in a single archive. It is ideally suited for clustered environments, but can also be used for manually-defined sets of standalone nodes.

# Usage
sos-collector leverages paramiko to open SSH sessions to the target nodes from the local system it is run on. 

By default, sos-collector *assumes* that SSH keys have been installed on any nodes it tries to connect to. This can be changed by using the `--password` option which will prompt the user to enter
an SSH password. This password is assumed to be the same for all nodes. If you have a different root password for each node, you should deploy SSH keys and use the default behavoir.

**IMPORTANT**: sos-collector itself does not need root privileges, however it does need root privileges on the target nodes in order to run sosreport. By default, SSH session will be opened as root. This can be changed via the `--ssh-user` option. If used, sos-collector will prompt for a `sudo` password.

If sos-collector is being run on a node that is part of the cluster being investigated, it can be run as simply as:

`$ sos-collector`

If it is being run on a workstation, then it can still be used provided that SSH keys for that workstation are installed on the target nodes. To do this, specify a "master" node in the cluster:

`$ sos-collector --master=master.example.com`

In this example, `master.example.com` will need to be able to enumerate all other nodes in the cluster. SSH sessions will be opened from the local workstation, NOT from the master node.

# Cluster types/support
sos-collector will attempt to identify the type of cluster environment it is being run against through the use of cluster profiles. These are effectively plugins and live under `soscollector/clusters`.

The most basic type of check is a package check, e.g. if it is a kubernetes cluster then sos-collector would at minimum look for the presence of the kubernetes package.

You can also manually force a specific type of cluster using `--cluster-type`, E.G.

`$ sos-collector --master=master.example.com --cluster-type=kubernetes`

# Node enumeration

The profile for each cluster contains the logic to enumerate and report the nodes in the cluster to sos-collector. However, a user may also specify a list of nodes alongside a given `--master` or `--cluster-type`. In the event that neither is provided, the first node in the list given to sos-collector is considered to be the master node. For example:

`$ sos-collector --nodes=node1.example.com,node2.example.com`



# Installation

You can run sos-collector from the git checkout, E.G.

`$ ./sos-collector`

Currently `sos-collector` is available for Fedora 27 and later and can be installed from the repos:

`# dnf install sos-collector`
