# Copyright Red Hat 2017, Jake Hunsaker <jhunsake@redhat.com>
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from soscollector.clusters import Cluster


class kubernetes(Cluster):

    sos_plugins = ['kubernetes']
    sos_options = {'kubernetes.all': 'on'}

    option_list = [
        ('label', '', 'Restrict nodes to those with matching label')
    ]

    def check_enabled(self):
        if self.is_installed('atomic-openshift-master'):
            self.cluster_type = 'openshift'
            self.cmd = 'oc'
            return True
        elif self.is_installed('kubernetes-master'):
            self.cmd = 'kubectl'
            return True
        else:
            return False

    def get_nodes(self):
        self.cmd += ' get nodes'
        if self.get_option('label'):
            self.cmd += ' -l %s ' % self.get_option('label')
        res = self.exec_master_cmd(self.cmd)
        if res['status'] == 0:
            nodes = [node.split()[0] for node in res['stdout'].splitlines()]
            nodes.remove("NAME")
            return nodes
        else:
            raise Exception('Node enumeration did not return usable output')
