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

    packages = ('kubernetes-master',)
    sos_plugins = ['kubernetes']
    sos_plugin_options = {'kubernetes.all': 'on'}

    cmd = 'kubectl'

    option_list = [
        ('label', '', 'Filter node list to those with matching label'),
        ('role', '', 'Filter node list to those with matching role')
    ]

    def get_nodes(self):
        self.cmd += ' get nodes'
        if self.get_option('label'):
            self.cmd += ' -l %s ' % self.get_option('label')
        res = self.exec_master_cmd(self.cmd)
        if res['status'] == 0:
            nodes = []
            roles = [x for x in self.get_option('role').split(',') if x]
            for nodeln in res['stdout'].splitlines()[1:]:
                node = nodeln.split()
                if not roles:
                    nodes.append(node[0])
                else:
                    if node[2] in roles:
                        nodes.append(node[0])
            return nodes
        else:
            raise Exception('Node enumeration did not return usable output')


class openshift(kubernetes):

    packages = ('atomic-openshift',)
    sos_preset = 'ocp'
    cmd = 'oc'
