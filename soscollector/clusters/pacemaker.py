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


class pacemaker(Cluster):

    sos_plugins = ['pacemaker']
    packages = ('pacemaker',)
    option_list = [
        ('online', True, 'Collect nodes listed as online'),
        ('offline', True, 'Collect nodes listed as offline')
    ]

    def get_nodes(self):
        self.res = self.exec_master_cmd('pcs status')
        if self.res['status'] != 0:
            self.log_error('Cluster status could not be determined. Is the '
                           'cluster running on this node?')
            return []
        if 'node names do not match' in self.res['stdout']:
            self.log_warn('Warning: node name mismatch reported. Attempts to '
                          'connect to some nodes may fail.\n')
        return self.parse_pcs_output()

    def parse_pcs_output(self):
        nodes = []
        if self.get_option('online'):
            nodes += self.get_online_nodes()
        if self.get_option('offline'):
            nodes += self.get_offline_nodes()
        return nodes

    def get_online_nodes(self):
        for line in self.res['stdout'].splitlines():
            if line.startswith('Online:'):
                nodes = line.split('[')[1].split(']')[0]
                return [n for n in nodes.split(' ') if n]

    def get_offline_nodes(self):
        offline = []
        for line in self.res['stdout'].splitlines():
            if line.startswith('Node') and line.endswith('(offline)'):
                offline.append(line.split()[1].replace(':', ''))
            if line.startswith('OFFLINE:'):
                nodes = line.split('[')[1].split(']')[0]
                offline.extend([n for n in nodes.split(' ') if n])
        return offline
