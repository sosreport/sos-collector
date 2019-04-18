# Copyright Red Hat 2018, Jake Hunsaker <jhunsake@redhat.com>
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

from pipes import quote
from soscollector.clusters import Cluster


class satellite(Cluster):
    """Red Hat Satellite 6"""

    cluster_name = 'Red Hat Satellite 6'
    packages = ('satellite', 'satellite-installer')

    def _psql_cmd(self, query):
        _cmd = "su postgres -c %s"
        _dbcmd = "psql foreman -c %s"
        return _cmd % quote(_dbcmd % quote(query))

    def get_nodes(self):
        cmd = self._psql_cmd('select name from smart_proxies')
        res = self.exec_master_cmd(cmd, need_root=True)
        if res['status'] == 0:
            idx = 2
            if 'could not change' in res['stdout']:
                idx = 3
            nodes = [n.strip() for n in res['stdout'].splitlines()[idx:-1]]
            return nodes

    def set_node_label(self, node):
        if node.address == self.master.address:
            return 'satellite'
        return 'capsule'
