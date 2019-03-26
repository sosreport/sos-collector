# Copyright Red Hat 2019, Jake Hunsaker <jhunsake@redhat.com>
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


class jbon(Cluster):
    '''Just a Bunch of Nodes

    Used when --cluster-type=none (or jbon), to avoid cluster checks, and just
    use the provided --nodes list
    '''

    packages = None

    def get_nodes(self):
        return []

    def checK_enabled(self):
        # This should never be called, but as insurance explicitly never
        # allow this to be enabled via the determine_cluster() path
        return False
