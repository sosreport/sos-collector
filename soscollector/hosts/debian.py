# Copyright Canonical 2018, Bryan Quigley <bryan.quigley@canonical.com>
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

from soscollector.hosts import SosHost


class DebianHost(SosHost):
    '''Base class for defining Debian based systems'''

    distribution = 'Debian'
    releases = ['ubuntu', 'debian']
    package_manager = {
        'name': 'dpkg',
        'query': "dpkg-query -W -f='${Package}-${Version}\\\n' "
    }
    sos_pkg_name = 'sosreport'
    sos_bin_path = '/usr/bin/sosreport'

    def check_enabled(self, rel_string):
        for release in self.releases:
            if release in rel_string:
                return True
        return False
# vim:ts=4 et sw=4
