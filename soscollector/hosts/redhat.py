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

from soscollector.hosts import SosHost


class RedHatHost(SosHost):
    '''Base class for defining Red Hat family systems'''

    distribution = 'Red Hat'
    release_file = '/etc/redhat-release'
    releases = ['fedora', 'red hat', 'centos']
    package_manager = {
        'name': 'rpm',
        'query': 'rpm -q'
    }
    sos_pkg_name = 'sos'
    sos_bin_path = '/usr/sbin/sosreport'

    def check_enabled(self, rel_string):
        for release in self.releases:
            if release in rel_string.lower() and 'CoreOS' not in rel_string:
                return True
        return False


class RedHatAtomicHost(RedHatHost):

    containerized = True
    container_runtime = 'docker'
    container_image = 'registry.access.redhat.com/rhel7/support-tools'
    sos_path_strip = '/host'

    def check_enabled(self, rel_string):
        return 'Atomic Host' in rel_string

    def create_sos_container(self):
        _cmd = ("{runtime} run -di --name {name} --privileged --ipc=host"
                " --net=host --pid=host -e HOST=/host -e NAME={name} -e "
                "IMAGE={image} -v /run:/run -v /var/log:/var/log -v "
                "/etc/machine-id:/etc/machine-id -v "
                "/etc/localtime:/etc/localtime -v /:/host {image}")
        return _cmd.format(
                    runtime=self.container_runtime,
                    name=self.sos_container_name,
                    image=self.container_image
                )

    def set_cleanup_cmd(self):
        return 'docker rm --force sos-collector-tmp'


class RedHatCoreOSHost(RedHatHost):

    containerized = True
    container_runtime = 'podman'
    container_image = 'registry.redhat.io/rhel8/support-tools'
    sos_path_strip = '/host'

    def check_enabled(self, rel_string):
        return 'CoreOS' in rel_string

    def create_sos_container(self):
        _cmd = ("{runtime} run -di --name {name} --privileged --ipc=host"
                " --net=host --pid=host -e HOST=/host -e NAME={name} -e "
                "IMAGE={image} -v /run:/run -v /var/log:/var/log -v "
                "/etc/machine-id:/etc/machine-id -v "
                "/etc/localtime:/etc/localtime -v /:/host {image}")
        return _cmd.format(
                    runtime=self.container_runtime,
                    name=self.sos_container_name,
                    image=self.container_image
                )

    def set_cleanup_cmd(self):
        return 'podman rm --force %s' % self.sos_container_name
