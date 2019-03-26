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


class SosHost():
    '''Base class for defining host types - usually defined by distribution

    This should be subclassed for any distro/release that sos-collector can be
    expected to run on. At minimum it needs to define a package manager and a
    way to identify the node as a particular distribution - usually through
    inspection of /etc/os-release or related file.

    The check_enabled() method should handle looking for the necessary string
    inside the release_file, or any other way to uniquely identify the host
    installation.

    The release_file should be set to an identifying file like /etc/os-release
    that can be inspected.

    '''
    distribution = ''
    release_file = '/etc/os-release'
    package_manager = {
        'name': '',
        'query': ''
    }
    release = ''
    containerized = False
    container_runtime = None
    container_image = None
    sos_path_strip = None
    sos_pkg_name = None  # package name in deb/rpm/etc
    sos_bin_path = None  # path to sosreport binary
    sos_container_name = 'sos-collector-tmp'

    def __init__(self, address):
        self.address = address

    def _check_enabled(self, rel_string):
        self.release = rel_string.strip()
        return self.check_enabled(rel_string)

    def check_enabled(self, rel_string):
        '''Should handle identifying the given host as being of the defined
        distribution.

        MUST return either True or False.
        '''
        return False

    def report_facts(self):
        '''Assemble relevant information and return as a dict'''
        facts = {
            'distribution': self.distribution,
            'release': self.release,
            'containerized': self.containerized,
            'container_runtime': self.container_runtime,
            'sos_prefix': self.set_sos_prefix() % {
                'image': self.container_image},
            'cleanup_command': self.set_cleanup_cmd()
        }
        return facts

    def pkg_query(self, pkg):
        '''Returns the command string to query a given package.

        Note that this DOES NOT run the query itself. That is left to the
        SosNode instance that maintains the SSH connection.
        '''
        return self.package_manager['query'] + ' %s' % pkg

    def set_sos_prefix(self):
        '''If sosreport commands need to always be prefixed with something,
        for example running in a specific container image, then it should be
        defined here.

        If no prefix should be set, return an empty string instead of None.
        '''
        return ''

    def set_cleanup_cmd(self):
        '''If a host requires additional cleanup, the command should be set and
        returned here
        '''
        return ''

    def create_sos_container(self):
        '''Returns the command that will create the container that will be
        used for running commands inside a container on hosts that require it.

        This will use the container runtime defined for the host type to
        launch a container. From there, we use the defined runtime to exec into
        the container's namespace.
        '''
        return ''

    def restart_sos_container(self):
        '''Restarts the container created for sos-collector if it has stopped.

        This is called immediately after create_sos_container() as the command
        to create the container will exit and the container will stop. For
        current container runtimes, subsequently starting the container will
        default to opening a bash shell in the container to keep it running,
        thus allowing us to exec into it again.
        '''
        return "%s start %s" % (self.container_runtime,
                                self.sos_container_name)

    def format_container_command(self, cmd):
        '''Returns the command that allows us to exec into the created
        container for sos-collector.
        '''
        if self.container_runtime:
            return '%s exec %s %s' % (self.container_runtime,
                                      self.sos_container_name,
                                      cmd)
        else:
            return cmd
