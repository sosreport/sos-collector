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

import logging
import subprocess

from soscollector.configuration import ClusterOption


class Cluster():

    option_list = []
    packages = ('',)
    sos_options = {}

    def __init__(self, config):
        self.master = None
        self.config = config
        self.cluster_type = self.__class__.__name__
        self.node_list = None
        sos_plugins = []
        self.logger = logging.getLogger('sos_collector')
        self.console = logging.getLogger('sos_collector_console')
        self.options = []
        self._get_options()

    def _get_options(self):
        '''Loads the options defined by a cluster and sets the default value'''
        for opt in self.option_list:
            option = ClusterOption(name=opt[0], opt_type=opt[0].__class__,
                                   value=opt[1], cluster=self.cluster_type,
                                   description=opt[2])
            self.options.append(option)

    def _fmt_msg(self, msg):
        return '[ %s ] %s' % (self.cluster_type, msg)

    def log_info(self, msg):
        '''Used to print info messages'''
        self.logger.info(self._fmt_msg(msg))
        self.console.info(msg)

    def log_error(self, msg):
        '''Used to print error messages'''
        self.logger.error(self._fmt_msg(msg))
        self.console.error(msg)

    def get_option(self, option):
        '''This is used to by clusters to check if a cluster option was
        supplied to sos-collector.
        '''
        for opt in self.options:
            if opt.name == option:
                return opt.value
        return False

    def is_installed(self, pkg):
        cmd = self.master.host_facts['package_manager']['query'] + pkg
        res = self.exec_master_cmd(cmd)
        if res['status'] == 0:
            return True
        return False

    def exec_master_cmd(self, cmd):
        '''Used to retrieve output from a (master) node in a cluster'''
        if self.config['need_sudo']:
            cmd = "sudo -S %s" % cmd
        if self.config['become_root']:
            cmd = "su -c '%s'" % cmd
        self.logger.debug('Running %s on %s' % (cmd, self.master.address))
        res = self.master.run_command(cmd, get_pty=True)
        if res['stdout']:
            if 'password' in res['stdout'][0].lower():
                res['stdout'].pop(0)
        return res

    def setup(self):
        '''This MAY be used by a cluster to do prep work in case there are
        extra commands to be run even if a node lsit is given by the user, and
        thus get_nodes() would not be called
        '''
        pass

    def get_sos_prefix(self, facts):
        '''This wraps set_sos_prefix used by clusters.
        It is called by sosnode.finalize_sos_cmd() for each node
        '''
        try:
            return self.set_sos_prefix(facts)
        except:
            return ''

    def set_sos_prefix(self, facts):
        '''This may be overridden by clusters when needed.

        In a cluster this should return a string that is placed immediately
        before the 'sosreport' command, but will be after sudo if needed.

        If a cluster overrides this, it will need to be known if the the
        cluster needs to be sensitive to cluster nodes being Atomic Hosts.
        '''
        if facts['atomic']:
            cmd = 'atomic run --name=sos-collector-tmp '
            img = self.config['image']
            return cmd + img

    def get_sos_path_strip(self, facts):
        '''This calls set_sos_path_strip that is used by clusters to determine
        if we need to remove a particular string from a returned sos path for
        any reason
        '''
        try:
            return self.set_sos_path_strip(facts)
        except:
            return ''

    def set_sos_path_strip(self, facts):
        '''This may be overriden by a cluster and used to set
        a string to be stripped from the return sos path if needed.

        For example, on Atomic Host, the sosreport gets written under
        /host/var/tmp in the container, but is available to scp under the
        standard /var/tmp after the container exits.

        If a cluster overrides this, it will need to be known if it needs to be
        sensitive to cluster nodes being Atomic Hosts.
        '''
        if facts['atomic']:
            return '/host'

    def get_cleanup_cmd(self, facts):
        '''This calls set_cleanup_cmd that is used by clusers to determine if
        sos-collector needs to do additional cleanup on a node
        '''
        try:
            return self.set_cleanup_cmd(facts)
        except:
            return False

    def set_cleanup_cmd(self, facts):
        '''This should be overridden by a cluster and used to set an additional
        command to run during cleanup.

        The cluster should return a string containing the full cleanup
        command to run

        If a cluster overrides this, it will need to be known if the the
        cluster needs to be sensitive to cluster nodes being Atomic Hosts.
        '''
        if facts['atomic']:
            return 'docker rm sos-collector-tmp'

    def check_enabled(self):
        '''This may be overridden by clusters

        This is called by sos-collector on each cluster type that exists, and
        is meant to return True when the cluster type matches a criteria
        that indicates that is the cluster type is in use.

        Only the first cluster type to determine a match is run
        '''
        for pkg in self.packages:
            if self.is_installed(pkg):
                return True
        return False

    def get_nodes(self):
        '''This MUST be overridden by a cluster.
        A cluster should use this method to return a list or string that
        contains all the nodes that a report should be collected from
        '''
        pass

    def _get_nodes(self):
        try:
            return self.format_node_list()
        except Exception as e:
            self.logger.error('Failed to get node list: %s' % e)
            raise

    def modify_sos_cmd(self):
        '''This is used to modify the sosreport command run on the nodes.
        By default, sosreport is run without any options, using this will
        allow the profile to specify what plugins to run or not and what
        options to use.

        This will NOT override user supplied options.
        '''

        if self.sos_plugins:
            for plug in self.sos_plugins:
                if plug not in self.config['sos_cmd']:
                    self.config['enable_plugins'].append(plug)
        if self.sos_options:
            for opt in self.sos_options:
                if opt not in self.config['sos_cmd']:
                    option = '%s=%s' % (opt, self.sos_options[opt])
                    self.config['plugin_option'].append(option)

    def format_node_list(self):
        '''Format the returned list of nodes from a cluster into a known
        format. This being a list that contains no duplicates
        '''

        try:
            nodes = self.get_nodes()
        except Exception as e:
            self.log_error('\n%s failed to enumerate nodes: %s'
                           % (self.cluster_type, e))
            raise
        if isinstance(nodes, list):
            node_list = [n.strip() for n in nodes if n]
            node_list = list(set(nodes))
        if isinstance(nodes, str):
            node_list = [n.split(',').strip() for n in nodes]
            node_list = list(set(nodes))
        return node_list
