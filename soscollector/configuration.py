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

import inspect
import os
import pipes
import re
import six
import socket
import sys


class Configuration(dict):
    """ Dict subclass that is used to handle configuration information
    needed by both SosCollector and the SosNode classes """

    def __init__(self, args=None):
        self.args = args
        self.set_defaults()
        self.parse_config()
        self.parse_options()
        self.check_user_privs()
        self.parse_node_strings()
        self['host_types'] = self._load_supported_hosts()
        self['cluster_types'] = self._load_clusters()

    def set_defaults(self):
        self['sos_mod'] = {}
        self['master'] = ''
        self['strip_sos_path'] = ''
        self['ssh_port'] = 22
        self['ssh_user'] = 'root'
        self['ssh_key'] = None
        self['sos_cmd'] = 'sosreport --batch'
        self['no_local'] = False
        self['tmp_dir'] = None
        self['out_dir'] = '/var/tmp/'
        self['nodes'] = None
        self['debug'] = False
        self['tmp_dir_created'] = False
        self['cluster_type'] = None
        self['cluster'] = None
        self['password'] = False
        self['label'] = None
        self['case_id'] = None
        self['timeout'] = 300
        self['all_logs'] = False
        self['alloptions'] = False
        self['no_pkg_check'] = False
        self['hostname'] = socket.gethostname()
        ips = [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)]
        self['ip_addrs'] = list(set(ips))
        self['cluster_options'] = []
        self['image'] = None
        self['skip_plugins'] = []
        self['enable_plugins'] = []
        self['plugin_options'] = []
        self['only_plugins'] = []
        self['list_options'] = False
        self['hostlen'] = len(self['master']) or len(self['hostname'])
        self['need_sudo'] = False
        self['sudo_pw'] = ''
        self['become_root'] = False
        self['root_password'] = ''
        self['threads'] = 4
        self['compression'] = ''
        self['verify'] = False
        self['chroot'] = ''
        self['sysroot'] = ''
        self['sos_opt_line'] = ''
        self['batch'] = False
        self['verbose'] = False
        self['preset'] = ''
        self['insecure_sudo'] = False
        self['log_size'] = 0
        self['host_types'] = []

    def parse_node_strings(self):
        '''
        Parses the given --nodes option(s) to properly format the regex
        list that we use. We cannot blindly split on ',' chars since it is a
        valid regex character, so we need to scan along the given strings and
        check at each comma if we should use the preceeding string by itself
        or not, based on if there is a valid regex at that index.
        '''
        if not self['nodes']:
            return
        nodes = []
        if not isinstance(self['nodes'], list):
            self['nodes'] = [self['nodes']]
        for node in self['nodes']:
            idxs = [i for i, m in enumerate(node) if m == ',']
            idxs.append(len(node))
            start = 0
            pos = 0
            for idx in idxs:
                try:
                    pos = idx
                    reg = node[start:idx]
                    re.compile(re.escape(reg))
                    # make sure we aren't splitting a regex value
                    if '[' in reg and ']' not in reg:
                        continue
                    nodes.append(reg.lstrip(','))
                    start = idx
                except re.error:
                    continue
            if pos != len(node):
                nodes.append(node[pos+1:])
        self['nodes'] = nodes

    def parse_config(self):
        for k in self.args:
            if self.args[k]:
                self[k] = self.args[k]
        if self['sos_opt_line']:
            self['sos_opt_line'] = pipes.quote(self['sos_opt_line'])

    def parse_cluster_options(self):
        opts = []
        if not isinstance(self['cluster_options'], list):
            self['cluster_options'] = [self['cluster_options']]
        if self['cluster_options']:
            for option in self['cluster_options']:
                cluster = option.split('.')[0]
                name = option.split('.')[1].split('=')[0]
                try:
                    # there are no instances currently where any cluster option
                    # should contain a legitimate space.
                    value = option.split('=')[1].split()[0]
                except IndexError:
                    # conversion to boolean is handled during validation
                    value = 'True'

                opts.append(
                    ClusterOption(name, value, value.__class__, cluster)
                )
        self['cluster_options'] = opts

    def parse_options(self):
        self.parse_cluster_options()
        for opt in ['skip_plugins', 'enable_plugins', 'plugin_options',
                    'only_plugins']:
            if self[opt]:
                opts = []
                if isinstance(self[opt], six.string_types):
                    self[opt] = [self[opt]]
                for option in self[opt]:
                    opts += option.split(',')
                self[opt] = opts

    def check_user_privs(self):
        if not self['ssh_user'] == 'root':
            self['need_sudo'] = True

    def _import_modules(self, modname):
        '''Import and return all found classes in a module'''
        mod_short_name = modname.split('.')[2]
        module = __import__(modname, globals(), locals(), [mod_short_name])
        modules = inspect.getmembers(module, inspect.isclass)
        for mod in modules:
            if mod[0] in ('SosHost', 'Cluster'):
                modules.remove(mod)
        return modules

    def _find_modules_in_path(self, path, modulename):
        '''Given a path and a module name, find everything that can be imported
        and then import it

            path - the filesystem path of the package
            modulename - the name of the module in the package

        E.G. a path of 'clusters', and a modulename of 'ovirt' equates to
        importing soscollector.clusters.ovirt
        '''
        modules = []
        if os.path.exists(path):
            for pyfile in sorted(os.listdir(path)):
                if not pyfile.endswith('.py'):
                    continue
                if '__' in pyfile:
                    continue
                fname, ext = os.path.splitext(pyfile)
                modname = 'soscollector.%s.%s' % (modulename, fname)
                modules.extend(self._import_modules(modname))
        return modules

    def _load_modules(self, package, submod):
        '''Helper to import cluster and host types'''
        modules = []
        for path in package.__path__:
            if os.path.isdir(path):
                modules.extend(self._find_modules_in_path(path, submod))
        return modules

    def _load_clusters(self):
        '''Load an instance of each cluster so that sos-collector can later
        determine what type of cluster is in use
        '''
        import soscollector.clusters
        package = soscollector.clusters
        supported_clusters = {}
        clusters = self._load_modules(package, 'clusters')
        for cluster in clusters:
            supported_clusters[cluster[0]] = cluster[1](self)
        return supported_clusters

    def _load_supported_hosts(self):
        '''Load all the supported/defined host types for sos-collector.
        These will then be used to match against each node we run on
        '''
        import soscollector.hosts
        package = soscollector.hosts
        supported_hosts = {}
        hosts = self._load_modules(package, 'hosts')
        for host in hosts:
            supported_hosts[host[0]] = host[1]
        return supported_hosts


class ClusterOption():
    '''Used to store/manipulate options for cluster profiles.'''

    def __init__(self, name, value, opt_type, cluster, description=None):
        self.name = name
        self.value = value
        self.opt_type = opt_type
        self.cluster = cluster
        self.description = description
