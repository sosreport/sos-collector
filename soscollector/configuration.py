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

import re
import six
import socket


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

    def set_defaults(self):
        self['sos_mod'] = {}
        self['master'] = ''
        self['strip_sos_path'] = ''
        self['ssh_port'] = '22'
        self['ssh_user'] = 'root'
        self['sos_cmd'] = 'sosreport --batch '
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
        self['cluster_options'] = ''
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
                    re.compile(reg)
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

    def parse_cluster_options(self):
        opts = []
        if self['cluster_options']:
            for opt in self['cluster_options'].split(','):
                cluster = opt.split('.')[0]
                name = opt.split('.')[1].split('=')[0]
                try:
                    value = opt.split('=')[1]
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


class ClusterOption():
    '''Used to store/manipulate options for cluster profiles.'''

    def __init__(self, name, value, opt_type, cluster, description=None):
        self.name = name
        self.value = value
        self.opt_type = opt_type
        self.cluster = cluster
        self.description = description
