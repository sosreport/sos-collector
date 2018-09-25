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

import fnmatch
import inspect
import logging
import os
import random
import re
import string
import tarfile
import threading
import tempfile
import shutil
import subprocess
import sys

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from .sosnode import SosNode
from distutils.sysconfig import get_python_lib
from getpass import getpass
from six.moves import input
from textwrap import fill
from soscollector import __version__


class SosCollector():
    '''Main sos-collector class'''

    def __init__(self, config):
        os.umask(0077)
        self.config = config
        self.threads = []
        self.workers = []
        self.client_list = []
        self.node_list = []
        self.master = False
        self.retrieved = 0
        self.need_local_sudo = False
        if not self.config['list_options']:
            try:
                if not self.config['tmp_dir']:
                    self.create_tmp_dir()
                self._setup_logging()
                self.log_debug('Executing %s' % ' '.join(s for s in sys.argv))
                self._load_clusters()
                self._parse_options()
                self.prep()
            except KeyboardInterrupt:
                self._exit('Exiting on user cancel', 130)
        else:
            self._load_clusters()

    def _setup_logging(self):
        # behind the scenes logging
        self.logger = logging.getLogger('sos_collector')
        self.logger.setLevel(logging.DEBUG)
        self.logfile = tempfile.NamedTemporaryFile(
            mode="w+",
            dir=self.config['tmp_dir'])
        hndlr = logging.StreamHandler(self.logfile)
        hndlr.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s'))
        hndlr.setLevel(logging.DEBUG)
        self.logger.addHandler(hndlr)

        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(logging.Formatter('%(message)s'))

        # ui logging
        self.console = logging.getLogger('sos_collector_console')
        self.console.setLevel(logging.DEBUG)
        self.console_log_file = tempfile.NamedTemporaryFile(
            mode="w+",
            dir=self.config['tmp_dir'])
        chandler = logging.StreamHandler(self.console_log_file)
        cfmt = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        chandler.setFormatter(cfmt)
        self.console.addHandler(chandler)

        # also print to console
        ui = logging.StreamHandler()
        fmt = logging.Formatter('%(message)s')
        ui.setFormatter(fmt)
        if self.config['verbose']:
            ui.setLevel(logging.DEBUG)
        else:
            ui.setLevel(logging.INFO)
        self.console.addHandler(ui)

    def _exit(self, msg, error=1):
        '''Used to safely terminate if sos-collector encounters an error'''
        self.log_error(msg)
        try:
            self.close_all_connections()
        except Exception:
            pass
        sys.exit(error)

    def _parse_options(self):
        '''If there are cluster options set on the CLI, override the defaults
        '''
        if self.config['cluster_options']:
            for opt in self.config['cluster_options']:
                match = False
                for option in self.clusters[opt.cluster].options:
                    if opt.name == option.name:
                        match = True
                        # override the default from CLI
                        option.value = self._validate_option(option, opt)
                if not match:
                    self._exit('Unknown option provided: %s.%s' % (
                        opt.cluster, opt.name
                    ))

    def _validate_option(self, default, cli):
        '''Checks to make sure that the option given on the CLI is valid.
        Valid in this sense means that the type of value given matches what a
        cluster profile expects (str for str, bool for bool, etc).

        For bool options, this will also convert the string equivalent to an
        actual boolean value
        '''
        if not default.opt_type == bool:
            if not default.opt_type == cli.opt_type:
                msg = "Invalid option type for %s. Expected %s got %s"
                self._exit(msg % (cli.name, default.opt_type, cli.opt_type))
            return cli.value
        else:
            val = cli.value.lower()
            if val not in ['true', 'on', 'false', 'off']:
                msg = ("Invalid value for %s. Accepted values are: 'true', "
                       "'false', 'on', 'off'")
                self._exit(msg % cli.name)
            else:
                if val in ['true', 'on']:
                    return True
                else:
                    return False

    def log_info(self, msg):
        '''Log info messages to both console and log file'''
        self.logger.info(msg)
        self.console.info(msg)

    def log_error(self, msg):
        '''Log error messages to both console and log file'''
        self.logger.error(msg)
        self.console.error(msg)

    def log_debug(self, msg):
        '''Log debug message to both console and log file'''
        caller = inspect.stack()[1][3]
        msg = '[sos_collector:%s] %s' % (caller, msg)
        self.logger.debug(msg)
        if self.config['verbose']:
            self.console.debug(msg)

    def create_tmp_dir(self):
        '''Creates a temp directory to transfer sosreports to'''
        tmpdir = tempfile.mkdtemp(prefix='sos-collector-', dir='/var/tmp')
        self.config['tmp_dir'] = tmpdir
        self.config['tmp_dir_created'] = True

    def list_options(self):
        '''Display options for available clusters'''
        print('\nThe following cluster options are available:\n')
        print('{:15} {:15} {:<10} {:10} {:<}'.format(
            'Cluster',
            'Option Name',
            'Type',
            'Default',
            'Description'
        ))

        for cluster in self.clusters:
            for opt in self.clusters[cluster].options:
                optln = '{:15} {:15} {:<10} {:<10} {:<10}'.format(
                    opt.cluster,
                    opt.name,
                    opt.opt_type.__name__,
                    str(opt.value),
                    opt.description
                )
                print(optln)
        print('\nOptions take the form of cluster.name=value'
              '\nE.G. "ovirt.no-database=True" or "pacemaker.offline=False"')

    def delete_tmp_dir(self):
        '''Removes the temp directory and all collected sosreports'''
        shutil.rmtree(self.config['tmp_dir'])

    def _load_clusters(self):
        '''Load an instance of each cluster so that sos-collector can later
        determine what type of cluster is in use
        '''
        if 'soscollector' not in os.listdir(os.getcwd()):
            p = get_python_lib()
            path = p + '/soscollector/clusters/'
        else:
            path = 'soscollector/clusters'
        self.clusters = {}
        sys.path.insert(0, path)
        for f in sorted(os.listdir(path)):
            fname, ext = os.path.splitext(f)
            if ext == '.py' and fname not in ['__init__', 'cluster']:
                mods = inspect.getmembers(__import__(fname), inspect.isclass)
                for cluster in mods[1:]:
                    self.clusters[cluster[0]] = cluster[1](self.config)
        self.log_debug('Found cluster profiles: %s'
                       % list(self.clusters.keys()))
        sys.path.pop(0)

    def _get_archive_name(self):
        '''Generates a name for the tarball archive'''
        nstr = 'sos-collector'
        if self.config['label']:
            nstr += '-%s' % self.config['label']
        if self.config['case_id']:
            nstr += '-%s' % self.config['case_id']
        dt = datetime.strftime(datetime.now(), '%Y-%m-%d')

        try:
            string.lowercase = string.ascii_lowercase
        except NameError:
            pass

        rand = ''.join(random.choice(string.lowercase) for x in range(5))
        return '%s-%s-%s' % (nstr, dt, rand)

    def _get_archive_path(self):
        '''Returns the path, including filename, of the tarball we build
        that contains the collected sosreports
        '''
        self.arc_name = self._get_archive_name()
        compr = 'gz'
        return self.config['out_dir'] + self.arc_name + '.tar.' + compr

    def _fmt_msg(self, msg):
        width = 80
        _fmt = ''
        for line in msg.splitlines():
            _fmt = _fmt + fill(line, width, replace_whitespace=False) + '\n'
        return _fmt

    def prep(self):
        '''Based on configuration, performs setup for collection'''
        disclaimer = ("""\
This utility is used to collect sosreports from multiple \
nodes simultaneously. It uses the python-paramiko library \
to manage the SSH connections to remote systems. If this \
library is not acceptable for use in your environment, \
you should not use this utility.

An archive of sosreport tarballs collected from the nodes will be \
generated in %s and may be provided to an appropriate support representative.

The generated archive may contain data considered sensitive \
and its content should be reviewed by the originating \
organization before being passed to any third party.

No configuration changes will be made to the system running \
this utility or remote systems that it connects to.
""")
        self.console.info("\nsos-collector (version %s)\n" % __version__)
        intro_msg = self._fmt_msg(disclaimer % self.config['tmp_dir'])
        self.console.info(intro_msg)
        prompt = "\nPress ENTER to continue, or CTRL-C to quit\n"
        if not self.config['batch']:
            input(prompt)

        if not self.config['password']:
            self.log_debug('password not specified, assuming SSH keys')
            msg = ('sos-collector ASSUMES that SSH keys are installed on all '
                   'nodes unless the --password option is provided.\n')
            self.console.info(self._fmt_msg(msg))

        if self.config['password']:
            self.log_debug('password specified, not using SSH keys')
            msg = ('Provide the SSH password for user %s: '
                   % self.config['ssh_user'])
            self.config['password'] = getpass(prompt=msg)

        if self.config['need_sudo'] and not self.config['insecure_sudo']:
            if not self.config['password']:
                self.log_debug('non-root user specified, will request '
                               'sudo password')
                msg = ('A non-root user has been provided. Provide sudo '
                       'password for %s on remote nodes: '
                       % self.config['ssh_user'])
                self.config['sudo_pw'] = getpass(prompt=msg)
            else:
                if not self.config['insecure_sudo']:
                    self.config['sudo_pw'] = self.config['password']

        if self.config['become_root']:
            if not self.config['ssh_user'] == 'root':
                self.log_debug('non-root user asking to become root remotely')
                msg = ('User %s will attempt to become root. '
                       'Provide root password: ' % self.config['ssh_user'])
                self.config['root_password'] = getpass(prompt=msg)
                self.config['need_sudo'] = False
            else:
                self.log_info('Option to become root but ssh user is root.'
                              ' Ignoring request to change user on node')
                self.config['become_root'] = False

        if self.config['master']:
            self.connect_to_master()
            self.config['no_local'] = True
        else:
            self.master = SosNode('localhost', self.config)
        if self.config['cluster_type']:
            self.config['cluster'] = self.clusters[self.config['cluster_type']]
        else:
            self.determine_cluster()
        if self.config['cluster'] is None and not self.config['nodes']:
            msg = ('Cluster type could not be determined and no nodes provided'
                   '\nAborting...')
            self._exit(msg, 1)
        self.config['cluster'].setup()
        self.get_nodes()
        self.intro()
        self.configure_sos_cmd()

    def intro(self):
        '''Prints initial messages and collects user and case if not
        provided already.
        '''
        self.console.info('')

        if not self.node_list and not self.master.connected:
            self._exit('No nodes were detected, or nodes do not have sos '
                       'installed.\nAborting...')

        self.console.info('The following is a list of nodes to collect from:')
        if self.master.connected:
            self.console.info('\t%-*s' % (self.config['hostlen'],
                                          self.config['master']))

        for node in sorted(self.node_list):
            self.console.info("\t%-*s" % (self.config['hostlen'], node))

        self.console.info('')

        if not self.config['case_id'] and not self.config['batch']:
            msg = 'Please enter the case id you are collecting reports for: '
            self.config['case_id'] = input(msg)

    def configure_sos_cmd(self):
        '''Configures the sosreport command that is run on the nodes'''
        if self.config['sos_opt_line']:
            self.config['sos_cmd'] += self.config['sos_opt_line']
            self.log_debug("User specified manual sosreport command line. "
                           "sos command set to %s" % self.config['sos_cmd'])
            return True
        if self.config['case_id']:
            self.config['sos_cmd'] += ' --case-id=%s' % self.config['case_id']
        if self.config['alloptions']:
            self.config['sos_cmd'] += ' --alloptions'
        if self.config['verify']:
            self.config['sos_cmd'] += ' --verify'
        if self.config['log_size']:
            self.config['sos_cmd'] += (' --log-size=%s'
                                       % self.config['log_size'])
        if self.config['sysroot']:
            self.config['sos_cmd'] += ' -s %s' % self.config['sysroot']
        if self.config['chroot']:
            self.config['sos_cmd'] += ' -c %s' % self.config['chroot']
        if self.config['compression']:
            self.config['sos_cmd'] += ' -z %s' % self.config['compression']
        if self.config['cluster_type']:
            self.config['cluster'].modify_sos_cmd()
        self.log_debug('Initial sos cmd set to %s' % self.config['sos_cmd'])

    def connect_to_master(self):
        '''If run with --master, we will run cluster checks again that
        instead of the localhost.
        '''
        try:
            self.master = SosNode(self.config['master'], self.config)
        except Exception as e:
            self.log_debug('Failed to connect to master: %s' % e)
            self._exit('Could not connect to master node.\nAborting...', 1)

    def determine_cluster(self):
        '''This sets the cluster type and loads that cluster's cluster.

        If no cluster type is matched and no list of nodes is provided by
        the user, then we abort.

        If a list of nodes is given, this is not run, however the cluster
        can still be run if the user sets a --cluster-type manually
        '''

        for clus in self.clusters:
            self.clusters[clus].master = self.master
            if self.clusters[clus].check_enabled():
                self.config['cluster'] = self.clusters[clus]
                name = str(self.clusters[clus].__class__.__name__).lower()
                self.config['cluster_type'] = name
                self.log_info(
                    'Cluster type set to %s' % self.config['cluster_type'])
                break

    def get_nodes_from_cluster(self):
        '''Collects the list of nodes from the determined cluster cluster'''
        nodes = self.config['cluster']._get_nodes()
        self.log_debug('Node list: %s' % nodes)
        return nodes

    def reduce_node_list(self):
        '''Reduce duplicate entries of the localhost and/or master node
        if applicable'''
        if (self.config['hostname'] in self.node_list and
                self.config['no_local']):
            self.node_list.remove(self.config['hostname'])
        for i in self.config['ip_addrs']:
            if i in self.node_list:
                self.node_list.remove(i)
        # remove the master node from the list, since we already have
        # an open session to it.
        if self.config['master']:
            for n in self.node_list:
                if n == self.master.hostname or n == self.config['master']:
                    self.node_list.remove(n)
        self.node_list = list(set(n for n in self.node_list if n))
        self.log_debug('Node list reduced to %s' % self.node_list)

    def compare_node_to_regex(self, node):
        '''Compares a discovered node name to a provided list of nodes from
        the user. If there is not a match, the node is removed from the list'''
        for regex in self.config['nodes']:
            try:
                if re.match(regex, node):
                    return True
            except re.error as err:
                msg = 'Error comparing %s to provided node regex %s: %s'
                self.log_debug(msg % (node, regex, err))
        return False

    def get_nodes(self):
        ''' Sets the list of nodes to collect sosreports from '''
        if not self.config['master'] and not self.config['cluster']:
            msg = ('Could not determine a cluster type and no list of '
                   'nodes or master node was provided.\nAborting...'
                   )
            self._exit(msg)

        try:
            nodes = self.get_nodes_from_cluster()
            if self.config['nodes']:
                for node in nodes:
                    if self.compare_node_to_regex(node):
                        self.node_list.append(node)
            else:
                self.node_list = nodes
        except Exception as e:
            self.log_debug("Error parsing node list: %s" % e)
            self.log_debug('Setting node list to --nodes option')
            self.node_list = self.config['nodes']
            for node in self.node_list:
                if any(i in node for i in ('*', '\\', '?', '(', ')', '/')):
                    self.node_list.remove(node)

        # force add any non-regex node strings from nodes option
        if self.config['nodes']:
            for node in self.config['nodes']:
                if any(i in node for i in ('*', '\\', '?', '(', ')', '/')):
                    continue
                if node not in self.node_list:
                    self.log_debug("Force adding %s to node list" % node)
                    self.node_list.append(node)

        if not self.config['master']:
            host = self.config['hostname'].split('.')[0]
            # trust the local hostname before the node report from cluster
            for node in self.node_list:
                if host == node.split('.')[0]:
                    self.node_list.remove(node)
            self.node_list.append(self.config['hostname'])
        self.reduce_node_list()
        try:
            self.config['hostlen'] = len(max(self.node_list, key=len))
        except (TypeError, ValueError):
            self.config['hostlen'] = len(self.config['master'])

    def can_run_local_sos(self):
        '''Check if sosreport can be run as the current user, or if we need
        to invoke sudo'''
        if os.geteuid() != 0:
            self.log_debug('Not running as root. Need sudo for local sos')
            self.need_local_sudo = True
            msg = ('\nLocal sosreport requires root. Provide sudo password'
                   'or press ENTER to skip: ')
            self.local_sudopw = getpass(prompt=msg)
            self.console.info('\n')
            if not self.local_sudopw:
                self.logger.info('Will not collect local sos, no password')
                return False
        self.log_debug('Able to collect local sos')
        return True

    def _connect_to_node(self, node):
        '''Try to connect to the node, and if we can add to the client list to
        run sosreport on
        '''
        try:
            client = SosNode(node, self.config)
            if client.connected:
                self.client_list.append(client)
            else:
                client.close_ssh_session()
        except Exception:
            pass

    def collect(self):
        ''' For each node, start a collection thread and then tar all
        collected sosreports '''
        if self.master.connected:
            self.client_list.append(self.master)
        self.console.info("\nConnecting to nodes...")
        filters = [self.master.address, self.master.hostname]
        nodes = [n for n in self.node_list if n not in filters]

        try:
            pool = ThreadPoolExecutor(self.config['threads'])
            pool.map(self._connect_to_node, nodes, chunksize=1)
            pool.shutdown(wait=True)

            self.report_num = len(self.client_list)

            self.console.info("\nBeginning collection of sosreports from %s "
                              "nodes, collecting a maximum of %s "
                              "concurrently\n"
                              % (len(self.client_list), self.config['threads'])
                              )

            pool = ThreadPoolExecutor(self.config['threads'])
            pool.map(self._collect, self.client_list, chunksize=1)
            pool.shutdown(wait=True)
        except KeyboardInterrupt:
            self.log_error('Exiting on user cancel\n')
            os._exit(130)

        if hasattr(self.config['cluster'], 'run_extra_cmd'):
            self.console.info('Collecting additional data from master node...')
            f = self.config['cluster'].run_extra_cmd()
            if f:
                self.master.collect_extra_cmd(f)
        msg = '\nSuccessfully captured %s of %s sosreports'
        self.log_info(msg % (self.retrieved, self.report_num))
        if self.retrieved > 0:
            self.create_cluster_archive()
        else:
            msg = 'No sosreports were collected, nothing to archive...'
            self._exit(msg, 1)
        self.close_all_connections()

    def _collect(self, client):
        '''Runs sosreport on each node'''
        if not client.local:
            client.sosreport()
        else:
            if not self.config['no_local']:
                client.sosreport()
        if client.retrieved:
            self.retrieved += 1

    def close_all_connections(self):
        '''Close all ssh sessions for nodes'''
        for client in self.client_list:
            self.log_debug('Closing SSH connection to %s' % client.address)
            client.close_ssh_session()

    def create_cluster_archive(self):
        '''Calls for creation of tar archive then cleans up the temporary
        files created by sos-collector'''
        self.log_info('Creating archive of sosreports...')
        self.create_sos_archive()
        if self.archive:
            self.logger.info('Archive created as %s' % self.archive)
            self.cleanup()
            self.console.info('\nThe following archive has been created. '
                              'Please provide it to your support team.')
            self.console.info('    %s' % self.archive)

    def create_sos_archive(self):
        '''Creates a tar archive containing all collected sosreports'''
        try:
            self.archive = self._get_archive_path()
            with tarfile.open(self.archive, "w:gz") as tar:
                for fname in os.listdir(self.config['tmp_dir']):
                    arcname = fname
                    if fname == self.logfile.name.split('/')[-1]:
                        arcname = 'sos-collector.log'
                    if fname == self.console_log_file.name.split('/')[-1]:
                        arcname = 'ui.log'
                    tar.add(os.path.join(self.config['tmp_dir'], fname),
                            arcname=self.arc_name + '/' + arcname)
                tar.close()
        except Exception as e:
            msg = 'Could not create archive: %s' % e
            self._exit(msg, 2)

    def cleanup(self):
        ''' Removes the tmp dir and all sosarchives therein.

            If tmp dir was supplied by user, only the sos archives within
            that dir are removed.
        '''
        if self.config['tmp_dir_created']:
            self.delete_tmp_dir()
        else:
            for f in os.listdir(self.config['tmp_dir']):
                if re.search('*sosreport-*tar*', f):
                    os.remove(os.path.join(self.config['tmp_dir'], f))
