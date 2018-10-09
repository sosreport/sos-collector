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
import paramiko
import re
import shutil
import socket
import subprocess
import six
import time

from distutils.version import LooseVersion
from subprocess import Popen, PIPE


class SosNode():

    def __init__(self, address, config, force=False, load_facts=True):
        self.address = address.strip()
        self.local = False
        self.hostname = None
        self.config = config
        self.sos_path = None
        self.retrieved = False
        self.hash_retrieved = False
        self.sos_info = {
            'version': None,
            'enabled': [],
            'disabled': [],
            'options': [],
            'presets': []
        }
        filt = ['localhost', '127.0.0.1', self.config['hostname']]
        self.logger = logging.getLogger('sos_collector')
        self.console = logging.getLogger('sos_collector_console')
        if self.address not in filt or force:
            self.connected = self.open_ssh_session()
            self.sftp = self.client.open_sftp()
        else:
            self.connected = True
            self.local = True
        if self.connected and load_facts:
            self.host = self.determine_host()
            self._set_sos_prefix(self.host.set_sos_prefix())
            if not self.host:
                self.connected = False
                self.close_ssh_session()
                return None
            self.log_debug("Host facts found to be %s" %
                           self.host.report_facts())
            self.get_hostname()
            self._load_sos_info()

    def _fmt_msg(self, msg):
        return '{:<{}} : {}'.format(self._hostname, self.config['hostlen'] + 1,
                                    msg)

    def file_exists(self, fname):
        '''Checks for the presence of fname on the remote node'''
        if not self.local:
            try:
                self.sftp.stat(fname)
                return True
            except Exception as err:
                return False
        else:
            try:
                os.stat(fname)
                return True
            except Exception:
                return False

    @property
    def _hostname(self):
        return self.hostname if self.hostname else self.address

    def _sanitize_log_msg(self, msg):
        '''Attempts to obfuscate sensitive information in log messages such as
        passwords'''
        reg = r'(?P<var>(pass|key|secret|PASS|KEY|SECRET).*?=)(?P<value>.*?\s)'
        return re.sub(reg, r'\g<var>****** ', msg)

    def log_info(self, msg):
        '''Used to print and log info messages'''
        caller = inspect.stack()[1][3]
        lmsg = '[%s:%s] %s' % (self._hostname, caller, msg)
        self.logger.info(lmsg)
        self.console.info(self._fmt_msg(msg))

    def log_error(self, msg):
        '''Used to print and log error messages'''
        caller = inspect.stack()[1][3]
        lmsg = '[%s:%s] %s' % (self._hostname, caller, msg)
        self.logger.error(lmsg)
        self.console.error(self._fmt_msg(msg))

    def log_debug(self, msg):
        '''Used to print and log debug messages'''
        msg = self._sanitize_log_msg(msg)
        caller = inspect.stack()[1][3]
        msg = '[%s:%s] %s' % (self._hostname, caller, msg)
        self.logger.debug(msg)
        if self.config['verbose']:
            self.console.debug(msg)

    def get_hostname(self):
        '''Get the node's hostname'''
        sout = self.run_command('hostname')
        self.hostname = sout['stdout'].strip()
        self.log_debug(
            'Hostname set to %s' % self.hostname)

    def _format_cmd(self, cmd):
        '''If we need to provide a sudo or root password to a command, then
        here we prefix the command with the correct bits
        '''
        if self.config['become_root']:
            return "su -c '%s'" % cmd
        if self.config['need_sudo']:
            return "sudo -S %s" % cmd
        return cmd

    def _fmt_output(self, stdout=None, stderr=None, rc=0):
        '''Formats the returned output from a command into a dict'''
        c = {}
        c['status'] = rc
        if isinstance(stdout, six.string_types):
            stdout = [str(stdout)]
        if isinstance(stderr, six.string_types):
            stderr = [str(stderr)]
        if stdout:
            stdout = ''.join(s for s in stdout) or True
        if stderr:
            stderr = ' '.join(s for s in stderr) or False
        res = {'status': rc,
               'stdout': stdout,
               'stderr': stderr}
        return res

    def _load_sos_info(self):
        '''Queries the node for information about the installed version of sos
        '''
        cmd = self.host.prefix + self.host.pkg_query('sos')
        res = self.run_command(cmd)
        if res['status'] == 0:
            ver = res['stdout'].splitlines()[-1].split('-')[1]
            self.sos_info['version'] = ver
            self.log_debug('sos version is %s' % self.sos_info['version'])
        else:
            self.log_error('sos is not installed on this node')
            self.connected = False
            return False
        cmd = self.host.prefix + 'sosreport -l'
        sosinfo = self.run_command(cmd)
        if sosinfo['status'] == 0:
            self._load_sos_plugins(sosinfo['stdout'])
        if self.check_sos_version('3.6'):
            self._load_sos_presets()

    def _load_sos_presets(self):
        cmd = self.host.prefix + 'sosreport --list-presets'
        res = self.run_command(cmd)
        if res['status'] == 0:
            for line in res['stdout'].splitlines():
                if line.strip().startswith('name:'):
                    pname = line.split('name:')[1].strip()
                    self.sos_info['presets'].append(pname)

    def _load_sos_plugins(self, sosinfo):
        ENABLED = 'The following plugins are currently enabled:'
        DISABLED = 'The following plugins are currently disabled:'
        OPTIONS = 'The following plugin options are available:'
        PROFILES = 'Profiles:'

        enablereg = ENABLED + '(.*?)' + DISABLED
        disreg = DISABLED + '(.*?)' + OPTIONS
        optreg = OPTIONS + '(.*?)' + PROFILES
        proreg = PROFILES + '(.*?)' + '\n\n'

        self.sos_info['enabled'] = self._regex_sos_help(enablereg, sosinfo)
        self.sos_info['disabled'] = self._regex_sos_help(disreg, sosinfo)
        self.sos_info['options'] = self._regex_sos_help(optreg, sosinfo)
        self.sos_info['profiles'] = self._regex_sos_help(proreg, sosinfo, True)

    def _regex_sos_help(self, regex, sosinfo, is_list=False):
        res = []
        for result in re.findall(regex, sosinfo, re.S):
            for line in result.splitlines():
                if not is_list:
                    try:
                        res.append(line.split()[0])
                    except Exception:
                        pass
                else:
                    r = line.split(',')
                    res.extend(p.strip() for p in r if p.strip())
        return res

    def _set_sos_prefix(self, prefix):
        '''Applies any configuration settings to the sos prefix defined by a
        host type
        '''
        if self.host.containerized:
            prefix = prefix % {
                'image': self.config['image'] or self.host.container_image
            }
        self.host.prefix = prefix

    def read_file(self, to_read):
        '''Reads the specified file and returns the contents'''
        try:
            self.log_debug("Reading file %s" % to_read)
            if not self.local:
                remote = self.sftp.open(to_read)
                return remote.read()
            else:
                with open(to_read, 'r') as rfile:
                    return rfile.read()
        except Exception as err:
            if err.errno == 2:
                self.log_debug("File %s does not exist on node" % to_read)
            else:
                self.log_error("Error reading %s: %s" % (to_read, err))
            return ''

    def determine_host(self):
        '''Attempts to identify the host installation against supported
        distributions
        '''
        for host_type in self.config['host_types']:
            host = self.config['host_types'][host_type](self.address)
            rel_string = self.read_file(host.release_file)
            if host._check_enabled(rel_string):
                self.log_debug("Host installation found to be %s" %
                               host.distribution)
                return host
        self.log_error('Unable to determine host installation. Ignoring node')
        raise Exception('Host did not match any supported distributions')

    def check_sos_version(self, ver):
        '''Checks to see if the sos installation on the node is AT LEAST the
        given ver. This means that if the installed version is greater than
        ver, this will still return True
        '''
        return LooseVersion(self.sos_info['version']) >= ver

    def is_installed(self, pkg):
        '''Checks if a given package is installed on the node'''
        cmd = self.host.pkg_query(pkg)
        res = self.run_command(cmd)
        if res['status'] == 0:
            return True
        return False

    def run_command(self, cmd, timeout=180, get_pty=False, need_root=False):
        '''Runs a given cmd, either via the SSH session or locally'''
        if cmd.startswith('sosreport'):
            cmd = cmd.replace('sosreport', '/usr/sbin/sosreport')
            need_root = True
        if need_root:
            get_pty = True
            cmd = self._format_cmd(cmd)
        self.log_debug('Running command %s' % cmd)
        if 'atomic' in cmd:
            get_pty = True
        if not self.local:
            now = time.time()
            sin, sout, serr = self.client.exec_command(cmd, timeout=timeout,
                                                       get_pty=get_pty)
            while time.time() < now + timeout:
                if not sout.channel.exit_status_ready():
                    time.sleep(0.1)
                    if self.config['become_root'] and need_root:
                        sin.write(self.config['root_password'] + '\n')
                        sin.flush()
                        need_root = False
                    if self.config['sudo_pw'] and need_root:
                        sin.write(self.config['sudo_pw'] + '\n')
                        sin.flush()
                        need_root = False
                if sout.channel.exit_status_ready():
                    rc = sout.channel.recv_exit_status()
                    return self._fmt_output(sout, serr, rc)
            else:
                raise socket.timeout
        else:
            proc = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            stdout, stderr = proc.communicate()
            if self.config['become_root']:
                proc.communicate(input=self.config['root_password'] + '\n')
            if self.config['need_sudo']:
                proc.communicate(input=self.config['sude_pw'] + '\n')
            rc = proc.returncode
            if stdout:
                sout = (stdout or True)
            else:
                sout = None
            return self._fmt_output(stdout=sout, stderr=stderr, rc=rc)

    def sosreport(self):
        '''Run a sosreport on the node, then collect it'''
        self.finalize_sos_cmd()
        self.log_debug('Final sos command set to %s' % self.sos_cmd)
        try:
            path = self.execute_sos_command()
            if path:
                self.finalize_sos_path(path)
            else:
                self.log_error('Unable to determine path of sos archive')
            if self.sos_path:
                self.retrieved = self.retrieve_sosreport()
        except Exception:
            pass
        self.cleanup()

    def _determine_ssh_error(self, errors):
        '''Used to handle ssh exceptions when trying to connect the node.

            errors: the 'errors' dict from the exception raised

            returns: either a formatted error string or None
        '''
        for err in errors:
            errno = errors[err].errno
            if errno == 103:
                return 'Key exchange failed'
            if errno == 108:
                return 'SSH version is unsupported'
            if errno == 111:
                return ("Could not open SSH session on port %s" %
                        self.config['ssh_port'])
            if errno == 115:
                return "No valid SSH user '%s'" % self.config['ssh_user']
        return None

    def open_ssh_session(self):
        '''Create the persistent ssh session we use on the node'''
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.load_system_host_keys()
            self.log_debug('Opening session to %s.' % self.address)
            self.client.connect(self.address,
                                username=self.config['ssh_user'],
                                port=self.config['ssh_port'],
                                password=self.config['password'] or None,
                                timeout=15)
            self.log_debug('%s successfully connected' % self._hostname)
            return True
        except paramiko.AuthenticationException:
            if not self.config['password']:
                self.log_error('Authentication failed. SSH keys installed?')
            else:
                self.log_error('Authentication failed. Incorrect password.')
        except paramiko.BadAuthenticationType:
            self.log_error('Bad authentication type. The node rejected the '
                           'authentication attempt.')
        except paramiko.BadHostKeyException:
            self.log_error('Provided key was rejected by remote SSH client.'
                           ' Check ~/.ssh/known_hosts.')
        except socket.gaierror as err:
            if err.errno == -2:
                self.log_error('Provided hostname did not resolve.')
            else:
                self.log_error('Socket error trying to connect: %s' % err)
        except Exception as err:
            msg = "Unable to connect: %s" % err
            if err.errors:
                msg = self._determine_ssh_error(err.errors)
            self.log_error(msg)
        raise

    def close_ssh_session(self):
        '''Handle closing the SSH session'''
        if self.local:
            return True
        try:
            self.client.close()
            self.connected = False
            return True
        except Exception as e:
            self.log_error('Error closing SSH session: %s' % e)
            return False

    def _preset_exists(self, preset):
        '''Verifies if the given preset exists on the node'''
        return preset in self.sos_info['presets']

    def _plugin_exists(self, plugin):
        '''Verifies if the given plugin exists on the node'''
        return any(plugin in s for s in [self.sos_info['enabled'],
                                         self.sos_info['disabled']])

    def _check_enabled(self, plugin):
        '''Checks to see if the plugin is default enabled on node'''
        return plugin in self.sos_info['enabled']

    def _check_disabled(self, plugin):
        '''Checks to see if the plugin is default disabled on node'''
        return plugin in self.sos_info['disabled']

    def _plugin_option_exists(self, opt):
        '''Attempts to verify that the given option is available on the node.
        Note that we only get available options for enabled plugins, so if a
        plugin has been force-enabled we cannot validate if the plugin option
        is correct or not'''
        plug = opt.split('.')[0]
        if not self._plugin_exists(plug):
            return False
        if (self._check_disabled(plug) and
                plug not in self.config['enable_plugins']):
            return False
        if self._check_enabled(plug):
            return opt in self.sos_info['options']
        # plugin exists, but is normally disabled. Assume user knows option is
        # valid when enabling the plugin
        return True

    def _fmt_sos_opt_list(self, opts):
        '''Returns a comma delimited list for sos plugins that are confirmed
        to exist on the node'''
        return ','.join(o for o in opts if self._plugin_exists(o))

    def finalize_sos_cmd(self):
        '''Use host facts and compare to the cluster type to modify the sos
        command if needed'''
        self.sos_cmd = self.config['sos_cmd']
        self.sos_cmd = self.host.prefix + self.sos_cmd

        label = self.determine_sos_label()
        if label:
            self.sos_cmd = ' %s %s' % (self.sos_cmd, label)

        if self.config['sos_opt_line']:
            return True

        if self.config['only_plugins']:
            plugs = [o for o in self.config['only_plugins']
                     if self._plugin_exists(o)]
            if len(plugs) != len(self.config['only_plugins']):
                not_only = list(set(self.config['only_plugins']) - set(plugs))
                self.log_debug('Requested plugins %s were requested to be '
                               'enabled but do not exist' % not_only)
            only = self._fmt_sos_opt_list(self.config['only_plugins'])
            if only:
                self.sos_cmd += ' --only-plugins=%s' % only
            return True

        if self.config['skip_plugins']:
            # only run skip-plugins for plugins that are enabled
            skip = [o for o in self.config['skip_plugins']
                    if self._check_enabled(o)]
            if len(skip) != len(self.config['skip_plugins']):
                not_skip = list(set(self.config['skip_plugins']) - set(skip))
                self.log_debug('Requested to skip plugins %s, but plugins are '
                               'already not enabled' % not_skip)
            skipln = self._fmt_sos_opt_list(skip)
            if skipln:
                self.sos_cmd += ' --skip-plugins=%s' % skipln

        if self.config['enable_plugins']:
            # only run enable for plugins that are disabled
            opts = [o for o in self.config['enable_plugins']
                    if o not in self.config['skip_plugins']
                    and self._check_disabled(o) and self._plugin_exists(o)]
            if len(opts) != len(self.config['enable_plugins']):
                not_on = list(set(self.config['enable_plugins']) - set(opts))
                self.log_debug('Requested to enable plugins %s, but plugins '
                               'are already enabled or do not exist' % not_on)
            enable = self._fmt_sos_opt_list(opts)
            if enable:
                self.sos_cmd += ' --enable-plugins=%s' % enable

        if self.config['plugin_options']:
            opts = [o for o in self.config['plugin_options']
                    if self._plugin_exists(o.split('.')[0])
                    and self._plugin_option_exists(o.split('=')[0])]
            if opts:
                self.sos_cmd += ' -k %s' % ','.join(o for o in opts)

        if self.config['preset']:
            if self._preset_exists(self.config['preset']):
                self.sos_cmd += ' --preset=%s' % self.config['preset']
            else:
                self.log_debug('Requested to enable preset %s but preset does '
                               'not exist on node' % self.config['preset'])

    def determine_sos_label(self):
        '''Determine what, if any, label should be added to the sosreport'''
        label = ''
        label += self.config['cluster'].get_node_label(self)

        if self.config['label']:
            label += ('%s' % self.config['label'] if not label
                      else '-%s' % self.config['label'])

        if not label:
            return None

        self.log_debug('Label for sosreport set to %s' % label)
        if self.check_sos_version('3.6'):
            lcmd = '--label'
        else:
            lcmd = '--name'
            label = '%s-%s' % (self.address.split('.')[0], label)
        return '%s=%s' % (lcmd, label)

    def finalize_sos_path(self, path):
        '''Use host facts to determine if we need to change the sos path
        we are retrieving from'''
        pstrip = self.host.sos_path_strip
        if pstrip:
            path = path.replace(pstrip, '')
        path = path.split()[0]
        self.log_debug('Final sos path: %s' % path)
        self.sos_path = path
        self.archive = path.split('/')[-1]

    def determine_sos_error(self, rc, stdout):
        if rc == -1:
            return 'sosreport process received SIGKILL on node'
        if rc == 1:
            if 'sudo' in stdout:
                return 'sudo attempt failed'
        if rc == 127:
            return 'sosreport terminated unexpectedly. Check disk space'
        if len(stdout) > 0:
            return stdout.split('\n')[0:1]
        else:
            return 'sos exited with code %s' % rc

    def execute_sos_command(self):
        '''Run sosreport and capture the resulting file path'''
        self.log_info("Generating sosreport...")
        try:
            path = False
            res = self.run_command(self.sos_cmd,
                                   timeout=self.config['timeout'],
                                   get_pty=True, need_root=True)
            if res['status'] == 0:
                for line in res['stdout'].splitlines():
                    if fnmatch.fnmatch(line, '*sosreport-*tar*'):
                        path = line.strip()
            else:
                err = self.determine_sos_error(res['status'], res['stdout'])
                self.log_debug("Error running sosreport. rc = %s msg = %s"
                               % (res['status'], res['stdout'] or
                                  res['stderr']))
                raise Exception(err)
            return path
        except socket.timeout:
            self.log_error('Timeout exceeded')
            raise
        except Exception as e:
            self.log_error('Error running sosreport: %s' % e)
            raise

    def retrieve_file(self, path):
        '''Copies the specified file from the host to our temp dir'''
        destdir = self.config['tmp_dir'] + '/'
        dest = destdir + path.split('/')[-1]
        try:
            if not self.local:
                if self.file_exists(path):
                    self.log_debug("Copying remote %s to local %s" %
                                   (path, destdir))
                    self.sftp.get(path, dest)
                else:
                    self.log_debug("Attempting to copy remote file %s, but it "
                                   "does not exist on filesystem" % path)
                    return False
            else:
                self.log_debug("Moving %s to %s" % (path, destdir))
                shutil.move(path, dest)
            return True
        except Exception as err:
            self.log_debug("Failed to retrieve %s: %s" % (path, err))
            return False

    def remove_file(self, path):
        '''Removes the spciefied file from the host. This should only be used
        after we have retrieved the file already
        '''
        try:
            if self.file_exists(path):
                self.log_debug("Removing file %s" % path)
                if (self.local or self.config['become_root'] or
                        self.config['need_sudo']):
                    cmd = "rm -f %s" % path
                    res = self.run_command(cmd, need_root=True)
                else:
                    self.sftp.remove(path)
                return True
            else:
                self.log_debug("Attempting to remove remote file %s, but it "
                               "does not exist on filesystem" % path)
                return False
        except Exception as e:
            self.log_debug('Failed to remove %s: %s' % (path, e))
            return False

    def retrieve_sosreport(self):
        '''Collect the sosreport archive from the node'''
        if self.sos_path:
            if self.config['need_sudo'] or self.config['become_root']:
                try:
                    self.make_archive_readable(self.sos_path)
                except Exception:
                    self.log_error('Failed to make archive readable')
                    return False
            self.logger.info('Retrieving sosreport from %s' % self.address)
            self.log_info('Retrieving sosreport...')
            ret = self.retrieve_file(self.sos_path)
            if ret:
                self.log_info('Successfully collected sosreport')
            else:
                self.log_error('Failed to retrieve sosreport')
                return False
            self.hash_retrieved = self.retrieve_file(self.sos_path + '.md5')
            return True
        else:
            # sos sometimes fails but still returns a 0 exit code
            if self.stderr.read():
                e = self.stderr.read()
            else:
                e = [x.strip() for x in self.stdout.readlines() if x.strip][-1]
            self.logger.error(
                'Failed to run sosreport on %s: %s' % (self.address, e))
            self.log_error('Failed to run sosreport. %s' % e)
            return False

    def remove_sos_archive(self):
        '''Remove the sosreport archive from the node, since we have
        collected it and it would be wasted space otherwise'''
        if self.sos_path is None:
            return
        if 'sosreport' not in self.sos_path:
            self.log_debug("Node sosreport path %s looks incorrect. Not "
                           "attempting to remove path" % self.sos_path)
            return
        removed = self.remove_file(self.sos_path)
        if not removed:
            self.log_error('Failed to remove sosreport')

    def cleanup(self):
        '''Remove the sos archive from the node once we have it locally'''
        self.remove_sos_archive()
        if self.hash_retrieved:
            self.remove_file(self.sos_path + '.md5')
        cleanup = self.host.set_cleanup_cmd()
        if cleanup:
            self.run_command(cleanup)

    def collect_extra_cmd(self, filenames):
        '''Collect the file created by a cluster outside of sos'''
        for filename in filenames:
            try:
                if self.config['need_sudo'] or self.config['become_root']:
                    try:
                        self.make_archive_readable(filename)
                    except Exception as err:
                        self.log_error("Unable to retrieve file %s" % filename)
                        self.log_debug("Failed to make file %s readable: %s"
                                       % (filename, err))
                        continue
                ret = self.retrieve_file(filename)
                if ret:
                    self.remove_file(filename)
                else:
                    self.log_error("Unable to retrieve file %s" % filename)
            except Exception as e:
                msg = 'Error collecting additional data from master: %s' % e
                self.log_error(msg)

    def make_archive_readable(self, filepath):
        '''Used to make the given archive world-readable, which is slightly
        better than changing the ownership outright.

        This is only used when we're not connecting as root.
        '''
        cmd = 'chmod +r %s' % filepath
        res = self.run_command(cmd, timeout=10, need_root=True)
        if res['status'] == 0:
            return True
        else:
            msg = "Exception while making %s readable. Return code was %s"
            self.log_error(msg % (filepath, res['status']))
            raise Exception
