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
import logging
import paramiko
import shutil
import socket
import subprocess
import sys
import time

from subprocess import Popen, PIPE


class SosNode():

    def __init__(self, address, config):
        self.address = address.strip()
        self.local = False
        self.hostname = None
        self.config = config
        self.sos_path = None
        self.retrieved = False
        self.host_facts = {}
        self.logger = logging.getLogger('sos_collector')
        self.console = logging.getLogger('sos_collector_console')
        if self.address not in ['localhost', '127.0.0.1']:
            # TODO: add check for address matching local hostname
            self.connected = self.open_ssh_session()
        else:
            self.connected = True
            self.local = True
        if self.connected:
            self.get_hostname()
            self.load_host_facts()

    def _fmt_msg(self, msg):
        return '{:<{}} : {}'.format(self._hostname,
                                    self.config['hostlen'],
                                    msg)

    def file_exists(self, fname):
        '''Checks for the presence of fname on the remote node'''
        if not self.local:
            sftp = self.client.open_sftp()
            try:
                sftp.stat(fname)
                return True
            except:
                return False
        else:
            try:
                os.stat(fname)
                return True
            except:
                return False

    @property
    def _hostname(self):
        return self.hostname if self.hostname else self.address

    def log_info(self, msg):
        '''Used to print and log info messages'''
        self.logger.info(' %s: %s' % (self._hostname, msg))
        self.console.info(self._fmt_msg(msg))

    def log_error(self, msg):
        '''Used to print and log error messages'''
        self.logger.error(' %s: %s' % (self._hostname, msg))
        self.console.info(self._fmt_msg(msg))

    def log_debug(self, msg):
        '''Used to print and log debug messages'''
        self.logger.debug(' %s: %s' % (self._hostname, msg))
        self.console.debug(self._fmt_msg(msg))

    def get_hostname(self):
        '''Get the node's hostname'''
        sout = self.run_command('hostname')
        self.hostname = sout['stdout'].strip()
        self.logger.debug(
            'Hostname for %s set to %s' % (self.address, self.hostname))

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
        if stdout:
            stdout = ' '.join(s for s in stdout) or True
        if stderr:
            stderr = ' '.join(s for s in stderr) or True
        res = {'status': rc,
               'stdout': stdout,
               'stderr': stderr}
        return res

    def run_command(self, cmd, timeout=180, get_pty=False):
        '''Runs a given cmd, either via the SSH session or locally'''
        if not self.local:
            now = time.time()
            sin, sout, serr = self.client.exec_command(cmd, timeout=timeout,
                                                       get_pty=get_pty)
            if self.config['become_root']:
                sin.write(self.config['root_password'] + '\n')
                sin.flush()
            if self.config['need_sudo']:
                sin.write(self.config['sudo_pw'] + '\n')
                sin.flush()
            while time.time() < now + timeout:
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
                sout = ([s.decode('utf-8') for s in stdout.splitlines()] or
                        True)
            else:
                sout = None
            return self._fmt_output(stdout=sout, stderr=stderr, rc=rc)

    def sosreport(self):
        '''Run a sosreport on the node, then collect it'''
        self.finalize_sos_cmd()
        self.logger.debug('Running sosreport on %s' % self.address)
        self.execute_sos_command()
        if self.sos_path:
            self.retrieved = self.retrieve_sosreport()
        self.cleanup()

    def open_ssh_session(self):
        '''Create the persistent ssh session we use on the node'''
        try:
            msg = ''
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.load_system_host_keys()
            if not self.config['password']:
                self.logger.debug(
                    'Opening passwordless session to %s' % self.address)
                self.client.connect(self.address,
                                    username=self.config['ssh_user'],
                                    timeout=15)
            else:
                self.logger.debug(
                    'Opening session to %s with password' % self.address)
                self.client.connect(self.address,
                                    username=self.config['ssh_user'],
                                    password=self.config['password'],
                                    timeout=15)
            self.logger.debug('%s successfully connected' % self._hostname)
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
        except Exception as e:
            self.log_error('Exception caught while trying to connect: %s' % e)
        return False

    def close_ssh_session(self):
        '''Handle closing the SSH session'''
        if self.local:
            return True
        try:
            self.client.close()
            return True
        except Exception as e:
            self.log_error('Error closing SSH session: %s' % e)
            return False

    def load_host_facts(self):
        '''Obtain information about the node which can be referneced by
        clusters to change the sosreport command'''
        self.get_release()
        self.set_package_manager()
        self.logger.debug('%s facts found to be %s'
                          % (self._hostname, self.host_facts))

    def get_release(self):
        '''Determine the distribution that we're running on.
        For our intents, any Red Hat family distribution or derivitive is going
        to be listed as 'Red Hat'
        '''
        release = 'Unknown'
        self.host_facts['release'] = release
        self.host_facts['atomic'] = False
        try:
            if self.file_exists('/etc/redhat-release'):
                relfile = '/etc/redhat-release'
            else:
                relfile = '/etc/os-release'
            res = self.run_command('cat ' + relfile)
            if len(res['stdout'].split('\n')) > 2:
                for line in res['stdout']:
                    if line.startswith('NAME'):
                        release = line.split()[1].lower()
            else:
                release = res['stdout'].lower()
            rh = ['fedora', 'centos', 'red hat']
            if any(rel in release for rel in rh):
                self.host_facts['release'] = 'Red Hat'
            self.host_facts['atomic'] = 'atomic' in release
        except Exception as e:
            self.log_error(e)

    def set_package_manager(self):
        '''Based on the distribution of the node, set the package manager to
        use for checking system installations'''
        self.host_facts['package_manager'] = None
        if self.host_facts['release'] == 'Red Hat':
            self.host_facts['package_manager'] = {'name': 'rpm',
                                                  'query': 'rpm -q '
                                                  }

    def finalize_sos_cmd(self):
        '''Use host facts and compare to the cluster type to modify the sos
        command if needed'''
        self.sos_cmd = self._format_cmd(self.config['sos_cmd'])
        prefix = self.config['cluster'].get_sos_prefix(self.host_facts)
        if prefix:
            self.sos_cmd = prefix + ' ' + self.sos_cmd
        self.logger.info(
            'Final sos command for %s: %s' % (self.address, self.sos_cmd))

    def finalize_sos_path(self, path):
        '''Use host facts to determine if we need to change the sos path
        we are retrieving from'''
        pstrip = self.config['cluster'].get_sos_path_strip(self.host_facts)
        if pstrip:
            return path.replace(pstrip, '')
        self.logger.debug('Final sos path for %s: %s' % (self.address, path))
        self.sos_path = path
        self.archive = path.split('/')[-1]

    def determine_sos_error(self, rc, stdout):
        if rc == -1:
            return 'sosreport process received SIGKILL on node'
        if rc == 127:
            return 'sosreport terminated unexpectedly. Check disk space'
        if len(stdout) > 0:
            return stdout.split('\n')[0:1]
        else:
            return 'sos exited with code %s' % rc

    def execute_sos_command(self):
        '''Run sosreport and capture the resulting file path'''
        self.logger.info('Running sosreport on %s' % self.address)
        self.log_info("Generating sosreport...")
        try:
            res = self.run_command(self.sos_cmd,
                                   timeout=self.config['timeout'],
                                   get_pty=True)
            if res['status'] == 0:
                for line in res['stdout'].split(' '):
                    if fnmatch.fnmatch(line, '*sosreport-*tar*'):
                        line = line.strip()
                        self.finalize_sos_path(line)
            else:
                err = self.determine_sos_error(res['status'], res['stdout'])
                self.log_debug("Error running sosreport. rc = %s msg = %s"
                               % (res['status'], res['stdout'] or
                                  res['stderr']))
                self.log_error('Error running sosreport: %s' % err)
        except socket.timeout:
            self.log_error('Timeout exceeded')
        except Exception as e:
            self.log_error('Error running sosreport: %s' % e)

    def retrieve_sosreport(self):
        '''Collect the sosreport archive from the node'''
        if self.sos_path:
            if self.config['need_sudo'] or self.config['become_root']:
                try:
                    self.make_archive_readable(self.sos_path)
                except:
                    self.log_error('Failed to make archive readable')
                    return False
            self.logger.info('Retrieving sosreport from %s' % self.address)
            self.log_info('Retrieving sosreport...')
            try:
                dest = self.config['tmp_dir'] + '/' + self.archive
                if not self.local:
                    sftp = self.client.open_sftp()
                    sftp.get(self.sos_path, dest)
                    sftp.close()
                else:
                    shutil.move(self.sos_path, dest)
                self.retrieved = True
                self.log_info('Successfully collected sosreport')
                return True
            except Exception as err:
                msg = 'Failed to retrieve sosreport from %s, error: %s'
                self.logger.error(msg % (self.address, err))
                self.log_error('Failed to retrieve sosreport. %s' % err)
                return False
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
        try:
            cmd = self._format_cmd("rm -f %s" % self.sos_path)
            res = self.run_command(cmd)
        except Exception as e:
            self.log_error('Failed to remove sosreport on host: %s' % e)

    def cleanup(self):
        '''Remove the sos archive from the node once we have it locally'''
        self.remove_sos_archive()
        cleanup = self.config['cluster'].get_cleanup_cmd(self.host_facts)
        if cleanup:
            sin, sout, serr = self.client.exec_command(cleanup, timeout=15)

    def collect_extra_cmd(self, filename):
        '''Collect the file created by a cluster outside of sos'''
        try:
            if self.config['need_sudo'] or self.config['become_root']:
                try:
                    self.make_archive_readable(filename)
                except:
                    self.console.error('Unable to make extra data readable')
                    return False
            dest = self.config['tmp_dir'] + '/' + filename.split('/')[-1]
            if not self.local:
                sftp = self.client.open_sftp()
                sftp.get(filename, dest)
                sftp.close()
            else:
                shutil.move(filename, dest)
            return True
        except Exception as e:
            msg = 'Error collecting additional data from master: %s' % e
            self.console.error(msg)
            return False

    def make_archive_readable(self, filepath):
        '''Used to make the given archive world-readable, which is slightly
        better than changing the ownership outright.

        This is only used when we're not connecting as root.
        '''
        cmd = self._format_cmd('chmod +r %s' % filepath)
        res = self.run_command(cmd, timeout=10, get_pty=True)
        if res['status'] == 0:
            return True
        else:
            msg = "Exception while making %s readable. Return code was %s"
            self.logger.error(msg % (filepath, res['status']))
            raise Exception
