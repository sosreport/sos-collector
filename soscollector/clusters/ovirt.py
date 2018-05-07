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

import os
import fnmatch

from soscollector.clusters import Cluster
from getpass import getpass


class ovirt(Cluster):

    packages = ('ovirt-engine', 'rhevm')
    sos_plugins = ['ovirt']

    option_list = [
        ('no-database', False, 'Do not collect a database dump'),
        ('cluster', '', 'Only collect from hosts in this cluster')
    ]

    def setup(self):
        self.pg_pass = False
        if not self.get_option('no-database'):
            self.conf = self.parse_db_conf()
            self.pg_pass = self.get_db_password()
        self.dbcmd = '/usr/share/ovirt-engine/dbscripts/engine-psql.sh -c '
        if not self.get_option('cluster'):
            self.dbcmd += '"select host_name from vds_static"'
        else:
            self.dbcmd += ('"select v.host_name from vds_static as v, cluster'
                           'as c where v.cluster_id = (select cluster_id from'
                           'cluster where name = \'%s\') "'
                           % self.get_option('cluster'))

    def get_nodes(self):
        res = self.exec_master_cmd(self.dbcmd)
        if res['status'] == 0:
            nodes = res['stdout'].splitlines()[2:-1]
            return [n.split('(')[0].strip() for n in nodes]
        else:
            raise Exception('database query failed, return code: %s'
                            % res['status'])

    def run_extra_cmd(self):
        if self.pg_pass:
            return self.collect_database()
        return False

    def get_db_password(self):
        if not self.conf:
            self.log_error('Could not parse database configuration. Will not '
                           'attempt to collect database dump from the manager'
                           )
            return False
        pg_pass = getpass('Please provide the engine database password: ')
        return pg_pass if pg_pass else False

    def parse_db_conf(self):
        conf = {}
        engconf = '/etc/ovirt-engine/engine.conf.d/10-setup-database.conf'
        res = self.exec_master_cmd('cat %s' % engconf)
        if res['status'] == 0:
            config = res['stdout'].splitlines()
        for line in config:
            k = str(line.split('=')[0])
            v = str(line.split('=')[1].replace('"', ''))
            conf[k] = v
        return conf

    def collect_database(self):
        sos_opt = (
                   '-k {plugin}.dbname={db} '
                   '-k {plugin}.dbhost={dbhost} '
                   '-k {plugin}.dbport={dbport} '
                   '-k {plugin}.username={dbuser} '
                   ).format(plugin='postgresql',
                            db=self.conf['ENGINE_DB_DATABASE'],
                            dbhost=self.conf['ENGINE_DB_HOST'],
                            dbport=self.conf['ENGINE_DB_PORT'],
                            dbuser=self.conf['ENGINE_DB_USER']
                            )
        cmd = ('PGPASSWORD={} /usr/sbin/sosreport --name=postgresqldb '
               '--batch -o postgresql {}'
               ).format(self.pg_pass, sos_opt)
        db_sos = self.exec_master_cmd(cmd)
        for line in db_sos['stdout'].splitlines():
            if fnmatch.fnmatch(line, '*sosreport-*tar*'):
                return line.strip()
        self.log_error('Failed to gather database dump')
        return False
