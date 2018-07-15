import unittest

from soscollector.sosnode import SosNode
from soscollector.configuration import Configuration

class SosNodeTests(unittest.TestCase):

    def setUp(self):
        args = {'nodes': 'localhost'}
        self.config = Configuration(args=args)
        self.node = SosNode('127.0.0.1', self.config, force=True,
                            load_facts=False)

    def test_connect_local_no_check(self):
        self.assertTrue(self.node.connected)

    def test_connect_local_check(self):
        node = SosNode('127.0.0.1', self.config, force=True)
        self.assertTrue(node.connected)

    def test_command_exec(self):
        out = self.node.run_command('echo sos-collector')
        self.assertEquals(out['status'], 0)
        self.assertEquals(out['stdout'], 'sos-collector\n')
