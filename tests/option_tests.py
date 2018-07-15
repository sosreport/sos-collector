import unittest

from soscollector.configuration import Configuration, ClusterOption


class OptionTests(unittest.TestCase):

    def setUp(self):
        args = {
            'nodes': 'localhost',
            'cluster_options': 'foo.bar=foobar',
            'enable_plugins': 'foobar,barfoo',
            'skip_plugins': 'barfoo'
        }
        self.config = Configuration(args)

    def test_option_parse(self):
        self.assertEquals(self.config['nodes'], 'localhost')

    def test_cluster_options_parsing(self):
        self.assertIsInstance(self.config['cluster_options'], list)
        self.assertIsInstance(self.config['cluster_options'][0], ClusterOption)

    def test_cluster_options_value(self):
        opt = self.config['cluster_options'][0]
        self.assertEquals(opt.value, 'foobar')
        self.assertEquals(opt.name, 'bar')
        self.assertEquals(opt.cluster, 'foo')

    def test_sos_options_plugins(self):
        self.assertIsInstance(self.config['enable_plugins'], list)
        self.assertIsInstance(self.config['skip_plugins'], list)
        self.assertEquals(self.config['enable_plugins'], ['foobar', 'barfoo'])
        self.assertEquals(self.config['skip_plugins'], ['barfoo'])
