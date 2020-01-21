import unittest
from v2_config import Routing


class TestRouting(unittest.TestCase):

    def test_rule_domain(self):
        r = Routing()
        r.add_rule('always', 'proxy', ['domain:google.com'])
        self.assertEqual(r.to_dict(), {'domainStrategy': 'AsIs',
                                       'rules': [
                                           {'type': 'field',
                                            'domain': ['google.com'],
                                            'inboundTag': 'always',
                                            'outboundTag': 'proxy'
                                            }]})

    def test_rule_ip(self):
        r = Routing()
        r.add_rule('always', 'proxy', ['ip:1.1.1.1'])
        self.assertEqual(r.to_dict(), {'domainStrategy': 'AsIs',
                                       'rules': [
                                           {'type': 'field',
                                            'ip': ['1.1.1.1'],
                                            'inboundTag': 'always',
                                            'outboundTag': 'proxy'
                                            }]})

    def test_rule_None(self):
        r = Routing()
        r.add_rule('always', 'proxy', None)
        self.assertEqual(r.to_dict(), {'domainStrategy': 'AsIs',
                                       'rules': [
                                           {'type': 'field',
                                            'inboundTag': 'always',
                                            'outboundTag': 'proxy'
                                            }]})

    def test_rule_empty(self):
        r = Routing()
        r.add_rule('always', 'proxy', [])
        self.assertEqual(r.to_dict(), {'domainStrategy': 'AsIs',
                                       'rules': [
                                           {'type': 'field',
                                            'inboundTag': 'always',
                                            'outboundTag': 'proxy'
                                            }]})

    def test_rule_multi(self):
        r = Routing()
        r.add_rule('auto', 'proxy', ['domain:google.com', 'domain:youtu.be', 'ip:1.1.1.1'])
        self.assertEqual(r.to_dict(), {'domainStrategy': 'AsIs',
                                       'rules': [{'inboundTag': 'auto',
                                                  'ip': ['1.1.1.1'],
                                                  'outboundTag': 'proxy',
                                                  'type': 'field'},
                                                 {'domain': ['google.com', 'youtu.be'],
                                                  'inboundTag': 'auto',
                                                  'outboundTag': 'proxy',
                                                  'type': 'field'}]})


if __name__ == '__main__':
    unittest.main()
