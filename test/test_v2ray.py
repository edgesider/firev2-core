import unittest

import v2ray
from v2_config import Routing, Inbound, Node
import demo_data


class TestV2ray(unittest.TestCase):

    def test_make_config(self):
        r = Routing()
        r.add_rule('auto', 'proxy', ['domain:google.com', 'domain:youtu.be', 'ip:1.1.1.1'], )
        r.add_rule('auto', 'direct', [])
        c = v2ray.make_config(inbound=Inbound('auto', 'socks', 3000),
                              node=Node(vmess=demo_data.get_demo_vmess_str()),
                              routing=r)

        self.assertEqual(c, {'inbounds': [{'listen': '127.0.0.1',
                                           'port': 3000,
                                           'protocol': 'socks',
                                           'tag': 'auto'}],
                             'outbounds': [{'protocol': 'blackhole', 'tag': 'blackhole'},
                                           {'protocol': 'freedom', 'tag': 'direct'},
                                           {'protocol': 'vmess',
                                            'settings': {'vnext': [{'address': 'google.com',
                                                                    'port': 8000,
                                                                    'ps': 'google',
                                                                    'users': [{'alterId': 1,
                                                                               'id': 'ABCDEFGH-IJKL-MNOPQRSTU-VWXYZ0123456',
                                                                               'level': 0,
                                                                               'security': 'auto'}]}]},
                                            'streamSettings': {'network': 'ws',
                                                               'security': 'tls',
                                                               'wsSettings': {'header': {'type': 'utp'}}},
                                            'tag': 'proxy'}],
                             'routing': {'domainStrategy': 'AsIs',
                                         'rules': [{'inboundTag': 'auto',
                                                    'ip': ['1.1.1.1'],
                                                    'outboundTag': 'proxy',
                                                    'type': 'field'},
                                                   {'domain': ['google.com', 'youtu.be'],
                                                    'inboundTag': 'auto',
                                                    'outboundTag': 'proxy',
                                                    'type': 'field'},
                                                   {'inboundTag': 'auto',
                                                    'outboundTag': 'direct',
                                                    'type': 'field'}]}})


def test_monitor():
    config = {
        "log": {
            "access": "/run/user/1000/firev2/test_access.log",
            "error": "/run/user/1000/firev2/test_error.log",
            "loglevel": "debug"
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": "proxy",
                    "outboundTag": "proxy"
                },
                {
                    "type": "field",
                    "domain": [
                        "geosite:geolocation-!cn",
                        "github.com",
                        "githun.io",
                        "u9un.com",
                        "docker.com",
                        "docker.io"
                    ],
                    "inboundTag": "auto",
                    "outboundTag": "proxy"
                },
                {
                    "type": "field",
                    "ip": [
                        "geoip:cn"
                    ],
                    "inboundTag": "auto",
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "inboundTag": "auto",
                    "outboundTag": "direct"
                }
            ]
        },
        "inbounds": [
            {
                "tag": "auto",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": 3000,
                "settings": {
                    "ip": "127.0.0.1",
                    "auth": "noauth",
                    "udp": False,
                    "userLevel": 0
                }
            },
            {
                "tag": "proxy",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": 3001,
                "settings": {
                    "ip": "127.0.0.1",
                    "auth": "noauth",
                    "udp": False,
                    "userLevel": 0
                }
            }
        ],
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            },
            {
                "tag": "blocked",
                "protocol": "blackhole",
                "settings": {}
            },
            {
                "tag": "proxy",
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": "tw1.v2u9.top",
                            "port": 443,
                            "users": [
                                {
                                    "id": "CEB9A517-D7F0-FFA0-2B79-D5BAE642411E",
                                    "alterId": 1,
                                    "security": "auto",
                                    "level": 0
                                }
                            ],
                            "ps": "台湾1(1)"
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "wsSettings": {
                        "header": {
                            "type": "utp"
                        }
                    }
                }
            }
        ]
    }

    vm = v2ray.V2rayManager()
    if vm.is_running():
        vm.stop()
    vm.start(config)
    acc_file = vm.get_access_log_file()
    print(acc_file.read(150))


if __name__ == '__main__':
    unittest.main()
    # test_monitor()
