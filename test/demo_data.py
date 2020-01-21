from base64 import b64encode
from v2_config import Node
import json

demo_node_info = {'add': 'google.com',
                  'id': 'ABCDEFGH-IJKL-MNOPQRSTU-VWXYZ0123456',
                  'port': 8000,
                  'aid': 1,
                  'ps': 'google',
                  'net': 'ws',
                  'tls': 'tls',
                  'type': 'utp'}


def get_demo_vmess():
    s = json.dumps(demo_node_info, ensure_ascii=False)
    return b64encode(s.encode('utf8'))


def get_demo_vmess_str():
    return 'vmess://' + get_demo_vmess().decode('utf8')


def get_demo_dict():
    return {'protocol': 'vmess',
            'settings': {'vnext': [{'address': demo_node_info['add'],
                                    'port': demo_node_info['port'],
                                    'ps': demo_node_info['ps'],
                                    'users': [{'alterId': demo_node_info['aid'],
                                               'id': demo_node_info['id'],
                                               'level': 0,
                                               'security': 'auto'}]}]},
            'streamSettings': {'network': demo_node_info['net'],
                               'security': demo_node_info['tls'],
                               'wsSettings': {'header': {'type': demo_node_info['type']}}},
            'tag': ''}


def get_demo_node():
    return Node(dict=get_demo_dict())
