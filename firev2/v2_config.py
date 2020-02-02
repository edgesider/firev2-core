from __future__ import annotations
import json
import os
import re
from abc import ABC
from base64 import b64decode

import requests

from . import config
from .config import tag_blocked, tag_direct
from typing import List, Dict, Tuple, Optional, Union, Set
from .serializable import Serializable, NamedSerializableManager, SerializableType


def b64decode_pad(b64str):
    padsize = 3 - (len(b64str) + 3) % 4
    return b64decode(b64str + '=' * padsize)


class V2ConfigObject(ABC):

    def to_v2_object(self):
        raise NotImplementedError


class Node(V2ConfigObject, Serializable, ABC):
    tag: str
    remark: str
    protocol: str

    @classmethod
    def from_object(cls, obj: Dict):
        """factory of nodes"""
        protocol = obj['protocol']
        if protocol == 'vmess':
            return VmessNode.from_object(obj)
        elif protocol == 'blackhole':
            return BlockedNode.from_object(obj)
        elif protocol == 'freedom':
            return DirectNode.from_object(obj)
        else:
            raise ValueError

    def to_v2_object(self, tag=None):
        raise NotImplementedError


class BlockedNode(Node):

    @property
    def remark(self):
        return 'blackhole'

    @property
    def tag(self):
        return tag_blocked

    def to_v2_object(self, tag=None):
        return {
            'tag': tag_blocked,
            'protocol': 'blackhole',
        }

    def to_object(self):
        return self.to_v2_object()


class DirectNode(Node):

    @property
    def remark(self):
        return 'freedom'

    @property
    def tag(self):
        return tag_direct

    def to_v2_object(self, tag=None):
        return {
            'tag': tag_direct,
            'protocol': 'freedom',
        }

    def to_object(self):
        return self.to_v2_object()


class VmessNode(Node):
    tag: str
    remark: str
    address: str
    port: int
    user_id: str
    alter_id: int
    network: str
    tls: bool
    header_type: str

    def __init__(self, vmess_str=None):
        self.tag = ''
        self.remark = ''
        self.address = ''
        self.port = 0
        self.user_id = ''
        self.alter_id = 0
        self.network = ''
        self.tls = False
        self.header_type = ''
        if vmess_str is not None:
            self.read_vmess_str(vmess_str)

    @property
    def protocol(self):
        return 'vmess'

    def read_vmess_str(self, vs: str):
        vs = vs.strip()
        vs = vs.replace('vmess://', '')
        conf: dict = json.loads(b64decode_pad(vs))
        self.address = conf.get('add')
        self.port = int(conf.get('port'))
        self.user_id = conf.get('id')
        self.alter_id = conf.get('aid')
        self.network = conf.get('net')
        self.tls = bool(conf.get('tls'))
        self.header_type = conf.get('type')
        self.remark = conf.get('ps')

    def to_v2_object(self, tag=None):
        if tag is None:
            tag = self.tag
        rv = {
            'tag': tag,
            'protocol': 'vmess',
            'settings': {
                'vnext': [
                    {
                        'address': self.address,
                        'port': self.port,
                        'users': [
                            {
                                'id': self.user_id,
                                'alterId': self.alter_id,
                                'security': 'auto',
                                'level': 0
                            }
                        ],
                        'ps': self.remark
                    }
                ]
            },
            'streamSettings': {
                'network': self.network,
                'security': 'tls' if self.tls else None,
            }
        }
        if self.header_type and self.network:
            # noinspection PyTypeChecker
            rv['streamSettings'][self.network + 'Settings'] = {'header': {'type': self.header_type}}
        return rv

    @classmethod
    def from_object(cls, obj: SerializableType):
        rv = cls()
        rv.address = obj.get('address')
        rv.port = int(obj.get('port'))
        rv.user_id = obj.get('user_id')
        rv.alter_id = obj.get('alter_id')
        rv.network = obj.get('network')
        rv.tls = bool(obj.get('tls'))
        rv.header_type = obj.get('header_type')
        rv.remark = obj.get('remark')
        return rv

    def to_object(self):
        return {'protocol': 'vmess',
                'address': self.address,
                'port': self.port,
                'user_id': self.user_id,
                'alter_id': self.alter_id,
                'network': self.network,
                'tls': self.tls,
                'header_type': self.header_type,
                'remark': self.remark}


class Subscription(Serializable):
    nodes: Optional[List[Node]]
    url: str

    def __init__(self, url=None, dict=None):
        self.nodes = None
        self.url = ''

        if url:
            self.url = url
            self.update()
        elif dict:
            self.url = dict['url']
            self.nodes = [Node.from_object(n) for n in dict['nodes']]
        else:
            raise ValueError('url/dict are both unspecified or invalid')

    @classmethod
    def get_builtin(cls):
        return cls(dict={
            'url': config.url_builtin,
            'nodes': [DirectNode(), BlockedNode()]
        })

    def update(self):
        if self.url == config.url_builtin:
            self.nodes = [DirectNode(), BlockedNode()]
            return
        # TODO
        r = requests.get(self.url)
        r.encoding = 'ascii'
        s: str = b64decode_pad(r.text).decode('ascii').strip()
        if s.find('\n') > s.find('\r\n'):
            split = '\n'
        else:
            split = '\r\n'
        vmess_list = [v.strip() for v in s.split(split) if v.strip()]
        self.nodes = [VmessNode(vmess_str=v) for v in vmess_list]

    def get_node_by_index(self, idx):
        if 0 <= idx < len(self.nodes):
            return self.nodes[idx]
        else:
            return None

    def to_object(self):
        return {
            'url': self.url,
            'nodes': [n.to_object() for n in self.nodes]
        }

    @classmethod
    def from_object(cls, obj):
        return cls(dict=obj)

    def __hash__(self):
        return hash(id(self))

    def __eq__(self, other):
        return isinstance(other, type(self)) and \
               self.url == other.url and \
               self.nodes == other.nodes

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return f'<Subscription url={self.url}>'


class Routing(Serializable, V2ConfigObject):
    rules: Dict[Tuple[str, str], Set[str]]
    master: Optional[str]

    _ip_re = re.compile(r'^([0-1]?\d{1,2}|2(5[0-5]|[0-4]\d))(.\1){3}(/(8|16|24|32))?$')

    def __init__(self, rules: List[dict] = None, master=None):
        self.rules = {}
        self.master = master
        if rules is not None:
            self.read_objects(rules)

    def add_rule(self, tag_in: str, tag_out: str,
                 matchers: Optional[Union[str, List[str]]]):
        # TODO conflicts detect and solve
        if matchers is None:
            matchers = []
        if isinstance(matchers, str):
            matchers = [s.strip() for s in matchers.split(',')]
        matchers = [m for m in matchers]
        self.rules.setdefault((tag_in, tag_out), set()).update(matchers)

    def remove_rule(self, tag_in, tag_out, matcher=None):
        if matcher is None:
            self.rules.pop((tag_in, tag_out))
        else:
            self.rules[(tag_in, tag_out)].remove(matcher)

    def make_config(self, inbound_mgr: InboundManager,
                    subscr_mgr: SubscriptionManager):
        """return a v2ray config directory which has
        three keys: inbounds, outbounds, routings
        """
        inbounds = []
        nodes = []
        if self.rules:
            inbound_names, node_names = zip(*self.rules.keys())
            inbound_names = set(inbound_names)
            node_names = list(set(node_names))
            if self.master is not None:
                # move master node to first
                if self.master in node_names:
                    node_names.remove(self.master)
                node_names.insert(0, self.master)
            for name in inbound_names:
                i: Inbound = inbound_mgr.get_by_name(name)
                assert i, f'no such inbound "{name}"'
                inbounds.append(i.to_object(name))
            for name in node_names:
                n: Node = subscr_mgr.get_node(name)
                assert n, f'no such node "{name}"'
                nodes.append(n.to_v2_object(name))
        return {'inbounds': inbounds,
                'outbounds': nodes,
                'routing': self.to_v2_object(),
                'log': {'logLevel': 'debug'}}

    def read_objects(self, rules: List[dict]):
        for rule in rules:
            in_tag = rule['inboundTag']
            out_tag = rule['outboundTag']
            ips: List[str] = rule.get('ip')
            domains: List[str] = rule.get('domain')
            if ips:
                self.add_rule(in_tag, out_tag, ips)
            elif domains:
                self.add_rule(in_tag, out_tag, domains)
            else:
                self.add_rule(in_tag, out_tag, None)
            if ips and domains:
                print(f'[warning]: field ip and domain both exist, domain ignored')

    def to_object(self):
        rv = {
            'rules': [r for k, v in self.rules.items()
                      for r in self._rule_to_dict(k[0], k[1], v)]
        }
        if self.master:
            rv['master'] = self.master
        return rv

    def to_v2_object(self):
        return {
            'domainStrategy': 'AsIs',
            'rules': [r for k, v in self.rules.items()
                      for r in self._rule_to_dict(k[0], k[1], v)]
        }

    @classmethod
    def from_object(cls, obj):
        return cls(rules=obj.get('rules'), master=obj.get('master'))

    @classmethod
    def _rule_to_dict(cls, tag_in, tag_out, matchers):
        rv = []
        ips, domains = [], []
        for m in matchers:
            if cls._is_ip_str(m):
                ips.append(m)
            else:
                domains.append(m)
        if ips:
            rv.append({
                'type': 'field',
                'ip': ips,
                'inboundTag': tag_in,
                'outboundTag': tag_out,
            })
        if domains:
            rv.append({
                'type': 'field',
                'domain': domains,
                'inboundTag': tag_in,
                'outboundTag': tag_out,
            })
        if not rv:
            rv.append({
                'type': 'field',
                'inboundTag': tag_in,
                'outboundTag': tag_out,
            })
        return rv

    @classmethod
    def _is_ip_str(cls, s):
        return cls._ip_re.match(s) or s.startswith('geoip:')


class Inbound(Serializable):
    tag: str
    protocol: str
    port: int

    def __init__(self, tag, protocol, port):
        assert protocol in ['socks']
        self.tag = tag
        self.protocol = protocol
        self.port = port

    def to_dict(self):
        return {
            "tag": self.tag,
            "protocol": self.protocol,
            "listen": "127.0.0.1",
            "port": self.port,
        }

    def to_object(self, tag=None):
        obj = self.to_dict()
        if tag:
            obj['tag'] = tag
        return obj

    @classmethod
    def from_object(cls, obj):
        return cls(obj['tag'], obj['protocol'], obj['port'])


class ConfigObjectManager(NamedSerializableManager):
    pass


class RoutingManager(ConfigObjectManager):

    def __init__(self):
        super().__init__(Routing)


class SubscriptionManager(ConfigObjectManager):

    def __init__(self):
        super().__init__(Subscription)
        self.add_url(config.name_builtin, config.url_builtin)

    def add_url(self, name, url):
        self._check_name(name, False)
        s = Subscription(url=url)
        super().add(name, s)

    def update(self, name):
        self._check_name(name, True)
        s: Subscription = self.get_by_name(name)
        s.update()

    def add(self, name, item: Subscription):
        if name == config.name_builtin:
            raise ValueError('builtin subscription cannot be overridden')
        super().add(name, item)

    def remove(self, name):
        if name == config.name_builtin:
            raise ValueError('builtin subscription cannot be removed')
        super().remove(name)

    def get_node(self, name: str):
        """get a node by node-select-string"""
        if ':' not in name:
            builtin_subscr: Subscription = self.get_by_name(config.name_builtin)
            for n in builtin_subscr.nodes:
                if n.tag == name:
                    return n
            return None
        else:
            subscr_name, idx = name.split(':', 1)
            idx = int(idx)
            subscr: Subscription = self.get_by_name(subscr_name)
            if subscr is None:
                return None
            return subscr.get_node_by_index(idx)

    @classmethod
    def from_object(cls, obj: Dict):
        items: Dict = obj['items']
        if config.name_builtin in items:
            saved = obj.pop(config.name_builtin)
            rv = super().from_object(obj)
            items[config.name_builtin] = saved
            return rv
        else:
            return super().from_object(obj)

    def to_object(self):
        rv = super().to_object()
        items = rv['items']
        if config.name_builtin in items:
            items.pop(config.name_builtin)
        return rv


class InboundManager(ConfigObjectManager):

    def __init__(self):
        super().__init__(Inbound)

    def add(self, name, item: Inbound):
        item.tag = name
        super().add(name, item)


class NodeManager:
    _sm: SubscriptionManager

    def __init__(self, sm: SubscriptionManager):
        self._sm = sm

    def get_node(self, name: str):
        """get a node by node-select-string"""
        if ':' not in name:
            return None
        subscr_name, idx = name.split(':', 1)
        idx = int(idx)
        subscr: Subscription = self._sm.get_by_name(subscr_name)
        if subscr is None:
            return None
        return subscr.get_node_by_index(idx)

    def get_all(self):
        pass


class DataManager(Serializable):
    file: str
    subscription_mgr: SubscriptionManager
    routing_mgr: RoutingManager
    inbound_mgr: InboundManager
    node_mgr: NodeManager

    def __init__(self, file=''):
        if not file:
            file = config.config_file
        self.file = file

        if os.path.exists(self.file):
            self.read_file(self.file)
        else:
            self.subscription_mgr = SubscriptionManager()
            self.routing_mgr = RoutingManager()
            self.inbound_mgr = InboundManager()
            self.save()
        self.node_mgr = NodeManager(self.subscription_mgr)

    def read_file(self, file):
        with open(file) as fp:
            obj = json.load(fp)
            self.read_object(obj)

    def read_object(self, obj):
        self.subscription_mgr = SubscriptionManager.from_object(obj['subscriptions'])
        self.routing_mgr = RoutingManager.from_object(obj['routings'])
        self.inbound_mgr = InboundManager.from_object(obj['inbounds'])

    def save(self, indent=True):
        assert self.file, 'no file bind'
        if indent:
            indent = 4
        with open(self.file, 'w') as fp:
            json.dump(self.to_object(), fp, indent=indent,
                      ensure_ascii=False)
            fp.write('\n')

    def to_object(self):
        return {
            'subscriptions': self.subscription_mgr.to_object(),
            'routings': self.routing_mgr.to_object(),
            'inbounds': self.inbound_mgr.to_object()
        }

    @classmethod
    def from_object(cls, obj):
        rv = cls()
        rv.read_object(obj)
        return rv
