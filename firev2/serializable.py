import json
from abc import ABC
from typing import List, Dict, Union, Type

SerializableType = Union[List, Dict, int, str, float]


class Serializable(ABC):

    @classmethod
    def from_object(cls, obj: SerializableType):
        raise NotImplementedError

    def to_object(self):
        raise NotImplementedError


class NamedSerializableManager(Serializable):
    _items: Dict[str, Serializable]
    _attrs: Dict[str, str]
    _cls: Type[Serializable]
    file: str

    def __init__(self, cls: Type[Serializable]):
        self._items = {}
        self._attrs = {}
        self.file = ''
        self.bind_class(cls)

    def bind_class(self, cls: Type[Serializable]):
        self._cls = cls
        self._cls_name = str(cls)

    def read_file(self, file):
        self.file = file
        with open(file) as fp:
            self.read_items(json.load(fp))

    def save(self, indent=False):
        assert self.file, 'no file bind'
        if indent:
            indent = 4
        with open(self.file, 'w') as fp:
            json.dump(self.to_object(), fp, indent=indent)
            fp.write('\n')

    def read_items(self, obj):
        obj: Dict[str, dict]
        for name, d in obj.items():
            self.add(name, self._cls.from_object(d))

    def add(self, name, item: Union[SerializableType, Serializable]):
        self._check_name(name, False)
        if not isinstance(item, Serializable):
            item = self._cls.from_object(item)
        self._items[name] = item

    def remove(self, name):
        self._check_name(name, True)
        self._items.pop(name)

    def set_attr(self, key, value):
        self._attrs[key] = value

    def get_attr(self, key):
        return self._attrs[key]

    def clear_attr(self, key):
        self._attrs.pop(key)

    def get_by_name(self, name):
        return self._items.get(name)

    def get_all(self):
        return {n: r for n, r in self._items.items()}

    @property
    def count(self):
        return len(self._items)

    def _check_name(self, name, should_exist: bool):
        if should_exist:
            hint = f'item named "{name}" not exist'
        else:
            hint = f'item named "{name}" existed'
        assert (self.get_by_name(name) is not None) == should_exist, \
            hint

    def to_object(self):
        return {
            'attrs': {k: v for k, v in self._attrs.items()},
            'items': {n: i.to_object() for n, i in self._items.items()}
        }

    # noinspection PyArgumentList
    @classmethod
    def from_object(cls, obj: Dict[str, Serializable]):
        rv = cls()  # assume sub-class has default constructor
        rv.read_items(obj.get('items', {}))
        for k, v in rv._attrs.items():
            rv.set_attr(k, v)
        return rv
