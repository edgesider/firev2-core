import unittest
import shutil

import demo_data
from v2_config import Subscription
import config
import sub_srv

server_port = 8000
server_url = f'http://localhost:{server_port}'


def open_arena(name='arena'):
    shutil.copytree('test_config', name, dirs_exist_ok=True)
    config.auto_load()


def close_arena(name='arena'):
    shutil.rmtree(name)


class TestSubscription(unittest.TestCase):

    def setUp(self) -> None:
        sub_srv.start(mute=True)
        open_arena()

    def tearDown(self) -> None:
        sub_srv.stop()
        close_arena()

    def test_crt_url(self):
        s = Subscription(url=server_url)
        self.assertEqual(s.url, server_url)
        self.assertEqual(len(s.nodes), 3)
        self.assertEqual(s.nodes, [demo_data.get_demo_node(),
                                   demo_data.get_demo_node(),
                                   demo_data.get_demo_node()])
        self.assertEqual(s.to_dict(), {'nodes': [demo_data.get_demo_dict(),
                                                 demo_data.get_demo_dict(),
                                                 demo_data.get_demo_dict()],
                                       'url': server_url})

    def test_crt_error(self):
        exception = None
        try:
            Subscription()
        except ValueError as e:
            exception = e
        self.assertTrue(isinstance(exception, ValueError))

    def test_update(self):
        s = Subscription(url=server_url + '/count/increase')
        self.assertEqual(len(s.nodes), 1)
        s.update()
        self.assertEqual(len(s.nodes), 2)
        s.update()
        self.assertEqual(len(s.nodes), 3)


if __name__ == '__main__':
    unittest.main()
