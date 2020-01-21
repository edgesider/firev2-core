#! /usr/bin/env python

from base64 import b64encode
from bottle import route, run
from random import randint

vstr = b'vmess://eyJhZGQiOiAiZ29vZ2xlLmNvbSIsICJpZCI6ICJBQkNERUZHSC1JSktMLU1OT1BRUlNUVS1WV1hZWjAxMjM0NTYiLCAicG9ydCI6IDgwMDAsICJhaWQiOiAxLCAicHMiOiAiZ29vZ2xlIiwgIm5ldCI6ICJ3cyIsICJ0bHMiOiAidGxzIiwgInR5cGUiOiAidXRwIn0='


def subscription_getter(count=3):
    return b64encode(b'\r\n'.join([vstr] * count))


@route('/')
def index():
    return subscription_getter()


@route('/count/<i>')
def count(i=None):
    i = int(i)
    return subscription_getter(count=i)


@route('/count/random')
def random():
    return subscription_getter(randint(0, 10))


increase_counter = 0


@route('/count/increase')
def count_increase():
    global increase_counter
    increase_counter += 1
    return subscription_getter(increase_counter)


@route('/count/increase/reset')
def count_increase_reset():
    global increase_counter
    increase_counter = 0


def _mute():
    import sys
    import os
    os.close(1)
    sys.stdout = open('/dev/null', 'w')
    os.close(2)
    sys.stderr = open('/dev/null', 'w')


server_process = None


def start(mute=False, port=8000):
    from multiprocessing import Process
    global server_process

    def _():
        if mute:
            _mute()
        run(port=port)

    server_process = Process(target=_)
    server_process.start()

    # wait for server ready
    import requests
    while True:
        try:
            requests.get(f'http://localhost:{port}')
        except requests.exceptions.ConnectionError:
            continue
        break


def stop():
    server_process.kill()
    server_process.join()


if __name__ == '__main__':
    run()
