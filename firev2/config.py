import os
import subprocess

config_file = None

user = os.environ.get('SUDO_USER')
if user is None:
    home = os.environ['HOME']
else:
    # running as sudo
    home = subprocess.Popen(
        'getent passwd {} | cut -d: -f6'.format(user),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        shell=True).communicate()[0].decode('utf8').strip()
find_path = [
    'firev2.json',
    os.path.join(home, '.config', 'firev2.json'),
    '/etc/firev2.json',
]


def auto_load():
    global config_file
    for f in find_path:
        if os.path.isfile(f):
            config_file = f
    if not config_file:
        config_file = find_path[0]


url_builtin = '__builtin__'
name_builtin = '__builtin__'
tag_direct = 'direct'
tag_blocked = 'blocked'
