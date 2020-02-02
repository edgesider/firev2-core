import fcntl
import io
import json
import os
import select
import signal
import socket
import subprocess
import sys
import logging
from io import FileIO
from multiprocessing import Process
from typing import IO, Dict, List, Tuple, Optional


class V2rayManager:
    _v2_log_file: List[Optional[FileIO]]

    def __init__(self):
        self._v2_log_file = [None, None]

    def start(self, config: Dict):
        m = Monitor(config=config)
        m.start()

    def stop(self):
        """stop running monitor"""
        for fp in self._v2_log_file:
            if fp:
                fp.close()
        Monitor.kill_running()

    def restart(self):
        for fp in self._v2_log_file:
            if fp:
                fp.close()
        Monitor.restart_running()

    def get_access_log_file(self) -> FileIO:
        assert self.is_running(), 'no monitor running'
        f = self._v2_log_file[0]
        if not f:
            acc_fname = Monitor.get_v2_access_log_filename()
            acc = socket.socket(family=socket.AF_UNIX)
            acc.connect(acc_fname)
            f = io.FileIO(acc.fileno(), mode='r')
            f._sock = acc  # avoid gc
            # f = acc.makefile()
            self._v2_log_file[0] = f
        return f

    def get_error_log_file(self) -> FileIO:
        assert self.is_running(), 'no monitor running'
        f = self._v2_log_file[1]
        if not f:
            err_fname = Monitor.get_v2_error_log_filename()
            err = socket.socket(family=socket.AF_UNIX)
            err.connect(err_fname)
            f = io.FileIO(err.fileno(), mode='r')
            f._sock = err  # avoid gc
            self._v2_log_file[1] = f
        return f

    @staticmethod
    def is_running() -> bool:
        return Monitor.is_running()


class Monitor(Process):
    """Daemon for v2ray process
        1. We need to intercept v2ray's log, so we make v2ray always
           write logs to pipes and redirect them to the location needed;
        2. We need to send the logs to the manage process, so we should
           provide a way for it to get these log. The solution is
           listening on some unix domain sockets and write logs to
           the sockets connecting to them;
    """
    _logger: Optional[logging.Logger]
    _config: dict
    _v2: Optional[subprocess.Popen]
    _v2_access_log_reader: Optional[IO]
    _v2_error_log_reader: Optional[IO]
    _v2_config_filename: str
    _sock_access_fname: str
    _sock_error_fname: str
    _sock_access: Optional[socket.socket]
    _sock_error: Optional[socket.socket]
    _redirect_access_files: List[IO]
    _redirect_error_files: List[IO]
    _redirect_data_to_write: Dict[IO, bytes]

    def __init__(self, config: dict):
        super().__init__()
        self._logger = None
        self._config = config
        self._v2 = None
        self._v2_access_log_reader = None
        self._v2_error_log_reader = None
        self._v2_config_filename = ''

        self._sock_access_fname = self.get_v2_access_log_filename()
        self._sock_error_fname = self.get_v2_error_log_filename()
        self._sock_access = None
        self._sock_error = None

        self._redirect_access_files = []
        self._redirect_error_files = []
        self._redirect_data_to_write = {}

        self._should_exit = False
        self._child_exited = False
        self._should_restart = False

        if not os.path.exists(self._get_work_dir()):
            os.mkdir(self._get_work_dir())

    def run(self):
        assert not self.is_running(), 'another monitor is already running'
        try:
            self._run()
        finally:
            if self._v2:
                try:
                    self._release_v2_resources()
                except Exception:
                    pass
            # remove pid file and socket files if any exception occurred
            for f in [self.get_pid_filename(),
                      self._sock_access_fname,
                      self._sock_error_fname,
                      self._v2_config_filename]:
                if os.path.exists(f):
                    os.remove(f)

    def _run(self):
        self._create_logger()
        self._daemonize()
        """
        Steps:
        1. Write pid file
        2. Open unix domain sockets
        3. Install handlers for SIGCHLD and SIGTERM
        4. Start v2ray
        5. Poll file descriptors
        """
        self._write_pid_file()
        self._listen_log_sockets()
        self._install_signal_handler()
        self._open_v2_log_files()
        while True:
            self._start_v2ray()
            self._poll()
            # if self._poll returns, it means we need to restart v2ray
            self._release_v2_resources()
            for file, d in self._redirect_data_to_write.items():
                self._redirect_data_to_write[file] += b'[monitor] v2ray restarting...\n'

    def _release_v2_resources(self):
        prev = signal.signal(signal.SIGCHLD, signal.SIG_BLOCK)
        self._v2.terminate()
        self._wait_v2()
        self._v2_access_log_reader = None
        self._v2_error_log_reader = None
        signal.signal(signal.SIGCHLD, prev)

    def _create_logger(self, level=logging.INFO):
        self._logger = logging.getLogger('Firev2-Monitor')
        self._logger.setLevel(level)
        handler = logging.FileHandler(self.get_log_filename())
        handler.setFormatter(logging.Formatter(
            '[%(asctime)s - PID %(process)d - %(levelname)s]: %(message)s'))
        self._logger_fd = handler.stream.fileno()
        self._logger.addHandler(handler)

    def _daemonize(self):
        self._logger.info('daemonizing')
        import sys
        if os.fork() != 0:
            sys.exit()
        os.setsid()
        if os.fork() != 0:
            sys.exit()
        os.umask(0)
        os.chdir('/')
        # TODO
        fd_max = os.sysconf(os.sysconf_names['SC_OPEN_MAX'])
        # print(fd_max)
        fd_max = 1024
        for fd in range(0, fd_max):
            close = True
            if fd == self._logger_fd:
                close = False
            if close:
                try:
                    os.close(fd)
                except OSError:
                    pass
        fp = open('/dev/null')
        for fd in range(0, 3):
            os.dup2(fp.fileno(), fd)
        sys.stdin = sys.stdout = sys.stderr = fp

    def _write_pid_file(self):
        self._logger.debug('writing pid file')
        with open(self.get_pid_filename(), 'w') as fp:
            fp.write(f'{os.getpid()}\n')
        self._logger.debug('pid file written')

    def _listen_log_sockets(self):
        self._logger.debug('creating unix domain sockets')
        if os.path.exists(self._sock_access_fname):
            os.unlink(self._sock_access_fname)
        if os.path.exists(self._sock_error_fname):
            os.unlink(self._sock_error_fname)
        self._sock_access = socket.socket(family=socket.AF_UNIX)
        self._sock_error = socket.socket(family=socket.AF_UNIX)
        self._sock_access.bind(self._sock_access_fname)
        self._sock_error.bind(self._sock_error_fname)
        self._sock_access.listen(100)
        self._sock_error.listen(100)
        self._logger.debug('unix domain sockets created')

    def _install_signal_handler(self):
        def handler(signum, frame):
            if signum == signal.SIGCHLD:
                self._child_exited = True
            elif signum == signal.SIGTERM:
                self._should_exit = True
                raise InterruptedError
            elif signum == signal.SIGHUP:
                self._should_restart = True
                raise InterruptedError

        self._logger.debug('installing signal handlers')
        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGCHLD, handler)
        signal.signal(signal.SIGHUP, handler)
        signal.siginterrupt(signal.SIGTERM, True)
        signal.siginterrupt(signal.SIGHUP, True)
        self._logger.debug('signal handlers installed')

    def _open_v2_log_files(self):
        config = self._config
        log_config: dict = config.get('log')
        if log_config is not None:
            if log_config.get('access') is not None:
                f = open(log_config.pop('access'), 'a+b')
                self._add_redirect_file(access_file=f)
            if log_config.get('error') is not None:
                f = open(log_config.pop('error'), 'a+b')
                self._add_redirect_file(error_file=f)
        else:
            config['log'] = {}

        # TODO use pipe
        config['log']['access'] = '/dev/fd/1'
        config['log']['error'] = '/dev/fd/2'
        self._config = config

    def _start_v2ray(self):
        self._logger.info('starting v2ray')
        self._v2_config_filename = self._get_work_dir() + '/v2ray_config.json'
        with open(self._v2_config_filename, 'w') as fp:
            json.dump(self._config, fp, indent=4, ensure_ascii=False)
        self._v2 = subprocess.Popen(['v2ray', '-config',
                                     self._get_work_dir() + '/v2ray_config.json'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    close_fds=True)
        self._v2_access_log_reader = self._v2.stdout
        self._v2_error_log_reader = self._v2.stderr
        self._logger.info('v2ray started')

    def _poll(self):
        while True:
            rfd = [self._v2_access_log_reader, self._v2_error_log_reader,
                   self._sock_access, self._sock_error]
            wfd = [f for f, d in self._redirect_data_to_write.items() if d]
            try:
                rfd, wfd, xfd = select.select(rfd, wfd, [])
            except InterruptedError:
                if self._should_exit:
                    self._logger.warning('SIGTERM received. exiting...')
                    signal.signal(signal.SIGCHLD, signal.SIG_BLOCK)
                    self._v2.kill()
                    self._wait_v2()
                    sys.exit(-1)
                elif self._should_restart:
                    self._logger.warning('SIGHUP received. restarting...')
                    self._should_restart = False
                    return
            if self._child_exited:
                self._logger.error('v2ray terminated unexpectedly. exiting...')
                self._wait_v2()
                sys.exit(-1)
            self._dispatch_fd(rfd, wfd)

    def _wait_v2(self):
        self._v2.wait()
        acc, err = self._v2.communicate()
        self._add_redirect_data(acc, err)
        self._flush_all_redirect_log()

    def _dispatch_fd(self, rfds: List[IO], wfds: List[IO]):
        self._logger.info('start to redirect logs')
        for fd in rfds:
            if fd == self._v2_access_log_reader:
                data = self._v2_access_log_reader.read1()
                self._add_redirect_data(access_data=data)
            elif fd == self._v2_error_log_reader:
                data = self._v2_error_log_reader.read1()
                self._add_redirect_data(error_data=data)
            elif fd == self._sock_access:
                peer, _ = self._sock_access.accept()
                peer.setblocking(False)
                fp = peer.makefile(mode='wb')
                self._add_redirect_file(access_file=fp)
            elif fd == self._sock_error:
                peer, _ = self._sock_error.accept()
                peer.setblocking(False)
                fp = peer.makefile(mode='wb')
                self._add_redirect_file(error_file=fp)

        for fd in wfds:
            if fd in self._redirect_data_to_write:
                self._flush_redirect_log(fd)

    def _add_redirect_file(self, access_file=None, error_file=None):
        if access_file:
            self._redirect_access_files.append(access_file)
            self._redirect_data_to_write[access_file] = b''
            self._logger.info('new access log redirection added')
        if error_file:
            self._redirect_error_files.append(error_file)
            self._redirect_data_to_write[error_file] = b''
            self._logger.info('new error log redirection added')

    def _remove_redirect_file(self, file):
        self._redirect_data_to_write[file] = b''
        self._redirect_data_to_write.pop(file)
        if file in self._redirect_access_files:
            self._redirect_access_files.remove(file)
        else:
            self._redirect_error_files.remove(file)

    def _add_redirect_data(self, access_data=None, error_data=None):
        if access_data:
            for f in self._redirect_access_files:
                self._redirect_data_to_write[f] += access_data
        if error_data:
            for f in self._redirect_error_files:
                self._redirect_data_to_write[f] += error_data

    def _flush_all_redirect_log(self):
        for fd in list(self._redirect_data_to_write.keys()):
            self._flush_redirect_log(fd)

    def _flush_redirect_log(self, fd):
        to_write = self._redirect_data_to_write[fd]
        while to_write:
            try:
                written_len = fd.write(to_write)
                fd.flush()
            except BlockingIOError:
                # would block
                break
            except BrokenPipeError:
                self._remove_redirect_file(fd)
                break
            to_write = to_write[written_len:]
            self._redirect_data_to_write[fd] = to_write

    @classmethod
    def _get_work_dir(cls):
        return f'/run/user/{cls._get_uid()}/firev2/'

    @staticmethod
    def _get_uid():
        uid = os.environ.get('SUDO_UID')
        if uid is None:
            uid = os.getuid()
        return int(uid)

    @classmethod
    def get_pid_filename(cls):
        return f'{cls._get_work_dir()}/monitor.pid'

    @classmethod
    def get_log_filename(cls):
        return f'{cls._get_work_dir()}/monitor.log'

    @classmethod
    def get_v2_access_log_filename(cls):
        return f'{cls._get_work_dir()}/v2ray_access.sock'

    @classmethod
    def get_v2_error_log_filename(cls):
        return f'{cls._get_work_dir()}/v2ray_error.sock'

    @classmethod
    def is_running(cls):
        return cls.get_running_pid() is not None

    @classmethod
    def get_running_pid(cls):
        pidfile = cls.get_pid_filename()
        if os.path.isfile(pidfile):
            with open(pidfile) as f:
                try:
                    pid = int(f.read().strip())
                except ValueError:
                    os.remove(pidfile)
                    return None
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return None
            return pid
        else:
            return None

    @classmethod
    def kill_running(cls):
        pid = cls.get_running_pid()
        assert pid is not None, 'monitor is not running'
        os.kill(pid, signal.SIGTERM)

    @classmethod
    def restart_running(cls):
        pid = cls.get_running_pid()
        assert pid is not None, 'monitor is not running'
        os.kill(pid, signal.SIGHUP)


if __name__ == '__main__':
    V2rayManager().start({
        'log': {
            'access': '/run/user/1000/firev2/test_access.json',
            'error': '/run/user/1000/firev2/test_error.json',
            'logLevel': 'debug'
        }
    })
    # V2rayManager().start({})
