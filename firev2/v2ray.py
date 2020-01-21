import fcntl
import io
import json
import os
import select
import signal
import socket
import subprocess
import sys
from io import FileIO
from multiprocessing import Process
from typing import IO, Dict, List, Tuple, Optional


class V2rayManager:
    _v2_log_file: List[Optional[FileIO]]

    def __init__(self):
        self._v2_log_file = [None, None]

    def start(self, config: Dict):
        m = Monitor(config=config)
        self._v2_log_file = list(m.create_v2_log_pipe())
        m.start()

    def stop(self):
        """stop running monitor
        Note:
        """
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
        TODO add log
    """
    _config: dict
    _v2: Optional[subprocess.Popen]
    _v2_access_log_reader: Optional[IO]
    _v2_error_log_reader: Optional[IO]
    _v2_config_filename: str
    _parent_log_pipe: Tuple[Tuple[Optional[FileIO], Optional[FileIO]],
                            Tuple[Optional[FileIO], Optional[FileIO]]]
    _sock_access_fname: str
    _sock_error_fname: str
    _sock_access: Optional[socket.socket]
    _sock_error: Optional[socket.socket]
    _redirect_access_files: List[IO]
    _redirect_error_files: List[IO]
    _data_to_write: Dict[IO, bytes]

    def __init__(self, config: dict):
        super().__init__()
        self._config = config
        self._v2 = None
        self._v2_access_log_reader = None
        self._v2_error_log_reader = None
        self._v2_config_filename = ''
        self._parent_log_pipe = ((None, None), (None, None))

        self._sock_access_fname = self.get_v2_access_log_filename()
        self._sock_error_fname = self.get_v2_error_log_filename()
        self._sock_access = None
        self._sock_error = None

        self._redirect_access_files = []
        self._redirect_error_files = []
        self._data_to_write = {}

        self._should_exit = False
        self._child_exited = False
        self._should_restart = False

        self._sync_pipe = os.pipe()

        if not os.path.exists(self._get_work_dir()):
            os.mkdir(self._get_work_dir())

    def start(self):
        super().start()
        # after sub-process started, we need close the pipe in parent.
        os.close(self._sync_pipe[1])
        for fp in self._parent_log_pipe[1]:
            fp.close()
        d = os.read(self._sync_pipe[0], 1)
        assert d == b'@', 'monitor start failed'
        os.close(self._sync_pipe[0])

    def run(self):
        assert not self.is_running(), 'another monitor is already running'
        self._logfile_as_stdout_err()
        self._daemonize()
        try:
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
            assert os.write(self._sync_pipe[1], b'@') == 1, 'monitor start failed'
            self._open_v2_log_files()
            while True:
                self._start_v2ray()
                self._poll()
                # if self._poll returns, it means we need to restart v2ray
                self.release_v2_resources()
                for file, d in self._data_to_write.items():
                    self._data_to_write[file] += b'v2ray restarting...\n'
        finally:
            try:
                self._v2.kill()
            except Exception:
                pass
            # remove pid file and socket files if any exception occurred
            for f in [self.get_pid_filename(),
                      self._sock_access_fname,
                      self._sock_error_fname,
                      self._v2_config_filename]:
                if os.path.exists(f):
                    os.remove(f)

    def release_v2_resources(self):
        prev = signal.signal(signal.SIGCHLD, signal.SIG_BLOCK)
        self._v2.terminate()
        self._v2.wait()
        self._v2_access_log_reader.close()
        self._v2_error_log_reader.close()
        self._v2_access_log_reader = None
        self._v2_error_log_reader = None
        signal.signal(signal.SIGCHLD, prev)

    def _daemonize(self):
        print('daemonizing')
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
        print(fd_max)
        fd_max = 1024
        for fd in range(3, fd_max):
            close = True
            if fd == self._sync_pipe[1]:
                close = False

            for fp in self._parent_log_pipe[1]:
                if fp and fd == fp.fileno():
                    close = False
            if not close:
                continue
            try:
                os.close(fd)
            except OSError:
                pass
        os.close(0)
        sys.stdin = open('/dev/null')

    def _write_pid_file(self):
        with open(self.get_pid_filename(), 'w') as fp:
            fp.write(f'{os.getpid()}\n')

    def _listen_log_sockets(self):
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
        print('unix daemon sockets created')

    def _install_signal_handler(self):

        # step 3: install handlers for SIGHUP and SIGTERM
        def handler(signum, frame):
            if signum == signal.SIGCHLD:
                self._child_exited = True
            elif signum == signal.SIGTERM:
                self._should_exit = True
                raise InterruptedError
            elif signum == signal.SIGHUP:
                self._should_restart = True
                raise InterruptedError

        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGCHLD, handler)
        signal.signal(signal.SIGHUP, handler)
        signal.siginterrupt(signal.SIGTERM, True)
        signal.siginterrupt(signal.SIGHUP, True)

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
        self._v2_config_filename = self._get_work_dir() + '/v2ray_config.json'
        with open(self._v2_config_filename, 'w') as fp:
            json.dump(self._config, fp, indent=4, ensure_ascii=False)
        self._v2 = subprocess.Popen(['v2ray', '-config',
                                     self._get_work_dir() + '/v2ray_config.json'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    close_fds=True)
        self._v2_access_log_reader = self._v2.stdout
        self._v2_error_log_reader = self._v2.stderr
        print('v2ray started')

    def _poll(self):
        while True:
            rfd = [self._v2_access_log_reader, self._v2_error_log_reader,
                   self._sock_access, self._sock_error]
            wfd = [f for f, d in self._data_to_write.items() if d]
            try:
                rfd, wfd, xfd = select.select(rfd, wfd, [])
            except InterruptedError:
                if self._should_exit:
                    print('SIGTERM received. exiting...')
                    signal.signal(signal.SIGCHLD, signal.SIG_BLOCK)
                    self._v2.kill()
                    self._wait_v2()
                    sys.exit(-1)
                elif self._should_restart:
                    print('SIGHUP received. restarting...')
                    self._should_restart = False
                    return
            if self._child_exited:
                print('v2ray terminated unexpectedly. exiting...')
                self._wait_v2()
                sys.exit(-1)
            self._dispatch_fd(rfd, wfd)

    def _wait_v2(self):
        self._v2.wait()
        acc, err = self._v2.communicate()
        self._add_redirect_data(acc, err)
        self._flush_all_redirect_log()

    def _dispatch_fd(self, rfds: List[IO], wfds: List[IO]):
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
            if fd in self._data_to_write:
                self._flush_redirect_log(fd)

    def _add_redirect_file(self, access_file=None, error_file=None):
        if access_file:
            self._redirect_access_files.append(access_file)
            self._data_to_write[access_file] = b''
        if error_file:
            self._redirect_error_files.append(error_file)
            self._data_to_write[error_file] = b''

    def _remove_redirect_file(self, file):
        self._data_to_write[file] = b''
        self._data_to_write.pop(file)
        if file in self._redirect_access_files:
            self._redirect_access_files.remove(file)
        else:
            self._redirect_error_files.remove(file)

    def _add_redirect_data(self, access_data=None, error_data=None):
        if access_data:
            for f in self._redirect_access_files:
                self._data_to_write[f] += access_data
        if error_data:
            for f in self._redirect_error_files:
                self._data_to_write[f] += error_data

    def _flush_all_redirect_log(self):
        for fd in list(self._data_to_write.keys()):
            self._flush_redirect_log(fd)

    def _flush_redirect_log(self, fd):
        to_write = self._data_to_write[fd]
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
            self._data_to_write[fd] = to_write

    def _logfile_as_stdout_err(self):
        f = open(f'{self.get_log_filename()}', 'a')
        os.close(1)
        os.dup2(f.fileno(), 1)
        os.close(2)
        os.dup2(f.fileno(), 2)

    def create_v2_log_pipe(self) -> Tuple[FileIO, FileIO]:
        if any(self._parent_log_pipe[0]):
            assert all(self._parent_log_pipe[0])
            return self._parent_log_pipe[0]
        else:
            assert not self.is_alive(), 'v2ray already started'
            acc_fd = os.pipe()
            err_fd = os.pipe()
            fcntl.fcntl(acc_fd[1], fcntl.F_SETFL, os.O_NONBLOCK)
            fcntl.fcntl(err_fd[1], fcntl.F_SETFL, os.O_NONBLOCK)
            acc_read = io.FileIO(acc_fd[0], mode='r', closefd=True)
            acc_write = io.FileIO(acc_fd[1], mode='wb', closefd=True)
            err_read = io.FileIO(err_fd[0], mode='r', closefd=True)
            err_write = io.FileIO(err_fd[1], mode='wb', closefd=True)
            self._add_redirect_file(access_file=acc_write, error_file=err_write)
            self._parent_log_pipe = ((acc_read, err_read), (acc_write, err_write))
            return self._parent_log_pipe[0]

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
