import datetime
import select
import socket
import subprocess
import sys
import threading
import time
import getpass

import serial

from framework import error_handling as eh
from libs.external_modules import ssh_module, ssh, serial_module

class BackendError(Exception):
    def __init__(self, msg, status=-1):
        self.msg = msg
        self.status = status

class Backend(object):

    def __init__(self, codec='latin_1'):
        """
        Args:
            codec (str): codec used by the monitored system to answer.
        """
        self._started = False
        self.codec = codec
        self._sync_lock = threading.Lock()

    def start(self):
        with self._sync_lock:
            if not self._started:
                self._started = True
                self._start()

    def stop(self):
        with self._sync_lock:
            if self._started:
                self._started = False
                self._stop()

    def exec_command(self, cmd):
        with self._sync_lock:
            return self._exec_command(cmd)

    def read_output(self, chan_desc):
        """
        Args:
            chan_desc: object returned by :meth:`Backend.exec_command` that enables to gather
              output data

        Returns:
            bytes: data retrieved through the communication channel
        """
        raise NotImplementedError

    def _exec_command(self, cmd):
        """
        Args:
            cmd: command to execute through the communication channel

        Returns: list of file descriptors (e.g., stdout, stderr)
        """
        raise NotImplementedError

    def _start(self):
        pass

    def _stop(self):
        pass


class SSH_Backend(Backend):

    NO_PASSWORD = 10
    ASK_PASSWORD = 20

    @staticmethod
    def _create_pkey(pkey_path, pkey_password):
        if pkey_path is not None:
            if pkey_password == SSH_Backend.NO_PASSWORD:
                pkey_password = None
            elif pkey_password == SSH_Backend.ASK_PASSWORD:
                pkey_password = getpass.getpass()
            else:
                pass
            pkey = ssh.RSAKey.from_private_key_file(pkey_path, password=pkey_password)
        else:
            pkey = None

        return pkey


    """
    Backend to execute command through a serial line.
    """
    def __init__(self, target_addr='localhost', port=22, bind_address=None,
                 username=None, password=None, pkey_path=None, pkey_password=NO_PASSWORD,
                 proxy_jump_addr=None, proxy_jump_bind_addr=None, proxy_jump_port=None,
                 proxy_jump_username=None, proxy_jump_password=None,
                 proxy_jump_pkey_path=None, proxy_jump_pkey_password=NO_PASSWORD,
                 codec='latin-1',
                 timeout=None, get_pty=False):
        """
        Args:
            target_addr (str): IP of the SSH server.
            port (int): port of the SSH server.
            username (str): username to connect with.
            password (str): (optional) password related to the username.
            pkey_path (str): (optional) path of the private key (if no password provided).
            pkey_password: (optional)  if the private key is encrypted, this parameter
              can be either the password to decrypt it, or the special value `SSHTarget.ASK_PASSWORD` that will
              prompt the user for the password at the time of connection. If the private key is
              not encrypted, then this parameter should be set to `SSHTarget.NO_PASSWORD`
            proxy_jump_addr: If a proxy jump has to be done before reaching the target, this parameter
              should be provided with the proxy address to connect with.
            proxy_jump_bind_addr: internal address of the proxy to communication with the target.
            proxy_jump_port: port on which the SSH server of the proxy listen to.
            proxy_jump_username: username to use for the connection with the proxy.
            proxy_jump_password: (optional) password related to the username.
            proxy_jump_pkey_path: (optional) path to the private key related to the username.
            proxy_jump_pkey_password: (optional) if the private key is encrypted, this parameter
              can be either the password to decrypt it, or the special value `SSHTarget.ASK_PASSWORD` that will
              prompt the user for the password at the time of connection. If the private key is
              not encrypted, then this parameter should be set to `SSHTarget.NO_PASSWORD`.
            codec (str): codec used by the monitored system to answer.
            timeout (float): timeout on blocking read/write operations. None disables
               timeouts on socket operations
            get_pty (bool): Request a pseudo-terminal from the server. It implies that processes
              executed from this ssh session will be attached to the pty and will be killed
              once the session is closed. (Otherwise they could remain on the server.)
        """
        Backend.__init__(self, codec=codec)
        if not ssh_module:
            raise eh.UnavailablePythonModule('Python module for SSH is not available!')
        self.host = target_addr
        self.port = port
        self.bind_address = bind_address
        self.username = username

        assert password is None or pkey_path is None
        self.password = password
        self.pkey_path = pkey_path
        self.pkey_password = pkey_password

        assert proxy_jump_password is None or proxy_jump_pkey_path is None
        self.proxy_jump_addr = proxy_jump_addr
        self.proxy_jump_bind_addr = proxy_jump_bind_addr
        self.proxy_jump_port = proxy_jump_port
        self.proxy_jump_username = proxy_jump_username
        self.proxy_jump_password = proxy_jump_password
        self.proxy_jump_pkey_path = proxy_jump_pkey_path
        self.proxy_jump_pkey_password = proxy_jump_pkey_password

        self.timeout = timeout
        self.get_pty = get_pty
        self.client = None

    def _start(self):

        self.pkey = self._create_pkey(self.pkey_path, self.pkey_password)
        self.proxy_jump_pkey = self._create_pkey(self.proxy_jump_pkey_path, self.proxy_jump_pkey_password)

        if self.proxy_jump_addr is not None:
            jumpbox = ssh.SSHClient()
            jumpbox.set_missing_host_key_policy(ssh.AutoAddPolicy())
            jumpbox.connect(self.proxy_jump_addr, username=self.proxy_jump_username, pkey=self.proxy_jump_pkey)

            jumpbox_transport = jumpbox.get_transport()

            if self.proxy_jump_addr:
                src_addr = (self.proxy_jump_addr, self.proxy_jump_port)
                dest_addr = (self.host, self.port)
                sock = jumpbox_transport.open_channel("direct-tcpip", dest_addr, src_addr)
            else:
                sock = None

        elif self.bind_address:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.bind_address, 0))
            sock.connect((self.host, self.port))
        else:
            sock = None

        self.client = ssh.SSHClient()
        self.client.set_missing_host_key_policy(ssh.AutoAddPolicy())

        self.client.connect(hostname=self.host, port=self.port, username=self.username,
                            password=self.password, pkey=self.pkey, sock=sock)

    def _stop(self):
        self.client.close()

    def _exec_command(self, cmd):
        try:
            ssh_in, ssh_out, ssh_err = self.client.exec_command(cmd, timeout=self.timeout, get_pty=self.get_pty)
        except ssh.ssh_exception.SSHException:
            raise BackendError('SSH connection not active anymore. Need {} reset'.format(self.__class__.__name__),
                               status=-3)

        return ssh_out, ssh_err

    def read_output(self, chan_desc):
        ssh_out, ssh_err = chan_desc
        out_data = err_data = ''
        out_exception = err_exception = None

        try:
            out_data = self.read_stdout(chan_desc)
        except BackendError as err:
            out_exception = err

        try:
            err_data = self.read_stderr(chan_desc)
        except BackendError as err:
            err_exception = err

        if not out_data and not err_data:
            excp_msg = ''
            excp_status_code = 0
            if out_exception:
                excp_msg += 'stdout: ' + str(out_exception)
                excp_status_code += out_exception.status
            if err_exception:
                excp_msg += ' | ' if excp_msg else ''
                excp_msg += 'stderr: ' + str(err_exception)
                excp_status_code += err_exception.status

            raise BackendError(excp_msg, status=excp_status_code)

        elif out_data and err_data:
            output = out_data  + '\n' + err_data
        elif out_data:
            output = out_data
        else:
            output = err_data

        return output

    def read_stdout(self, chan_desc):
        return self._read_fd(chan_desc[0])

    def read_stderr(self, chan_desc):
        return self._read_fd(chan_desc[1])

    def _read_fd(self, fdesc):
        data = ''
        new_line = 'POISON'
        timeout = False

        try:
            while new_line:
                new_line = fdesc.readline()
                data += new_line
        except socket.timeout:
            timeout = True

        if not data:
            if timeout:
                raise BackendError('Read timeout', status=-1)
            else:
                raise BackendError('No more data to read', status=-2)

        return data

    def set_timeout(self, timeout):
        self.timeout = timeout

class Serial_Backend(Backend):
    """
    Backend to execute command through a serial line.
    """
    def __init__(self, serial_port, baudrate=115200, bytesize=8, parity='N', stopbits=1,
                 xonxoff=False, rtscts=False, dsrdtr=False,
                 username=None, password=None, slowness_factor=5,
                 cmd_notfound=b'command not found', codec='latin-1'):
        """
        Args:
            serial_port (str): path to the tty device file. (e.g., '/dev/ttyUSB0')
            baudrate (int): baud rate of the serial line.
            bytesize (int): number of data bits. (5, 6, 7, or 8)
            parity (str): parity checking. ('N', 'O, 'E', 'M', or 'S')
            stopbits (int): number of stop bits. (1, 1.5 or 2)
            xonxoff (bool): enable software flow control.
            rtscts (bool): enable hardware (RTS/CTS) flow control.
            dsrdtr (bool): enable hardware (DSR/DTR) flow control.
            username (str): username to connect with. If None, no authentication step will be attempted.
            password (str): password related to the username.
            slowness_factor (int): characterize the slowness of the monitored system. The scale goes from
              1 (fastest) to 10 (slowest). This factor is a base metric to compute the time to wait
              for the authentication step to terminate (if `username` and `password` parameter are provided)
              and other operations involving to wait for the monitored system.
            cmd_notfound (bytes): pattern used to detect if the command does not exist on the
              monitored system.
            codec (str): codec used to send/receive information through the serial line
        """
        Backend.__init__(self, codec=codec)
        if not serial_module:
            raise eh.UnavailablePythonModule('Python module for Serial is not available!')

        self.serial_port = serial_port
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits= stopbits
        self.xonxoff = xonxoff
        self.rtscts = rtscts
        self.dsrdtr = dsrdtr
        self.slowness_factor = slowness_factor
        self.cmd_notfound = cmd_notfound
        if sys.version_info[0] > 2:
            self.username = bytes(username, self.codec)
            self.password = bytes(password, self.codec)
        else:
            self.username = username
            self.password = password

        self.client = None

    def _start(self):
        self.ser = serial.Serial(self.serial_port, self.baudrate, bytesize=self.bytesize,
                                 parity=self.parity, stopbits=self.stopbits,
                                 xonxoff=self.xonxoff, dsrdtr=self.dsrdtr, rtscts=self.rtscts,
                                 timeout=self.slowness_factor*0.1)
        if self.username is not None:
            assert self.password is not None
            self.ser.flushInput()
            self.ser.write(self.username+b'\r\n')
            time.sleep(0.1)
            self.ser.readline() # we read login echo
            pass_prompt = self.ser.readline()
            retry = 0
            eot_sent = False
            while pass_prompt.lower().find(b'password') == -1:
                retry += 1
                if retry > 3 and eot_sent:
                    self.stop()
                    raise BackendError('Unable to establish a connection with the serial line.')
                elif retry > 3:
                    # we send an EOT if ever the console was not in its initial state
                    # (already logged, or with the password prompt, ...) when we first write on
                    # the serial line.
                    self.ser.write(b'\x04\r\n')
                    time.sleep(self.slowness_factor*0.8)
                    self.ser.flushInput()
                    self.ser.write(self.username+b'\r\n')
                    time.sleep(0.1)
                    self.ser.readline() # we consume the login echo
                    pass_prompt = self.ser.readline()
                    retry = 0
                    eot_sent = True
                else:
                    chunks = self._read_serial(duration=self.slowness_factor*0.2)
                    pass_prompt = b''.join(chunks)
            time.sleep(0.1)
            self.ser.write(self.password+b'\r\n')
            time.sleep(self.slowness_factor*0.7)

    def _stop(self):
        self.ser.write(b'\x04\r\n') # we send an EOT (Ctrl+D)
        self.ser.close()

    def _exec_command(self, cmd):
        if not self.ser.is_open:
            raise BackendError('Serial port not open')

        if sys.version_info[0] > 2:
            cmd = bytes(cmd, self.codec)
        cmd += b'\r\n'
        self.ser.flushInput()
        self.ser.write(cmd)
        time.sleep(0.1)
        return self.ser

    def read_output(self, chan_desc):
        chan_desc.readline() # we consume the 'writing echo' from the input
        try:
            result = self._read_serial(serial_chan=chan_desc, duration=self.slowness_factor * 0.8)
        except serial.SerialException:
            raise BackendError('Exception while reading serial line')
        else:
            # We have to remove the new prompt line at the end.
            # But in our testing environment, the two last entries had to be removed, namely
            # 'prompt_line \r\n' and 'prompt_line ' !?
            # print('\n*** DBG: ', result)
            result = result[:-2]
            ret = b''.join(result)
            if ret.find(self.cmd_notfound) != -1:
                raise BackendError('The command does not exist on the target_addr')
            else:
                return ret

    def _read_serial(self, serial_chan, duration):
        result = []
        t0 = datetime.datetime.now()
        delta = -1
        while delta < duration:
            now = datetime.datetime.now()
            delta = (now - t0).total_seconds()
            res = serial_chan.readline()
            if res == b'':
                break
            result.append(res)
        return result


class Shell_Backend(Backend):
    """
    Backend to execute shell commands locally
    """
    def __init__(self, timeout=None, codec='latin-1'):
        """
        Args:
            timeout (float): timeout in seconds for reading the result of the command
            codec (str): codec used by the monitored system to answer.
        """
        Backend.__init__(self, codec=codec)
        self._timeout = timeout
        self._app = None

    def _start(self):
        pass

    def _stop(self):
        pass

    def _exec_command(self, cmd):
        self._app = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ready_to_read, ready_to_write, in_error = \
            select.select([self._app.stdout, self._app.stderr], [], [], self._timeout)

        return ready_to_read, in_error

    def read_output(self, chan_desc):
        ready_to_read, in_error = chan_desc
        if in_error:
            # the command does not exist on the system
            raise BackendError('Issue with file descriptors')
        elif ready_to_read:
            if len(ready_to_read) == 2:
                err = ready_to_read[1].read()
                if err.strip():
                    raise BackendError('ERROR: {!s}'.format(ready_to_read[1].read()))
            if ready_to_read[0]:
                return ready_to_read[0].read()
            else:
                raise BackendError('BUG')
        else:
            return b''

