import datetime
import socket

from framework.target_helpers import Target, TargetError
from libs.external_modules import *
from framework.global_resources import *
import framework.error_handling as eh

class SSHTarget(Target):

    def __init__(self, host='localhost', port=12345, bind_address=None,
                 username=None, password=None, pkey_path=None,
                 targeted_command=None, file_parameter_path=None,
                 ref=None):
        """

        Args:
            host:
            port:
            bindaddress:
            username:
            password:
            pkey_path:
            targeted_command: If not None, it should be a format string taking one argument that will
              be automatically filled either with
              the data to be sent or with @file_parameter_path if it is not None (meaning the data
              have to be provided through a file).
            file_parameter_path: If data should be provided to the targeted command through a file,
              then this parameter should provide the remote path where the data to be sent will be
              first copied into. it will be provided as a parameter of @targeted_command.
            ref (str): Reference for the target. Used for description only.
        """
        Target.__init__(self)
        if not ssh_module:
            raise eh.UnavailablePythonModule('Python module for SSH is not available!')
        self.host = host
        self.port = port
        self.bind_address = bind_address
        self.username = username

        assert password is None or pkey_path is None
        self.password = password
        self.pkey = ssh.RSAKey.from_private_key_file(pkey_path) if pkey_path is not None else None

        self.file_paremeter_path = file_parameter_path
        if file_parameter_path:
            self.targeted_command = targeted_command.format(file_parameter_path)
        else:
            self.targeted_command = targeted_command
        self.tg_ref = ref

        self.client = None

    def start(self):
        self._fbk_received = False
        self._last_ack_date = None
        self.client = ssh.SSHClient()
        self.client.set_missing_host_key_policy(ssh.AutoAddPolicy())

        if self.bind_address:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.bind_address, 0))
            sock.connect((self.host, self.port))
        else:
            sock = None

        self.client.connect(hostname=self.host, port=self.port, username=self.username,
                            password=self.password, pkey=self.pkey, sock=sock)
        self.sftp = self.client.open_sftp() if self.file_paremeter_path else None

        return True

    def stop(self):
        self.client.close()
        if self.sftp is not None:
            self.sftp.close()
        return True

    def send_data(self, data, from_fmk=False):
        self._fbk_received = False
        if not self.targeted_command:
            cmd = data.to_str()
        elif self.file_paremeter_path:
            input_f = self.sftp.file(self.file_paremeter_path, mode='w', bufsize=-1)
            input_f.write(data.to_str())
            input_f.flush()
            cmd = self.targeted_command
        else:
            cmd = self.targeted_command.format(data.to_str())

        ssh_in, ssh_out, ssh_err = \
            self.client.exec_command(cmd)

        err = ssh_err.read()
        self._last_ack_date = datetime.datetime.now()
        self._fbk_received = True
        if err:
            # the command does not exist on the system
            self._logger.collect_feedback(content='The command does not exist on the system',
                                          status_code=-1)
        else:
            self._logger.collect_feedback(content=ssh_out.read(),
                                          status_code=0)

    def is_feedback_received(self): # useless currently as no-threaded send_data
        return self._fbk_received

    def get_last_target_ack_date(self):
        return self._last_ack_date

    def get_description(self):
        prefix = '{:s} | '.format(self.tg_ref) if self.tg_ref is not None else ''
        desc = '{:s}host:{:s},port:{:d},user:{:s}'.format(prefix, self.host,
                                                          self.port, self.username)
        if self.targeted_command:
            if self.file_paremeter_path:
                desc += " | cmd='{!s}'".format(self.targeted_command)
            else:
                desc += " | cmd='{!s}'".format(self.targeted_command)

        return desc

