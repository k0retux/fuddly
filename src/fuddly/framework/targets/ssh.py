import datetime
import socket
import time

from ..target_helpers import Target, TargetError
from ...libs.external_modules import *
from ..global_resources import *
from ..comm_backends import SSH_Backend, BackendError
from ..knowledge.feedback_collector import FeedbackCollector

from .. import error_handling as eh


class SSHTarget(Target):
    NO_PASSWORD = SSH_Backend.NO_PASSWORD
    ASK_PASSWORD = SSH_Backend.ASK_PASSWORD

    STATUS_THRESHOLD_FOR_RECOVERY = -2

    def __init__(
        self,
        target_addr="localhost",
        port=12345,
        bind_address=None,
        username=None,
        password=None,
        pkey_path=None,
        pkey_password=None,
        proxy_jump_addr=None,
        proxy_jump_bind_addr=None,
        proxy_jump_port=None,
        proxy_jump_username=None,
        proxy_jump_password=None,
        proxy_jump_pkey_path=None,
        proxy_jump_pkey_password=None,
        targeted_command=None,
        file_parameter_path=None,
        fbk_timeout=0.5,
        read_stdout=True,
        read_stderr=True,
        char_mapping=False,
        get_pty=False,
        ref=None,
    ):
        """
        This generic target enables you to interact with a remote target requiring an SSH connection.

        Args:
            target_addr: IP address to reach the SSH server
            port: port on which the SSH server listen to.
            bind_address: source address for communication.
            username: username to use for the connection.
            password: (optional) password related to the username. Could also be the special value
              `SSHTarget.ASK_PASSWORD` that will prompt the user for the password at the time of connection.
            pkey_path: (optional) path to the private key related to the username (if no password provided).
            pkey_password: (optional)  if the private key is encrypted, this parameter
              can be either the password to decrypt it, or the special value `SSHTarget.ASK_PASSWORD` that will
              prompt the user for the password at the time of connection. If the private key is
              not encrypted, then this parameter should be set to `SSHTarget.NO_PASSWORD`
            proxy_jump_addr: If a proxy jump has to be done before reaching the target, this parameter
              should be provided with the proxy address to connect with.
            proxy_jump_bind_addr: internal address of the proxy to communication with the target.
            proxy_jump_port: port on which the SSH server of the proxy listen to.
            proxy_jump_username: username to use for the connection with the proxy.
            proxy_jump_password: (optional) password related to the username. Could also be the special value
              `SSHTarget.ASK_PASSWORD` that will prompt the user for the password at the time of connection.
            proxy_jump_pkey_path: (optional) path to the private key related to the username.
            proxy_jump_pkey_password: (optional) if the private key is encrypted, this parameter
              can be either the password to decrypt it, or the special value `SSHTarget.ASK_PASSWORD` that will
              prompt the user for the password at the time of connection. If the private key is
              not encrypted, then this parameter should be set to `SSHTarget.NO_PASSWORD`.
            targeted_command: If not None, it should be a format string taking one argument that will
              be automatically filled either with
              the data to be sent or with @file_parameter_path if it is not None (meaning the data
              have to be provided through a file).
            file_parameter_path: If data should be provided to the targeted command through a file,
              then this parameter should provide the remote path where the data to be sent will be
              first copied into (otherwise it should remain equal to None).
              it will be provided as a parameter of @targeted_command.
            fbk_timeout: delay for the framework to wait before it requests feedback from us.
            read_stdout (bool): If `True`, collect as feedback what the executed command will write
              in stdout.
            read_stderr (bool): If `True`, collect as feedback what the executed command will write
              in stderr.
            char_mapping (dict): If provided, specific characters in the payload will be
              replaced based on it.
            get_pty (bool): Request a pseudo-terminal from the server.
            ref (str): Reference for the target. Used for description only.
        """
        Target.__init__(self)
        if not ssh_module:
            raise eh.UnavailablePythonModule("Python module for SSH is not available!")

        self.ssh_backend = SSH_Backend(
            target_addr=target_addr,
            port=port,
            bind_address=bind_address,
            username=username,
            password=password,
            pkey_path=pkey_path,
            pkey_password=pkey_password,
            proxy_jump_addr=proxy_jump_addr,
            proxy_jump_bind_addr=proxy_jump_bind_addr,
            proxy_jump_port=proxy_jump_port,
            proxy_jump_username=proxy_jump_username,
            proxy_jump_password=proxy_jump_password,
            proxy_jump_pkey_path=proxy_jump_pkey_path,
            proxy_jump_pkey_password=proxy_jump_pkey_password,
            get_pty=get_pty,
        )

        self.read_stdout = read_stdout
        self.read_stderr = read_stderr
        self.char_mapping = char_mapping
        self.file_paremeter_path = file_parameter_path
        if file_parameter_path:
            self.targeted_command = targeted_command.format(file_parameter_path)
        else:
            self.targeted_command = targeted_command
        self.tg_ref = ref
        self._fbk_collector = FeedbackCollector()
        self._set_feedback_timeout_specific(fbk_timeout)

    def start(self):
        self._fbk_received = False
        self._last_ack_date = None
        self.chan_desc = None

        self.ssh_backend.start()
        self.sftp = (
            self.ssh_backend.client.open_sftp() if self.file_paremeter_path else None
        )

        return True

    def stop(self):
        self.ssh_backend.stop()
        self.chan_desc = None
        if self.sftp is not None:
            self.sftp.close()

        return True

    def recover_target(self):
        self.stop()
        return self.start()

    def send_data(self, data, from_fmk=False):
        self._fbk_received = False
        data_str = data.to_str()
        if self.char_mapping:
            for old_c, new_c in self.char_mapping.items():
                data_str = data_str.replace(old_c, new_c)
        if not self.targeted_command:
            cmd = data_str
        elif self.file_paremeter_path:
            input_f = self.sftp.file(self.file_paremeter_path, mode="w", bufsize=-1)
            input_f.write(data_str)
            input_f.flush()
            cmd = self.targeted_command
        else:
            cmd = self.targeted_command.format(data_str)

        try:
            self.chan_desc = self.ssh_backend.exec_command(cmd)
            self._last_ack_date = datetime.datetime.now()
            self._fbk_received = True
        except BackendError as err:
            self._logger.collect_feedback(
                content="{}".format(err), status_code=err.status
            )
            return

        if self.read_stdout:
            try:
                data = self.ssh_backend.read_stdout(self.chan_desc)
                if data:
                    self._logger.collect_feedback(
                        content=data, status_code=0, subref="stdout"
                    )
            except BackendError as err:
                self._logger.collect_feedback(
                    content="{}".format(err), status_code=err.status, subref="stdout"
                )

        if self.read_stderr:
            try:
                data = self.ssh_backend.read_stderr(self.chan_desc)
                if data:
                    self._logger.collect_feedback(
                        content=data, status_code=0, subref="stderr"
                    )
            except BackendError as err:
                self._logger.collect_feedback(
                    content="{}".format(err), status_code=err.status, subref="stderr"
                )

    def is_feedback_received(self):  # useless currently as no-threaded send_data
        return self._fbk_received

    def _set_feedback_timeout_specific(self, fbk_timeout):
        self.feedback_timeout = fbk_timeout
        self.ssh_backend.set_timeout(fbk_timeout)

    def get_last_target_ack_date(self):
        return self._last_ack_date

    def get_description(self):
        prefix = "{:s} | ".format(self.tg_ref) if self.tg_ref is not None else ""
        desc = "{:s}host:{:s},port:{:d},user:{:s}".format(
            prefix,
            self.ssh_backend.host,
            self.ssh_backend.port,
            self.ssh_backend.username,
        )
        if self.ssh_backend.proxy_jump_addr:
            desc += f" | proxy_jump:{self.ssh_backend.proxy_jump_addr}"

        if self.targeted_command:
            desc += f" | cmd='{self.targeted_command}'"

        return desc
