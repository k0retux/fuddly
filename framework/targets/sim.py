################################################################################
#
#  Copyright 2014-2016 Eric Lacombe <eric.lacombe@security-labs.org>
#
################################################################################
#
#  This file is part of fuddly.
#
#  fuddly is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  fuddly is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with fuddly. If not, see <http://www.gnu.org/licenses/>
#
################################################################################

import binascii
import datetime
import struct
import sys
import time

import serial

from framework.node import Node, NodeSemanticsCriteria
from framework.target_helpers import Target
from framework.value_types import GSMPhoneNum
from libs.external_modules import serial_module, Color


class SIMTarget(Target):
    delay_between_write = 0.1  # without, it seems some commands can be lost

    _feedback_mode = Target.FBK_WAIT_FULL_TIME
    supported_feedback_mode = [Target.FBK_WAIT_FULL_TIME]

    def __init__(self, serial_port, baudrate, pin_code, targeted_tel_num, codec='latin_1'):
        Target.__init__(self)
        self.serial_port = serial_port
        self.baudrate = baudrate
        self.tel_num = targeted_tel_num
        self.pin_code = pin_code
        self.codec = codec
        self.pin_code = bytes(self.pin_code, self.codec)
        self.set_feedback_timeout(2)

    def start(self):

        if not serial_module:
            print('/!\\ ERROR /!\\: the PhoneTarget has been disabled because '
                  'python-serial module is not installed')
            return False

        self.ser = serial.Serial(self.serial_port, self.baudrate, timeout=2,
                                 dsrdtr=True, rtscts=True)

        self.ser.write(b"ATE1\r\n") # echo ON
        time.sleep(self.delay_between_write)
        self.ser.write(b"AT+CMEE=1\r\n") # enable extended error reports
        time.sleep(self.delay_between_write)
        self.ser.write(b"AT+CPIN?\r\n") # need to unlock?
        cpin_fbk = self._retrieve_feedback_from_serial(timeout=0)
        if cpin_fbk.find(b'SIM PIN') != -1:
            # Note that if SIM is already unlocked modem will answer CME ERROR: 3
            # if we try to unlock it again.
            # So we need to unlock only when it is needed.
            # If modem is unlocked the answer will be: CPIN: READY
            # otherwise it will be: CPIN: SIM PIN.
            self.ser.write(b"AT+CPIN="+self.pin_code+b"\r\n") # enter pin code
        time.sleep(self.delay_between_write)
        self.ser.write(b"AT+CMGF=0\r\n") # PDU mode
        time.sleep(self.delay_between_write)
        self.ser.write(b"AT+CSMS=0\r\n") # check if modem can process SMS
        time.sleep(self.delay_between_write)

        fbk = self._retrieve_feedback_from_serial(timeout=1)
        code = 0 if fbk.find(b'ERROR') == -1 else -1
        self._logger.collect_feedback(fbk, status_code=code)
        if code < 0:
            self._logger.print_console(cpin_fbk+fbk, rgb=Color.ERROR)

        return False if code < 0 else True

    def stop(self):
        self.ser.close()

    def _retrieve_feedback_from_serial(self, timeout=None):
        feedback = b''
        t0 = datetime.datetime.now()
        duration = -1
        timeout = self.feedback_timeout if timeout is None else timeout
        while duration < timeout:
            now = datetime.datetime.now()
            duration = (now - t0).total_seconds()
            time.sleep(0.1)
            fbk = self.ser.readline()
            if fbk.strip():
                feedback += fbk

        return feedback

    def send_data(self, data, from_fmk=False):
        if isinstance(data.content, Node):
            node_list = data.content[NodeSemanticsCriteria(mandatory_criteria=['tel num'])]
            if node_list and len(node_list)==1:
                node_list[0].set_values(value_type=GSMPhoneNum(values=[self.tel_num]))
            else:
                print('\nWARNING: Data does not contain a mobile number.')
        pdu = b''
        raw_data = data.to_bytes()
        pdu_sz = len(raw_data)
        for c in raw_data:
            pdu += binascii.b2a_hex(struct.pack('B', c))
        pdu = pdu.upper()

        pdu = b'00' + pdu + b"\x1a\r\n"
        at_cmd = "AT+CMGS={:d}\r\n".format(pdu_sz-1).encode()
        self.ser.write(at_cmd) # used for PDU mode
        time.sleep(self.delay_between_write)
        self.ser.write(pdu)

        fbk = self._retrieve_feedback_from_serial()
        code = 0 if fbk.find(b'ERROR') == -1 else -1
        self._logger.collect_feedback(fbk, status_code=code)