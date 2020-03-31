################################################################################
#
#  Copyright 2018 Eric Lacombe <eric.lacombe@security-labs.org>
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

from enum import Enum

try:
    from enum import auto
except ImportError:
    __my_enum_auto_id = 1
    def auto():
        global __my_enum_auto_id
        i = __my_enum_auto_id
        __my_enum_auto_id += 1
        return i


class TrustLevel(Enum):
    Maximum = auto()
    Medium = auto()
    Minimum = auto()

class Info(Enum):
    def __init__(self, val):
        self._trust = {}

    def increase_trust(self, inc=1):
        if self.value not in self._trust:
            self._trust[self.value] = 0
        self._trust[self.value] += inc

    def decrease_trust(self, inc=1):
        if self.value not in self._trust:
            self._trust[self.value] = 0
        self._trust[self.value] -= inc

    def reset_trust(self):
        self._trust[self.value] = 0

    def __str__(self):
        name = self.__class__.__name__ + '.' + self.name
        return 'Info: {!s} [{!s} --> value: {:d}]'.format(
                name, self.trust_level, self.trust_value)

    @property
    def trust_value(self):
        return self._trust.get(self.value, 0)

    @property
    def trust_level(self):
        trust_values = self._trust.values()
        if not trust_values:
            return None
        trust_val = self.trust_value
        if trust_val >= max(trust_values):
            return TrustLevel.Maximum
        elif trust_val <= min(trust_values):
            return TrustLevel.Minimum
        else:
            return TrustLevel.Medium


class OS(Info):
    Linux = auto()
    Windows = auto()
    Android = auto()
    Unknown = auto()

class Hardware(Info):
    X86_64 = auto()
    X86_32 = auto()
    PowerPc = auto()
    ARM = auto()
    Unknown = auto()

class Language(Info):
    C = auto()
    Pascal = auto()
    Unknown = auto()

class InputHandling(Info):
    Ctrl_Char_Set = auto()
    Unknown = auto()


class InformationCollector(object):

    def __init__(self):
        self._collector = None
        self.reset_information()

    def add_information(self, info, initial_trust_value=0):
        assert info is not None
        if isinstance(info, Info):
            info = [info]

        try:
            for i in info:
                assert isinstance(i, Info)
                if i in self._collector:
                    i.increase_trust()
                else:
                    i.increase_trust(inc=initial_trust_value)
                    self._collector.add(i)
        except TypeError:
            raise
            # self._collector.add(info)

    def is_assumption_valid(self, info):
        return not self._collector or info in self._collector

    def is_info_class_represented(self, info_class):
        for info in self._collector:
            if isinstance(info, info_class):
                return True
        else:
            return False

    def reset_information(self):
        self._collector = set()

    def __str__(self):
        desc = ''
        for info in self._collector:
            desc += str(info) + '\n'

        return desc

    # for python2 compatibility
    def __nonzero__(self):
        return bool(self._collector)

    # for python3 compatibility
    def __bool__(self):
        return bool(self._collector)


if __name__ == "__main__":

    OS.Linux.increase_trust()
    OS.Linux.increase_trust()
    OS.Linux.show_trust()

    OS.Windows.show_trust()

