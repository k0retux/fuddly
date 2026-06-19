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

import os
import re
import sys
import configparser

from collections.abc import Iterator
from fuddly.framework.global_resources import config_folder

verbose = False


class Default:
    def __init__(self):
        self.configs = {}

    # TODO when all known default configs have been updated, this can be removed
    __unindent = re.compile(r'^;;\s\s*', re.MULTILINE)

    def _unindent(self, multiline):
        return self.__unindent.sub('', multiline)

    def add(self, name, doc):
        self.configs[name] = self._unindent(doc)


default = Default()

default.add("FmkPlumbing", """
[global]
config_name = FmkPlumbing

[misc]
fuzz.delay = 0
fuzz.burst = 1
continuous_monitoring_mode = True

[misc.doc]
self: (default values used when the framework resets)
fuzz.delay: Default value (> 0) for fuzz_delay
fuzz.burst: Default value (>= 1) for fuzz_burst

[targets]
empty_tg.verbose = False

[targets.doc]
self: configuration related to targets
empty_tg.verbose: Enable verbose mode (if True) on the default EmptyTarget()

[terminal]
external_term = False
cmd = x-terminal-emulator -p tabtitle={title} -e {cmd}
hold_arg = --hold

[terminal.doc]
self: Configuration applicable to the external terminal
external_term: Use an external terminal
cmd: Command to call the terminal.
      It will be used as a python format string.
      {title} will be replaces by the terminal title,
      {hold} will be replaced with hold_arg if the terminal is to be kept open
      {cmd} is the command that will be executed in the terminal
hold_arg: Options to keep the terminal open after the commands exits

""")

default.add("FmkShell", """
[global]
config_name = FmkShell
prompt = >>

;;  [global.doc]
;;  prompt: Set the 'Fuddly Shell' prompt

[completion]
offline_doc = True
inline_doc = False
dmaker_short_desc = False

[completion.doc]
offline_doc: When set to True, documentation for Generators and Operators are
              are displayed (while being completed by the shell) on the external terminal
              if it is enabled (either via with the config parameter 'external_term' set
              to True in 'FmkPlumbing.ini', or by launching the fuddly shell with the
              option '--external-display').
              Besides, description of their parameters are also displayed on the external
              terminal while being completed by the shell.
inline_doc: When set to True, documentation for Generators and Operators are
             displayed inline, as well as description of their parameters when parameters
             are being completed by the shell.
dmaker_short_desc: When set to True, only a short description of data makers (Generators
                        and Operators) will be displayed. Otherwise, full documentation
                        including parameters will be displayed.

[config]
middle = 40
indent.width = 4
indent.level = 0

[config.doc]
self: Configuration applicable to the 'config' command
middle: Set the column where the helpers are defined.
indent.width: Set the indentation width used to display the helpers.
indent.level: Set the initial level of indentation width
                    used to display the helpers.

[send_loop]
aligned = False
aligned_options.batch_mode = False
aligned_options.hide_cursor = True
aligned_options.prompt_height = 3

[send_loop.doc]
self: Configuration applicable to the 'send_loop' command.

aligned: Enable aligned display while sending data payloads.
aligned_options.batch_mode: Enable fitting multiple payloads onscreen
                 (when using 'send_loop -1 <generator>').
aligned_options.hide_cursor: Attempt to reduce blinking by hiding cursor.
aligned_options.prompt_height: Estimation of prompt's height.

[send]
reset_dmakers = False

[send.doc]
self: Configuration applicable to the 'send' command and all derivatives
      (excluding the loop versions).

reset_dmakers: [OBSOLETE] When this property is False, the data makers (Generator and Operators) involved
  in the send* commands will keep their state, except if new parameters
  are provided to them. In this case, all the data makers in the command will be reset.
  When this property is set to True, the data makers involved in the send* commands will be
  systematically reset before being used.


""")

default.add("Database", """
[global]
config_name = Database

[async_data]
before_data_id = 5
after_data_id = 60

[async_data.doc]
self: Configuration applicable to ASYNC DATA.

before_data_id: an async_data (without any associated data_id) will be considered to be related
  to a data sent afterwards if the number of seconds that separates it from that data is less
  than the amount specified in this parameter.
after_data_id: if after the last registered data by the framework, an async data is sent after
  more than the amount of seconds specified in this parameter, it won't be considered to be
  related to this last registered data.

""")


def update_config(from_whom, old_config):
    error_msg = (f"\n[WARNING] Old version detected for '{old_config.config_name}.ini' (renamed)."
                 f" New version is about to be installed.\n")
    current_fn = os.path.join(config_folder, old_config.config_name + ".ini")
    new_fn = current_fn + '_old'
    os.rename(current_fn, new_fn)
    new_config = config(from_whom, path=[config_folder])
    with open(current_fn, "w") as cfile:
        new_config.write(cfile)
    return new_config, error_msg


def check_type(name: str, value: str):
    booleans = ["True", "False"]
    try:
        base = {
            "0b": 2,
            "0o": 8,
            "0x": 16,
        }[value[0:2]]
    except KeyError:
        base = 10

    # booleans
    if value in booleans:
        return value == "True"

    # integers
    try:
        return int(value, base=base)
    except BaseException:
        pass

    # floats
    try:
        return float(value)
    except BaseException:
        pass

    return value


class SectionProxyWrapper(configparser.SectionProxy):
    def __getattr__(self, key: str):
        # Just ignore all private attributes, that's the easiest
        if key.startswith("_"):
            return configparser.SectionProxy.__getattribute__(self, key)
        try:
            return self.__getitem__(key)
        except KeyError:
            return configparser.SectionProxy.__getattribute__(self, key)

    def __getitem__(self, key: str) -> object:
        return check_type(key, configparser.SectionProxy.__getitem__(self, key))

    def __setattr__(self, key: str, val: object):
        return self.__setitem__(key, val)

    def __setitem__(self, key: str, val: object):
        self.parser._config_changed = True
        return configparser.SectionProxy.__setitem__(self, key, str(val))

    def fmt_option(self, name, level=0, indent=4, middle=40) -> str:
        "Format the output for printing the docs of this section/option"
        if self.name.endswith(".doc"):
            return ""
        tab = " " * indent * level  # Level should either 0 or 1
        val = self[name]
        line_start = f"{tab}{name}: {val}"
        description = ""
        try:
            description = f"{self.parser[self.name + ".doc"][name]}".replace("\n", "\n" + " " * middle)
        except Exception:
            # Ignore missing docs
            pass
        pad = " " * (middle-(len(line_start)))
        return line_start + pad + description + "\n"

    def help(self, option: str | None, level=0, indent=4, middle=40) -> str:
        "Show help for this specific section, or an options in it"
        try:
            # Need to go through the parser to get the doc for the section
            doc_section = self.parser[self.name + ".doc"]
        except KeyError:
            return ""
        if option is not None:
            if option in self:
                return self.fmt_option(option, 0, indent, middle)
            else:
                # Sub options handling
                sub_opts = list(filter(lambda o: o.startswith(option + "."), doc_section))
                if len(sub_opts) == 0:
                    return f"{option}: <undefined>\n"

                msg = f"{option}: (subkey)\n"
                level = 1
                for o in sub_opts:
                    if o == "self":
                        continue
                    msg += self.fmt_option(o, level, indent, middle)
                return msg

        msg = ''
        # If in the global section, don't show the section name, and don't indent
        if self.name != "global":
            msg += f"{self.name}:\n"
            level = 1

        if self.name + ".doc" not in self.parser:
            return ""

        for opt in doc_section:
            if opt == "self":
                continue
            msg += self.fmt_option(opt, level, indent, middle)
        return msg


class ConfigParser(configparser.ConfigParser):
    def __init__(self,
                 parent: object,
                 path=['.'],
                 ext=['.ini', '.conf', '.cfg'],
                 *args,
                 **kwargs):

        # Need to call the real setter to not get into a recursion loop
        object.__setattr__(self, "_initialised", False)
        super().__init__(*args, **kwargs)

        loaded = False
        loaded_from_default = False

        if isinstance(parent, str):
            name = parent
        else:
            name = parent.__class__.__name__

        self.name = name

        # Select the first file matching name.ext in one of path
        for pdir in path:
            if not os.path.isdir(pdir):
                continue
            for pext in ext:
                filename = os.path.join(pdir, name + pext)
                if not os.path.isfile(filename):
                    continue
                try:
                    if verbose:
                        sys.stderr.write(f"Loading {filename}...\n")
                    with open(filename, 'r') as cfile:
                        self.read_file(cfile, source=filename)
                    loaded = True
                except BaseException as e:
                    if verbose:
                        sys.stderr.write(f"Warning: Unable to load {filename}:"
                                         f" {str(e)}\n")
                    continue

        if not loaded and name in default.configs:
            if verbose:
                sys.stderr.write(f"Loading default config for {name}...\n")
            self.read_string(default.configs[name], 'default_' + name)
            loaded = True
            loaded_from_default = True

        if not loaded and verbose:
            sys.stderr.write(f"Creating a new config for {name}...\n")

        if not self.has_section("global"):
            self.add_section("global")

        if "config_name" not in self["global"]:
            self["config_name"] = 'global'

        self._config_changed = loaded_from_default
        self._initialised = True

    def __getattr__(self, name: str) -> SectionProxyWrapper:
        if not self._initialised:
            return
        # The global section exposes it's options directly instead of going
        # though a section
        if name in self["global"]:
            return self["global"][name]
        elif name in self:
            return self[name]
        else:
            return configparser.ConfigParser.__getattr__(self, name)

    # Using the parent class' original getitem method but downcast the
    # SectionProxy to our wrapper
    def __getitem__(self, name: str) -> object:
        s = configparser.ConfigParser.__getitem__(self, name)
        object.__setattr__(s, "__class__", SectionProxyWrapper)
        return s

    def __setattr__(self, name: str, value: object):
        # If we are done initializing our class, a set should be adding to the
        # underlying parser instead of defining new attributes
        if self._initialised and name not in self.__dir__():
            # The options from the global section are exposed directly without
            # the section name indirection
            if name in self["global"]:
                self["global"][name] = value
            else:
                self[name] = value
        else:
            object.__setattr__(self, name, value)

    def no_docs(self) -> Iterator[str]:
        "Return an iterator of over the sections, without the *.doc and the DEFAULT section"
        return filter(lambda s: not s.endswith(".doc") and s != "DEFAULT", configparser.ConfigParser.__iter__(self))

    def help(self, args: list[str] = [], level=0, indent=4, middle=40) -> str:
        "Returns the doc string for name with the specified indentation"
        if len(args) == 0:
            msg = ""
            for s in self.no_docs():
                msg += self[s].help(None, level, indent, middle) + "\n"
            return msg[:-1]  # Remove the last line feed
        else:
            if args[0] in self["global"]:
                section = "global"
                option = args[0]
            else:
                section = args[0]
                option = args[1] if len(args) == 2 else None
            return self[section].help(option, level, indent, middle)

    def save(self, path: str):
        "Write the config to disk"
        if self._config_changed:
            filename = os.path.join(path, self.config_name + ".ini")
            with open(filename, "w") as cfile:
                self.write(cfile)

# Alias to stay backwards compatible
config = ConfigParser
