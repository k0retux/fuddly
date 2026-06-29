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
import sys
import configparser

from collections.abc import Iterator
from fuddly.framework.global_resources import config_folder


class Default:
    def __init__(self):
        self.configs = {}

    def add(self, name, doc):
        self.configs[name] = doc


default = Default()

default.add("FmkPlumbing", """
[global]
config_name = FmkPlumbing

[misc]
fuzz_delay = 0
fuzz_burst = 1
continuous_monitoring_mode = True

[misc.doc]
self: (default values used when the framework resets)
fuzz_delay: Default value (> 0) for fuzz_delay
fuzz_burst: Default value (>= 1) for fuzz_burst

[targets]
empty_tg_verbose = False

[targets.doc]
self: configuration related to targets
empty_tg_verbose: Enable verbose mode (if True) on the default EmptyTarget()

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

[global.doc]
prompt: Set the 'Fuddly Shell' prompt

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
indent_width = 4
indent_level = 0

[config.doc]
self: Configuration applicable to the 'config' command
middle: Set the column where the helpers are defined.
indent_width: Set the indentation width used to display the helpers.
indent_level: Set the initial level of indentation width
              used to display the helpers.

[send_loop]
aligned = False
aligned_options_batch_mode = False
aligned_options_hide_cursor = True
aligned_options_prompt_height = 3

[send_loop.doc]
self: Configuration applicable to the 'send_loop' command.

aligned: Enable aligned display while sending data payloads.
aligned_options_batch_mode: Enable fitting multiple payloads onscreen
                            (when using 'send_loop -1 <generator>').
aligned_options_hide_cursor: Attempt to reduce blinking by hiding cursor.
aligned_options_prompt_height: Estimation of prompt's height.

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
        if not self.parser._initialised:
            return super().__getattribute__(key)
        try:
            return self.__getitem__(key)
        except KeyError:
            return super().__getattribute__(key)

    def __getitem__(self, key: str) -> object:
        if not self.parser._initialised:
            return super().__getitem__(key)
        return check_type(key, configparser.SectionProxy.__getitem__(self, key))

    def __setattr__(self, key: str, val: object):
        if not self.parser._initialised:
            return super().__setattr__(key, val)
        return self.__setitem__(key, val)

    def __setitem__(self, key: str, val: object):
        if self.parser._initialised:
            self.parser._config_changed = True
        return super().__setitem__(key, str(val))

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
                sub_opts = list(filter(lambda o: o.startswith(option), doc_section))
                if len(sub_opts) == 0:
                    return f"{option}: <undefined>\n"

                msg = f"{option}: (partial match)\n"
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
                 auto_update=True,
                 *args,
                 **kwargs):

        # Need to call the real setter to not get into a recursion loop
        object.__setattr__(self, "_initialised", False)
        super().__init__(*args, **kwargs)

        if isinstance(parent, str):
            name = parent
        else:
            name = parent.__class__.__name__

        self.name = name

        updated = False

        # Load the default config, value from the conf file will override them
        if name in default.configs.keys():
            self.read_string(default.configs[name], 'default_' + name)
            self._config_changed = True
        else:
            # We don't have a default so we can't auto update
            auto_update = False

        # Try all files in {path} with all the extensions {ext}
        config_files = []
        for pdir in path:
            for pext in ext:
                config_files.append(os.path.join(pdir, name + pext))

        loaded_files = self.read(config_files)
        if len(loaded_files) != 0:
            self._config_changed = False
        else:
            sys.stderr.write(f'Warning: Unable to load any of {config_files}\n')

        self._initialised = True
        if auto_update:
            defconf = configparser.ConfigParser()
            defconf.read_string(default.configs[name], 'default_' + name)
            updated = self.clean(defconf)
        self._config_changed = self._config_changed or updated
        if auto_update and self._config_changed:
            new_fn = loaded_files[0] + '.old'
            os.rename(loaded_files[0], new_fn)
            self.save(fullpath=loaded_files[0])

    def __getattr__(self, name: str) -> SectionProxyWrapper:
        # The global section exposes it's options directly instead of going
        # though a section
        if not self._initialised:
            return object.__getattribute__(self, name)
        try:
            if super().has_option("global", name):
                return super().get("global", name)
            elif super().has_section(name):
                return self[name]
        except KeyError:
            return super().__getattribute__(name)

    # Using the parent class' original getitem method but downcast the
    # SectionProxy to our wrapper
    def __getitem__(self, name: str) -> object:
        s = super().__getitem__(name)
        object.__setattr__(s, "__class__", SectionProxyWrapper)
        return s

    def __setattr__(self, name: str, value: object):
        # If we are done initializing our class, a set should be adding to the
        # underlying parser instead of defining new attributes
        if not self._initialised:
            return super().__setattr__(name, value)
        if super().has_option("global", name):
            return super().set("global", name, value)
        else:
            return super().__setattr__(name, value)

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

    def save(self, path: str = "", fullpath: str = None):
        "Write the config to disk"
        if self._config_changed:
            if fullpath is not None:
                filename = fullpath
            else:
                filename = os.path.join(path, self.config_name + ".ini")
            with open(filename, "w") as cfile:
                self.write(cfile)

    def clean(self, default: configparser.ConfigParser) -> bool:
        "Remove config options and sections that do not exist in the default config"
        changed = False
        # Converting to lists because we are changing the dict
        # during the iteration
        for section in list(self):
            if section == "DEFAULT":
                continue

            if not default.has_section(section):
                print(f"Removing section {section} in {self.name}")
                self.remove_section(section)
                changed = True
                continue
            for opt in list(self.options(section)):
                if not default.has_option(section, opt):
                    print(f"Removing option {opt} from section {section} in {self.name}")
                    self.remove_option(section, opt)
                    changed = True
        return changed


# Alias to stay backwards compatible
config = ConfigParser
