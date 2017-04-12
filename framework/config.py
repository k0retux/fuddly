################################################################################
#
#  Copyright 2017 Matthieu Daumas <matthieu@daumas.me>
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



import io, re, sys

try:
    import configparser
except:
    import ConfigParser as configparser

reserved = {'config_name', 'parser', 'help', 'write'}

class default:
    def __init__(self):
        self.configs = {}

    __unindent = re.compile(r'^;;\s\s*', re.MULTILINE)
    def _unindent(self, multiline):
        return self.__unindent.sub('', multiline)

    def add(self, name, doc):
        if sys.version_info[0] > 2:
            pass
        else:
            doc = unicode(doc)

        self.configs[name] = self._unindent(doc)
default = default()

default.add(
'FmkPlumbing', u'''
[global]
config_name: FmkPlumbing

[default]
fuzz.delay = 0.01
fuzz.burst = 1

;;  [default.doc]
;;  self: (default values used when the framework resets)
;;  fuzz.delay: Default value (> 0) for fuzz_delay
;;  fuzz.burst: Default value (>= 1)for fuzz_burst

''')

default.add(
'FmkShell', u'''
[global]
config_name: FmkShell
prompt: >>

;;  [global.doc]
;;  prompt: Set the 'Fuddly Shell' prompt

[config]
middle: 40
indent.width: 4
indent.level: 0

;;  [config.doc]
;;  self: Configuration applicable to the 'config' command
;;  middle: Set the column where the helpers are defined.
;;  indent.width: Set the indentation width used to display the helpers.
;;  indent.level: Set the initial level of indentation width
                    used to display the helpers.

[send_loop]
aligned: True
aligned_options.batch_mode: False
aligned_options.prompt_height: 3

;;  [send_loop.doc]
;;  self: Configuration applicable to the 'send_loop' command.
;;
;;  aligned: Enable aligned display while sending data payloads.
;;  aligned_options.batch_mode: Enable fitting multiple payloads onscreen
                     (when using 'send_loop -1 <generator>').
;;  aligned_options.prompt_height: Estimation of prompt's height.

''')

def check_type(name, attr, value):
    original = value

    try:
        attr = str(attr)
    except Exception as e:
        raise AttributeError(
                "unable to cast key's value "
                + "'{}' into a string".format(name)
                + ': ' + str(e))

    try:
        value = str(value)
    except Exception as e:
        raise AttributeError(
                ("unable to cast '{}' "
                    + "for key '{}' into a string"
                ).format(value, name)
                + ': ' + str(e))

    booleans = [u'True', u'False']
    if attr in booleans:
        test = (attr == u'True')
    else:
        test = None
    if not test is None:
        if value in booleans:
            return (value == u'True')
        else:
            raise AttributeError(
                    "key '{}' expects a boolean".format(name))

    try:
        test = int(attr)
    except:
        test = None
    if not test is None:
        try:
            return int(value)
        except:
            raise AttributeError(
                    "key '{}' expects an integer".format(name))

    try:
        test = float(attr)
    except:
        test = None
    if not test is None:
        try:
            return float(value)
        except:
            raise AttributeError(
                    "key '{}' expects a float".format(name))

    return original

def config_write(that, stream=sys.stdout):

    that_dict = object.__getattribute__(that, '__dict__')
    subconfigs = []
    for item in that_dict.items():
        if isinstance(item, config):
            subconfigs.append(item)

    for name, subconfig in subconfigs:
        setattr(that, name, subconfig)

    return that.parser.write(stream)

def sectionize(that):
    try:
        name = unicode(that.config_name)
    except:
        name = that.config_name

    parser = configparser.SafeConfigParser()
    resection = re.compile(r'^([^.]*)\.?(.*)')
    for section in that.parser.sections():
        match = resection.match(section)
        if not match:
            raise RuntimeError(
                    "unable to match '{}'".format(section)
                    + ' section name')

        if len(match.group(2)) > 0:
            target = name + '.' + match.group(2)
        else:
            target = name

        if not parser.has_section(target):
            parser.add_section(target)

        if match.group(1) == 'global':
            for option in that.parser.options(section):
                value = that.parser.get(section, option)
                parser.set(target, option, value)
        else:
            for option in that.parser.options(section):
                value = that.parser.get(section, option)
                parser.set(
                        target,
                        match.group(1) + '.' + option,
                        value)

    return parser

def get_help_format(line, doc, level, indent, middle):
    if doc is None or len(doc) < 1:
        doc = '\n'

    try:
        line = str(line)
    except:
        pass

    msg = ''
    space = ' '
    lines = line.splitlines(True)
    for line in lines:
        line = level * indent * space + line
        msg += line

        fst = True
        docs = doc.splitlines(True)
        for doc in docs:
            if fst:
                size = middle - len(line)
                msg += size * space + doc
                fst = False
            else:
                msg += middle * space + doc

            if not ('\n' in doc):
                msg += '\n'
    return msg

def get_help(that, name=None, level=0, indent=4, middle=40):
    private = getattr(config, '_config__private')
    get_help_attr = private._private__get_help_attr.__func__
    if not name is None:
        return get_help_attr(that, name, level, indent, middle)

    msg = ''
    resection = re.compile(r'^[^.]*$')
    for section in that.parser.sections():
        if section == 'global':
            for option in that.parser.options(section):
                if option in reserved:
                    continue

                msg += get_help_attr(
                        that,
                        option,
                        level,
                        indent,
                        middle)
        elif resection.match(section):
            msg += get_help_attr(
                    that,
                    section,
                    level,
                    indent,
                    middle)
        else:
            pass

    return msg

def config_setattr(that, name, value):
    private = object.__getattribute__(that, '_config__private')

    try:
        attr = object.__getattribute__(that, name)
    except:
        attr = None

    if not isinstance(value, config):
        if isinstance(value, config_dot_proxy):
            raise RuntimeError(
                    "'{}' (config_dot_proxy)".format(name)
                    + ' can not be used as value.')

        if not attr is None:
            value = check_type(name, attr, value)

        if '.' in name:
            prefixes = name.split('.')
            for i in range(1, len(prefixes)):
                prefix = '.'.join(prefixes[:-1 * i])
                proxy = config_dot_proxy(that, prefix)
                object.__setattr__(that, prefix, proxy)

        strvalue = str(value)
        that.parser.set('global', name, strvalue)
        return object.__setattr__(that, name, value)

    if attr is None:
        flat_parser = sectionize(value)
        for section in flat_parser.sections():
            if not that.parser.has_section(section):
                that.parser.add_section(section)

            for option in flat_parser.options(section):
                if option in reserved:
                    continue
                subvalue = flat_parser.get(section, option)
                that.parser.set(section, option, subvalue)

        return object.__setattr__(that, name, value)

    if not isinstance(attr, config):
        raise AttributeError(
                "unable to replace key '{}'".format(name)
                + ' by a section')

    attr_parser = sectionize(attr)
    for section in attr_parser.sections():
        if not that.parser.has_section(section):
            continue

        for option in attr_parser.options(section):
            if option in reserved:
                continue

            that.parser.remove_option(section, option)

        if len(that.parser.options(section)) < 1:
            that.parser.remove_section(section)

    object.__setattr__(that, name, None)
    return that.__setattr__(name, value)

def config_getattribute(that, name):
    private = object.__getattribute__(that, '_config__private')
    if name == 'help':
        def get_help_proxy(name=None, level=0, indent=4, middle=40):
            msg = get_help(
                    that,
                    name,
                    level,
                    indent,
                    middle
                    )
            try:
                return str(msg)
            except:
                return msg
        return get_help_proxy

    if name == 'write':
        def write_proxy(stream=sys.stdout):
            return config_write(that, stream)
        return write_proxy

    try:
        attr = object.__getattribute__(that, name)
        try:
            attr = check_type(name, attr, attr)
        except:
            pass
    except:
        attr = None

    if attr is None or '__' in name[:2] or '_config__' in name[:9]:
        msg = "'config' instance for '{}' has no key nor section '{}'"
        if not name == 'config_name':
            raise AttributeError(msg.format(that.config_name, name))
        else:
            raise AttributeError(msg.format('error', name))

    return attr

class config_dot_proxy(object):
    def __init__(self, config, prefix):
        object.__setattr__(self, 'parent', config)
        object.__setattr__(self, 'prefix', prefix)

    def __getattribute__(self, name):
        parent = object.__getattribute__(self, 'parent')
        prefix = object.__getattribute__(self, 'prefix')
        try:
            return getattr(parent, prefix + '.' + name)
        except:
            return config_dot_proxy(self, name)

    def __setattr__(self, name, value):
        parent = object.__getattribute__(self, 'parent')
        prefix = object.__getattribute__(self, 'prefix')
        return setattr(parent, prefix + '.' + name, value)

class config(object):

    class __private:

        def __get_help_attr(self, name, level=0, indent=4, middle=40):
            private = getattr(config, '_config__private')
            get_help_attr = private.__get_help_attr.__func__

            if name in reserved:
                return get_help_format(
                        name + ': <reserved>',
                        '(implementation details, reserved)',
                        level,
                        indent,
                        middle
                        )

            dot_section = re.compile(r'^[^.]+\.[^.]+$')
            if dot_section.match(name) and self.parser.has_section(name):
                    return get_help_format(
                            name + ': <reserved>',
                            '(special section, reserved)',
                            level,
                            indent,
                            middle
                            )

            if self.parser.has_section(name):
                try:
                    doc = self.parser.get(name + '.doc', 'self')
                except:
                    doc = None

                msg = '\n'
                msg += get_help_format(
                    name + ':',
                    doc,
                    level,
                    indent,
                    middle
                    )

                return (msg
                    + get_help(
                        getattr(self, name),
                        level=level + 1,
                        indent=indent,
                        middle=middle))

            try:
                doc = self.parser.get('global.doc', name)
            except:
                doc = None

            try:
                try:
                    value = str(self.parser.get('global', name))
                except:
                    value = self.parser.get('global', name)
            except:
                kdict = object.__getattribute__(self, '__dict__')
                keys = [key for key in kdict]
                if name in keys and isinstance(kdict[name], config_dot_proxy):
                    msg = name + ': (subkeys)\n'
                    keys = [key for key in keys if key.startswith(name + '.')]
                    for key in sorted(keys):
                        msg += get_help_attr(
                                self,
                                key,
                                level + 1,
                                indent,
                                middle)
                    return msg
                else:
                    value = '<undefined>'

            return get_help_format(
                name + ': ' + value,
                doc,
                level,
                indent,
                middle
                )

    def __init__(self, parent):

        object.__setattr__(self, '_config__private', config.__private())
        object.__setattr__(
                self,
                'parser',
                configparser.SafeConfigParser()
                )

        if isinstance(parent, str):
            name = parent
        else:
            try:
                name = parent.__class__.__name__
            except:
                name = parent.__name__ # (no parent.__class__.__name__)

        if name in default.configs:
            try:
                self.parser.read_string(
                        default.configs[name],
                        'default_' + name
                        )
            except:
                stream = io.StringIO()
                stream.write(default.configs[name])
                stream.seek(0)
                self.parser.readfp(stream, 'default_' + name)

            if not self.parser.has_section('global'):
                raise AttributeError(
                        ("default config '{}' has no '{}' section"
                        ).format(name, 'global'))

            try:
                self.parser.get('global', 'config_name')
            except:
                raise AttributeError(
                        ("default config '{}' has no '{}' key"
                        ).format(name, 'config_name'))

            resection = re.compile(r'^([^.]*)(\..*)?')
            for section in self.parser.sections():

                match = resection.match(section)
                if not match:
                    raise RuntimeError(
                            ("unable to match '{}' section name"
                            ).format(section))

                if not section == 'global':
                    if match.group(2) and len(match.group(2)) == 0:
                        setattr(self, section, config(section))
                    else:
                        try:
                            subconfig = object.__getattribute__(
                                    self,
                                    match.group(1)
                                    )
                        except:
                            setattr(
                                    self,
                                    match.group(1),
                                    config(match.group(1))
                                    )
                            subconfig = object.__getattribute__(
                                    self,
                                    match.group(1)
                                    )

                        try:
                            subconfig.parser.add_section(
                                    'global' + match.group(2)
                                    )
                        except:
                            pass

                for option in self.parser.options(section):
                    value = self.parser.get(section, option)
                    if section == 'global':
                        if self.parser.has_section(option):
                            raise AttributeError(
                                    ("default config '{}' "
                                        + "has global '{}' which "
                                        + "overrides '{}' section"
                                    ).format(name, option, option))
                        setattr(self, option, value)
                    else:
                        if match.group(2) and len(match.group(2)) > 0:
                            subconfig = object.__getattribute__(
                                    self,
                                    match.group(1)
                                    )
                            subconfig.parser.set(
                                'global' + match.group(2),
                                option,
                                value
                                )
                        else:
                            subconfig = object.__getattribute__(self, section)
                            setattr(subconfig, option, value)


        if not self.parser.has_section('global'):
            self.parser.add_section('global')

        try:
            object.__getattribute__(self, 'config_name')
        except:
            self.config_name = 'global'

    def __getattribute__(self, name):

        try:
            private = object.__getattribute__(self, '_config__private')
        except:
            return object.__getattribute__(self, name)

        config_get = config_getattribute
        return config_get(self, name)

    def __setattr__(self, name, value):

        try:
            private = object.__getattribute__(self, '_config__private')
        except:
            return object.__setattr__(self, name, value)

        config_set = config_setattr
        return config_set(self, name, value)
