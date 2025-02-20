from fuddly.framework.knowledge.information import Info, auto


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
    Ada = auto()
    Pascal = auto()
    Unknown = auto()


class InputHandling(Info):
    Ctrl_Char_Set = auto()
    Printable_Char_Set = auto()
    Unknown = auto()


class Test(Info):
    Cursory = auto()
    Medium = auto()
    Deep = auto()


class OperationMode(Info):
    Determinist = auto()
    Random = auto()


if __name__ == "__main__":

    OS.Linux.increase_trust()
    OS.Linux.increase_trust()
    OS.Linux.show_trust()
    OS.Windows.show_trust()
