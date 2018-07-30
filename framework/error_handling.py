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

class UnavailablePythonModule(Exception): pass
class InvalidFmkDB(Exception): pass

class TargetFeedbackError(Exception): pass
class DataProcessTermination(Exception): pass
class UserInterruption(Exception): pass

class PopulationError(Exception): pass
class ExtinctPopulationError(PopulationError): pass

class DataModelDefinitionError(Exception): pass
class ProjectDefinitionError(Exception): pass

class RegexParserError(DataModelDefinitionError): pass

class EscapeError(RegexParserError):

    def __init__(self, char=None):
        if char is None:
            message = "Nothing to escape."
        elif char in ('\\','(',')','[',']','{','}','+','?','*','|','-'):
            message = char + " is a special character: it needs to be escaped in order to be used in this context."
        else:
            message = char + " is not a special character: it is useless to escape it."
        RegexParserError.__init__(self, message)

class QuantificationError(RegexParserError):

    def __init__(self, message=None):

        if message is None:
            message = u"Quantifier must be specified as followed: {X[,Y]} with X \u2264 Y."

        RegexParserError.__init__(self, message)



class StructureError(RegexParserError):

    def __init__(self, char):
        message = ""
        if char == '}':
            message = "Unopened bracket, nothing to close."
        elif char == ')':
            message = "Unopened parenthesis, nothing to close."
        elif char == "]":
            message = "Unopened squared bracket, nothing to close."
        else:
            message = "Unclosed element."
        RegexParserError.__init__(self, message)


class InconvertibilityError(RegexParserError):

    def __init__(self):
        RegexParserError.__init__(self, "Described regular expression is to complex, it can't be " +
                                        "translated into a non-terminal only composed of terminal ones.")

class EmptyAlphabetError(RegexParserError): pass
class InvalidRangeError(RegexParserError): pass

class InitialStateNotFoundError(RegexParserError):

    def __init__(self):
        RegexParserError.__init__(self, "No state was declared as initial.")

class CharsetError(RegexParserError):

    def __init__(self):
        RegexParserError.__init__(self, "Some character(s) into the regex are incoherent with the provided charset.")
