import idaapi
import idautils
import idc
import inspect

# TODO: add support for window
__version__ = '1.0.0'
__author__ = 'Hapsida @securisec'


class SaramIDA(idaapi.plugin_t):
    """
    SaramIDA class

    :param token: A valid Saram token
    :type idaapi: str

    >>> # from inside IDA python
    >>> saram = SaramIDA('546cd670-lol')
    """

    def __init__(self, token):
        idaapi.require('saramIDAHelpers')
        idaapi.require('saramIDAHelpers.saram_py2_scaffold')
        self._saram_conf = saramIDAHelpers.saram_py2_scaffold.saram_conf
        self._send = saramIDAHelpers.saram_py2_scaffold.saram_py2_new_section
        self.token = token
        self.command = None
        self.output = None
        self._comment = None

    def __get_screen_ea(self):
        return idaapi.get_func(idc.ScreenEA())

    def send(self):
        """
        Sends the data to the Saram server
        """
        data = {
            "type": "tool",
            "output": self.output,
            "command": self.command,
            "user": self._saram_conf['username'],
            "comment": [
                {
                    "username": self._saram_conf['username'],
                    "avatar": self._saram_conf['avatar'],
                    "text": "saramIDA {func}".format(func=self._comment)
                }
            ]
        }
        print(self._send(self.token, data))

    def decompile_function(self):
        """
        Decompile a function

        >>> saram.decompile_function().send()
        """
        offset = self._SaramIDA__get_screen_ea()
        self.command = 'Function: {name} @{offset}'.format(
            name=idc.GetFunctionName(offset.startEA), offset=hex(offset.startEA))
        self._comment = inspect.stack()[0][3]
        self.output = str(idaapi.decompile(offset))
        print(self.output)
        return self

    def get_strings(self):
        """
        Get all strings from the binary

        >>> saram.get_strings().send()
        """
        self._comment = inspect.stack()[0][3]
        strings = '\n'.join([
            '{offset} {value}'.format(offset=hex(x.ea), value=x) for x in idautils.Strings()
        ])
        self.command = 'Strings from binary'
        self.output = strings
        print(self.output)
        return self

    def function_comments(self):
        """
        Get all user comments from the function

        :raises TypeError: If no comments are found

        >>> saram.function_comments().send()
        """
        self._comment = inspect.stack()[0][3]
        offset = self._SaramIDA__get_screen_ea()
        comments = []
        for ea in range(offset.startEA, offset.endEA):
            comment = idaapi.get_cmt(ea, 1)
            if comment is not None:
                comments.append('{offset} {value}'.format(
                    offset=hex(ea), value=comment
                ))
        if len(comments) > 0:
            self.command = 'Comments for: {name}'.format(
                name=idc.GetFunctionName(offset.startEA))
            self.output = '\n'.join(comments)
            print(self.output)
            return self
        else:
            raise TypeError('No comments found')


def PLUGIN_ENTRY():
    return SaramIDA
