# Copyright Red Hat 2018, Jake Hunsaker <jhunsake@redhat.com>
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


class InvalidPasswordException(Exception):
    '''Raised when the provided password is rejected by the remote host'''

    def __init__(self):
        message = 'Invalid password provided'
        super(InvalidPasswordException, self).__init__(message)


class TimeoutPasswordAuthException(Exception):
    '''Raised when a timeout is hit waiting for an auth reply using a password
    '''

    def __init__(self):
        message = 'Timeout hit while waiting for password validation'
        super(TimeoutPasswordAuthException, self).__init__(message)


class PasswordRequestException(Exception):
    '''Raised when the remote host requests a password that was not anticipated
    '''

    def __init__(self):
        message = 'Host requested password, but none provided'
        super(PasswordRequestException, self).__init__(message)


class AuthPermissionDeniedException(Exception):
    '''Raised when authentication attempts return a permission error'''

    def __init__(self):
        message = 'Permission denied while trying to authenticate'
        super(AuthPermissionDeniedException, self).__init__(message)


class ConnectionException(Exception):
    '''Raised when an attempt to connect fails'''

    def __init__(self, address='', port=''):
        message = ("Could not connect to host %s on specified port %s"
                   % (address, port))
        super(ConnectionException, self).__init__(message)


class CommandTimeoutException(Exception):
    '''Raised when a timeout expires'''

    def __init__(self, command=None):
        message = 'Timeout expired'
        if command:
            message += " executing %s" % command
        super(CommandTimeoutException, self).__init__(message)


class ConnectionTimeoutException(Exception):
    '''Raised when a timeout expires while trying to connect to the host'''

    def __init__(self):
        message = 'Timeout expires while trying to connect'
        super(ConnectionTimeoutException, self).__init__(message)


class ControlSocketMissingException(Exception):
    '''Raised when the SSH control socket is missing'''

    def __init__(self, path=''):
        message = "SSH control socket %s does not exist" % path
        super(ControlSocketMissingException, self).__init__(message)


class ControlPersistUnsupportedException(Exception):
    '''Raised when SSH ControlPersist is unsupported locally'''

    def __init__(self):
        message = 'ControlPersist unsupported by local SSH installation'
        super(ControlPersistUnsupportedException, self).__init__(message)


class UnsupportedHostException(Exception):
    '''Raised when the host type is unsupported or undetermined'''

    def __init__(self):
        message = 'Host did not match any supported distributions'
        super(UnsupportedHostException, self).__init__(message)


__all__ = [
    'AuthPermissionDeniedException',
    'CommandTimeoutException',
    'ConnectionException',
    'ConnectionTimeoutException',
    'ControlPersistUnsupportedException',
    'ControlSocketMissingException',
    'InvalidPasswordException',
    'PasswordRequestException',
    'TimeoutPasswordAuthException',
    'UnsupportedHostException'
]
