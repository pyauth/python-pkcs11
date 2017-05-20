"""
Types for high level PKCS#11 interface.
"""


def _CK_UTF8CHAR_to_str(data):
    """Convert CK_UTF8CHAR to string."""
    # FIXME: the last couple of bytes are sometimes bogus, is this me
    # or SoftHSM?
    return data[:31].decode('utf-8').rstrip()


def _CK_VERSION_to_tuple(data):
    """Convert CK_VERSION to tuple."""
    return (data['major'], data['minor'])


class Slot:
    """
    A PKCS#11 device slot.

    This object represents a physical or software slot exposed by PKCS#11.
    A slot has hardware capabilities, e.g. supported mechanisms and may has
    a physical or software :class:`Token` installed.
    """

    def __init__(self,
                 slotDescription=None,
                 manufacturerID=None,
                 hardwareVersion=None,
                 firmwareVersion=None,
                 **kwargs):
        self.slotDescription = _CK_UTF8CHAR_to_str(slotDescription)
        self.manufacturerID = _CK_UTF8CHAR_to_str(manufacturerID)
        self.hardwareVersion = _CK_VERSION_to_tuple(hardwareVersion)
        self.firmwareVersion = _CK_VERSION_to_tuple(firmwareVersion)

    def get_token(self):
        """
        Returns the token loaded into this slot.

        :rtype: list(Token)
        """
        raise NotImplementedError()

    def get_mechanisms(self):
        """
        Returns the mechanisms supported by this device.

        :rtype: set(Mechanisms)
        """
        raise NotImplementedError()

    def __str__(self):
        return '\n'.join((
            "Slot Description: %s" % self.slotDescription,
            "Manufacturer ID: %s" % self.manufacturerID,
            "Hardware Version: %s.%s" % self.hardwareVersion,
            "Firmware Version: %s.%s" % self.firmwareVersion,
        ))

    def __repr__(self):
        return '<{klass} (slotID={slotID})>'.format(
            klass=type(self).__name__, slotID=self.slotID)


class Token:
    """
    A PKCS#11 token.

    A token can be physically installed in a :class:`Slot`, or a software
    token, depending on your PKCS#11 library.
    """

    def __init__(self, slot,
                 label=None,
                 **kwargs):
        self.slot = slot
        self.label = _CK_UTF8CHAR_to_str(label)

    def __str__(self):
        return self.label

    def __repr__(self):
        return "<{klass} (label='{label}')>".format(
            klass=type(self).__name__, label=self.label)
