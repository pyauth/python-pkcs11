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
    A PKCS#11 token
    """

    def __init__(self,
                 label=None,
                 **kwargs):
        self.label = _CK_UTF8CHAR_to_str(label)

    def __str__(self):
        return self.label

    def __repr__(self):
        return "<{klass} (label='{label}')>".format(
            klass=type(self).__name__, label=self.label)
