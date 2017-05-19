
class PKCSError(Exception):
    pass


def _CK_UTF8CHAR_to_str(data):
    """Convert CK_UTF8CHAR to string."""
    # FIXME: the last couple of bytes are sometimes bogus, is this me
    # or SoftHSM?
    return data[:31].decode('utf-8').rstrip()


def _CK_VERSION_to_tuple(data):
    """Convert CK_VERSION to tuple."""
    return (data['major'], data['minor'])


class Info:
    """
    getInfo return type
    """

    def __init__(self,
                 manufacturerID=None,
                 libraryDescription=None,
                 cryptokiVersion=None,
                 libraryVersion=None,
                 **kwargs):
        self.manufacturerID = _CK_UTF8CHAR_to_str(manufacturerID)
        self.libraryDescription = _CK_UTF8CHAR_to_str(libraryDescription)
        self.cryptokiVersion = _CK_VERSION_to_tuple(cryptokiVersion)
        self.libraryVersion = _CK_VERSION_to_tuple(libraryVersion)

    def __str__(self):
        return '\n'.join((
            "Manufacturer ID: %s" % self.manufacturerID,
            "Library Description: %s" % self.libraryDescription,
            "Cryptoki Version: %s.%s" % self.cryptokiVersion,
            "Library Version: %s.%s" % self.libraryVersion,
        ))


class SlotInfo:
    """
    getSlotInfo return type
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


