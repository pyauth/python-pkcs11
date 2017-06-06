from enum import IntEnum


class Extension:
    def __init__(self, value):
        self._value = value

    def __str__(self):
        return '%s.%s' % (type(self).__name__, hex(self._value))

    def __repr__(self):
        return '<%s>' % self

    def __hash__(self):
        return hash(self._value)

    def __int__(self):
        return self._value

    def __eq__(self, other):
        return self._value == other


class VendorExtendableEnum(IntEnum):
    @classmethod
    def _missing_(cls, value):
        if value & cls._VENDOR_DEFINED:
            # try:
            #     for extension in cls._extensions:
            #         try:
            #             return extension(value)
            #         except ValueError:
            #             pass
            # except AttributeError:
            #     pass

            type_ = type('%sVendorExtension' % cls.__name__, (Extension,), {})
        else:
            type_ = type('%sUnknownExtension' % cls.__name__, (Extension,), {})

        return type_(value)

    # @classmethod
    # def load_extension(cls, extension):
    #     assert issubclass(extension, IntEnum), "Extensions must be IntEnum"

    #     try:
    #         cls._extensions.append(extension)
    #     except AttributeError:
    #         cls._extensions = [extension]
