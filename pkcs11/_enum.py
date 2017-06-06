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
        return value
        if value & cls._VENDOR_DEFINED:
            type_ = type('%sVendorExtension' % cls.__name__, (Extension,), {})
        else:
            type_ = type('%sUnknownExtension' % cls.__name__, (Extension,), {})

        return type_(value)

    @classmethod
    def load_extensions(cls, extensions):
        assert issubclass(extensions, IntEnum), "Extensions must be IntEnum"

        for extension in extensions:
            assert extension.name.startswith('X_'), \
                "Extensions must start with 'X_'"
            cls._member_map_[extension.name] = extension
