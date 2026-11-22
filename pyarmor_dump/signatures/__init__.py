from . import v7, v8_rft, v9

ALL = (v7, v8_rft, v9)
BY_MAJOR = {mod.MAJOR: mod for mod in ALL}

__all__ = ["ALL", "BY_MAJOR", "v7", "v8_rft", "v9"]
