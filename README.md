# dlopen-resolver

Find library names opened by dlopen in a binary by statical analysis:

```console
$ python dlopen-resolver.py $(which htop)
libsensors.so
libsensors.so.5
libsensors.so.4
libsystemd.so.0
```

Note that we can only figure out static strings passed to dlopen.
If the string is computed at runtime for example with sprintf, there is no
trivial way to compute the right value.

## How does it work:

This script uses radare2 under the hood to find all function calls and than
tries to infer the library name argument passed using emulation.
