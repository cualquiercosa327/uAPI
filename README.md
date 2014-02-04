# µAPI

µAPI is a micro API project built on top of Joyent's [libuv](https://github.com/joyent/libuv/) library. A
large portion of the core HTTP server is based on @kellabyte's
[Haywire](https://github.com/kellabyte/Haywire/) source code.

## Dependencies

- libuv
- freetds (for SQL Server)

## Build Instructions

You first need to obtain libuv and install it, then it's as simple as invoking
GNU Make. Under Windows you should specify the Makefile.mingw file. It may be
required to alter the paths to libuv in the Makefile.

## License

This project is currently licensed under the Apache license. Some portions of
the code may be under a BSD/ISC (e.g. bstrlib) license.
