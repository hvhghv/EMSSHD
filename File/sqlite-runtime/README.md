# SQLite runtime libraries

SQLite 3.53.2 runtime libraries used by `APP/emtask` dynamic task storage.

- `win-x64/sqlite3.dll`: official SQLite Windows x64 DLL from `sqlite-dll-win-x64-3530200.zip`.
- `linux-x64/libsqlite3.so`: Linux x64 shared library built from official SQLite amalgamation `3530200`.
- `linux-x64/libsqlite3.so.0`: compatibility copy for loaders that search `libsqlite3.so.0`.

These files are kept here for packaging. They are not copied during CMake builds.

At runtime, `emtask` only searches the current working directory first, then the system library path. If it falls back to a system SQLite library, it prints a warning. To force the bundled runtime, start `emtask` with the matching `File/sqlite-runtime/<platform>` directory as the current directory or place the matching library in the current directory.

SQLite is in the public domain: https://www.sqlite.org/copyright.html
