# SQLite amalgamation source

Version: SQLite 3.53.2 (`3530200`).

Downloaded from the official SQLite download page:

- `https://www.sqlite.org/2026/sqlite-dll-win-x64-3530200.zip`
  - SHA3-256: `b898ced2e0627999d7d0b9d554ea53086a9b165e52ae743277d115dcd39e6868`
- `https://www.sqlite.org/2026/sqlite-amalgamation-3530200.zip`
  - SHA3-256: `81142986038e18f96c4a54e1a72562ae17e502a916f2a7701eff43388cbf1a40`

Files here:

- `src/sqlite3.c`, `src/sqlite3.h`, `src/sqlite3ext.h`: official amalgamation files used to build the Linux shared library.

Runtime libraries were moved to `File/sqlite-runtime`:

- `File/sqlite-runtime/win-x64/sqlite3.dll`
- `File/sqlite-runtime/linux-x64/libsqlite3.so`
- `File/sqlite-runtime/linux-x64/libsqlite3.so.0`

SQLite is in the public domain. See `https://www.sqlite.org/copyright.html`.
