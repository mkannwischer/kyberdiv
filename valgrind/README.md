To use our valgrind patch, you'll have to re-compile valgrind following these steps:

- Download and unpack Valgrind version VALGRIND_3_22_0


```
git clone https://sourceware.org/git/valgrind.git
cd valgrind
git checkout VALGRIND_3_22_0
```
- Apply the patch
```
  `patch -p1 <`_path-to_`/valgrind-3.22.0-varlat.patch`
	```

- Build and install Valgrind, per instructions in Valgrind's own `README` file.  Some additional tips:
  - `./configure --help` should give further options on how to build Valgrind.
  - To cross-compile for a Linux/AArch64 host, try to specify a `--host=` option, e.g. `--host=aarch64-linux-gnu`.

- You can now run a chosen program under Valgrind.  The program to be run under Valgrind should contain an invocation to `VALGRIND_ENABLE_TIMECOP_MODE;` to enable the variable-latency instruction checks.
