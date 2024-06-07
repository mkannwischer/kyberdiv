* Download and unpack Valgrind 3.22.0.
* Apply the patch.
  * `cd` _path-to_`/valgrind-3.22.0`
  * `patch -p1 <`_path-to_`/valgrind-3.22.0-varlat.patch`
* Build and install Valgrind, per instructions in Valgrind's own `README` file.  Some additional tips:
  * `./configure --help` should give further options on how to build Valgrind.
  * To cross-compile for a Linux/AArch64 host, try to specify a `--host=` option, e.g. `--host=aarch64-linux-gnu`.
* You can now run a chosen program under Valgrind.  The program to be run under Valgrind should contain an invocation to `VALGRIND_ENABLE_TIMECOP_MODE;` to enable the variable-latency instruction checks.
