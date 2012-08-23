## ewpcap on Windows

This document describes what tools are needed and how they should be set up to build ewpcap on Windows.

### Tools

* **MS Visual Studio C++ Express** has to be installed. The IDE will not be used, just the MS Visual Studio compiler (`cl.exe`). Version used: 10.0

* **MS Windows SDK** provides some headers and libraries. Version used: 7.1

* **Cygwin** is needed to get an usable console on Windows. The developer tools such as make and git should be included in the installation (it needs to be selected during the installation as it is not by default).

* **Erlang/OTP**'s binary package for Windows is available. Version used: R15B01

* **Git** is used for cloning rebar and ewpcap from Github.

* **Rebar** is used for compilation of ewpcap. It should not be installed at this stage!

* **WinPcap** is a dependency of ewpcap. It is a library for capturing network traffic (libpcap in Linux/UNIX). There are two types of the WinPcap for Windows:
	* driver + DLLs is the default installation of the library
	* development version - is a directory containing source files of the WinPcap library. It can be installed into `C:/WpdPack`

* **Pkt** is optional. TODO

### Installation and configuration

After all the tools are installed (apart from rebar), the `PATH`, `INCLUDE` and `LIB` variables in Cygwin must be set. The configuration of these variables may look like this (appended to the `C:/cygwin/home/user/.bashrc`):

``` shell
export VSINSTALLDIR='C:\Program Files\Microsoft Visual Studio 10.0\'
export WindowsSdkDir='C:\Program Files\Microsoft SDKs\Windows\v7.1\'
export ERLANGDIR='C:\Program Files\erl5.9.1\'
export WINPCAPDIR='C:\WpdPack\'


export VCINSTALLDIR="$VSINSTALLDIR"'VC\'
export DevEnvDir="$VSINSTALLDIR"'Common7\IDE\'

export INCLUDE="${VCINSTALLDIR}include;${WindowsSdkDir}Include;${WindowsSdkDir}Include\\gl"
export INCLUDE="${INCLUDE};${WINPCAPDIR}Include;${ERLANGDIR}erts-5.9.1\\include;${ERLANGDIR}usr\\include"
export LIB="${VCINSTALLDIR}lib;${WindowsSdkDir}Lib;${WINPCAPDIR}Lib;${ERLANGDIR}erts-5.9.1\\lib"
export LIBPATH="${LIBPATH}${VCINSTALLDIR}lib;"

c_VSINSTALLDIR=`cygpath -ua "$VSINSTALLDIR\\\\"`
c_WindowsSdkDir=`cygpath -ua "$WindowsSdkDir\\\\"`
c_ERLANGDIR=`cygpath -ua "$ERLANGDIR\\\\"`
c_WINPCAPDIR=`cygpath -ua "$WINPCAPDIR\\\\"`

export PATH="${c_WindowsSdkDir}Bin:$PATH"
export PATH="${c_WindowsSdkDir}Bin/NETFX 4.0 Tools:$PATH"
export PATH="${c_VSINSTALLDIR}VC/vcpackages:$PATH"
export PATH="${c_VSINSTALLDIR}Common7/Tools:$PATH"
export PATH="${c_VSINSTALLDIR}VC/Bin:$PATH"
export PATH="${c_VSINSTALLDIR}Common7/IDE/:$PATH"
export PATH="${c_ERLANGDIR}bin:$PATH"
```

Rebar can be downloaded using git and built with `./bootstrap` command. (`make` does not work).

### Building ewpcap

In order to build ewpcap, download it from Github and copy rebar (that was built in the previous step) to ewpcap's directory. The first line of the Makefile has to look like this:
```
REBAR=./rebar
```

It should be possible to build the project with the `make` command now.

### Using ewpcap

The tricky part on Windows is getting the names of network interfaces. The `ipconfig` command does not show the names that can be used with ewpcap. The winpcap uses its own identifiers.

Use ewpcap:getifaddrs/0 to get a list of device names that can be passed to open/1 and open/2.
