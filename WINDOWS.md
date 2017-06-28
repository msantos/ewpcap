## ewpcap on Windows

This document describes what tools are needed and how they should be set up to build ewpcap on Windows.

### Tools

* **MS Visual Studio C++ Express** has to be installed. The IDE will not be used, just the MS Visual Studio compiler (`cl.exe`). Version used: 14.0 (cl.exe version 19.00.x for x86)

* **MS Windows SDK** provides some headers and libraries. Versions used: v7.1A, v10.0A (on Win10, both versions were actually required, possibly installed at once). 


* **Cygwin** is needed to get an usable console on Windows. The developer tools such as make and git should be included in the installation (it needs to be selected during the installation as it is not by default). Alternatively, installing `git` for Windows with the optional `git-bash` can provide a minimal environment with the proper compatibility required to compile this library.

* **Erlang/OTP**'s 32-bit binary package for Windows is available. Version used: Erlang/OTP-20

* **Git** is used for cloning rebar and ewpcap from Github.

* **Rebar3** is used for compilation of ewpcap. It should not be installed at this stage!

* **WinPcap** is a dependency of ewpcap. It is a library for capturing network traffic (libpcap in Linux/UNIX). There are two types of the WinPcap for Windows:
	* driver + DLLs is the default installation of the library. Usually installed in `C:/Program Files (x86)/WinPcap/`
	* development version - is a directory containing source files of the WinPcap library. It can be installed into `C:/WpdPack`, or the development headers could be added to the actual install.

* **Pkt** is optional, but useful to decode actual packets returned by a packet capture.

### Installation and configuration

After all the tools are installed (apart from rebar), the `PATH`, `INCLUDE` and `LIB` variables in Cygwin must be set. The configuration of these variables may look like this (appended to the `C:/cygwin/home/user/.bashrc`, or just `C:/Users/<user>/.bashrc` if using git-bash):

```shell
export VSINSTALLDIR='C:\Program Files (x86)\Microsoft Visual Studio 14.0\'      # path to Visual studio
export WindowsSdkDir='C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\'    # path to v10.0A SDK for headers
export WindowsSdkDirOld='C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\'  # path to V7.1A SDK for headers
export WindowsKitDir='C:\Program Files (x86)\Windows Kits\10\'                  # path to Windows kit for further headers and libs
export WindowsKitDirIncl="${WindowsKitDir}"'Include\10.0.14393.0\'              # newest version for includes in kits
export WindowsKitLibUm="${WindowsKitDir}"'Lib\10.0.14393.0\um\x86'              # windows kit libraries
export WindowsKitLibUcrt="${WindowsKitDir}"'Lib\10.0.14393.0\ucrt\x86'          # windows kit libraries
export ERLANGDIR='C:\Program Files (x86)\erl-9.0\'                              # path to Erlang install
export WINPCAPDIR='C:\WpdPack\'                                                 # path to WinPcap
export ERTSVSN='erts-9.0'                                                       # Version of the Erlang runtime system (to find C headers)

export VCINSTALLDIR="$VSINSTALLDIR"'VC\'
export DevEnvDir="$VSINSTALLDIR"'Common7\IDE\'

export INCLUDE="${VCINSTALLDIR}include;${WindowsSdkDir}Include;${WindowsSdkDir}Include\\gl;${WindowsSdkDirOld}Include;${WindowsSdkDirOld}Include\\gl"
export INCLUDE="${INCLUDE};${WindowsKitDir}Include;${WindowsKitDirIncl};${WindowsKitDirIncl}\\shared;${WindowsKitDirIncl}\\ucrt;${WindowsKitDirIncl}\\um"
export INCLUDE="${INCLUDE};${WINPCAPDIR}Include;${ERLANGDIR}{$ERTSVSN}\\include;${ERLANGDIR}usr\\include"
export LIB="${VCINSTALLDIR}lib;${WindowsSdkDir}Lib;${WINPCAPDIR}Lib;${ERLANGDIR}{$ERTSVSN}\\lib"
export LIBPATH="${LIBPATH}${VCINSTALLDIR}lib;${WindowsKitLib}"

#convert paths
c_VSINSTALLDIR=`cygpath -ua "$VSINSTALLDIR\\\\"`
c_WindowsSdkDir=`cygpath -ua "$WindowsSdkDir\\\\"`
c_WindowsSdkDirOld=`cygpath -ua "$WindowsSdkDirOld\\\\"`
c_WindowsKitDir=`cygpath -ua "$WindowsKitDir\\\\"`
c_ERLANGDIR=`cygpath -ua "$ERLANGDIR\\\\"`
c_WINPCAPDIR=`cygpath -ua "$WINPCAPDIR\\\\"`

export PATH="${c_WindowsKitir}Bin:$PATH"
export PATH="${c_WindowsSdkDir}Bin:$PATH"
export PATH="${c_WindowsSdkDirOld}Bin:$PATH"
export PATH="${c_WindowsSdkDir}Bin/NETFX 4.6.2 Tools:$PATH"
export PATH="${c_VSINSTALLDIR}VC/vcpackages:$PATH"
export PATH="${c_VSINSTALLDIR}Common7/Tools:$PATH"
export PATH="${c_VSINSTALLDIR}VC/Bin:$PATH"
export PATH="${c_VSINSTALLDIR}Common7/IDE/:$PATH"
export PATH="${c_ERLANGDIR}bin:$PATH"
```

Rebar can be downloaded using git and built with `./bootstrap` command. (`make` does not work).

### Building ewpcap

ewpcap can be compiled by calling `rebar3 compile`.

For an environment using makefiles, download ewpcap from Github and copy rebar3 (that was built in the previous step) to ewpcap's directory. The first line of the Makefile has to look like this:

```
REBAR=./rebar3 compile
```

It should be possible to build the project with the `make` command now.


### Using ewpcap

The tricky part on Windows is getting the names of network interfaces. The `ipconfig` command does not show the names that can be used with ewpcap. The winpcap uses its own identifiers.

Use ewpcap:getifaddrs/0 to get a list of device names that can be passed to open/1 and open/2.
