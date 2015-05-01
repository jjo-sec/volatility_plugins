# volatility_plugins
Volatility Plugins

A collection of plugs for the [Volatility](https://github.com/volatilityfoundation/volatility) framework that I have
authored or made significant contributions to.

The PlugX configuration extraction is a fork and update of the plugin located at http://bitbucket.cassidiancybersecurity.com/volatility_plugins/wiki/Home

with more configuration sizes supported and moving to ctypes Structure for parsing of the configuration blob.

The Andromeda configuration extraction plugin will attempt to locate and extract C2 URLs, RC4 key used for initial communication,
and parameters in the phone-home format string

# Install

The andromeda plugin requires PyCrypto and [Yara](http://plusvic.github.io/yara/) python module to be installed. Manual installation of yara is recommended to obtain the latest release, instructions are available on the Yara site.

* On Debian-based systems these modules can be installed via

    $ apt-get install python-crypto python-yara

* PyCrypto can also be installed via pip

    $ sudo pip install pycrypto

The andromeda plugin also requires [Capstone](http://capstone-engine.org) to be installed.

* On *nix (including Mac OS X, Linux, BSD, etc), do this with:

    $ sudo pip install capstone

* On Windows, there are 2 choices:

  * Download & install Python binary package from [Capstone homepage](http://capstone-engine.org/download.html)
  * Download PyPi package [capstone-windows](https://pypi.python.org/pypi/capstone-windows), then unzip & install from commandline with:

    `python setup.py install`

# Usage

To search for and print out Andromeda configuration:

    $ python vol.py -f memory.dmp andromeda
    Volatility Foundation Volatility Framework 2.4
    Andromeda Config Located
      Process msiexec.exe (PID: 2952, VAD: 0x7ff90000)
      	Bb: 0
      	Url: hxxp://andromeda-hostname[.]com/andromeda-path.php
      	Bid: 9
      	Fmt Str: {"id":%lu,"bid":%lu,"os":%lu,"la":%lu,"rg":%lu,"bb":%lu
      	Rg: 1
      	Key: f5d0e0420865071a12c22a84702daca3
      	Os: 351
      	Id: 2cae84cd

The usage for the modified PlugX plugin has not changed, but the naming for the new versions is slightly different than the original. These will be unified at a later date.

    $ python vol.py -f memory.dmp plugxconfig

    Process: iexplore.exe (3044)

    PlugX Config (0x2d58 bytes):
    	Hide Dll: -1
    	Keylogger: -1
    	Sleep1: 167772160
    	Sleep2: 0
    	Cnc: plugx[.]cnc:53 (TCP / HTTP / UDP / ICMP / DNS)
    	Cnc: plugx[.]cnc:80 (TCP / HTTP / UDP / ICMP / DNS)
    	Cnc: plugx[.]cnc:53 (TCP / HTTP / UDP / ICMP / DNS)
    	Cnc: plugx[.]cnc:80 (TCP / HTTP / UDP / ICMP / DNS)
    	Persistence: None
    	Install Folder: %APPDATA%
    	Reg Hive: Unknown
    	Injection: 0
    	Inject Process: %ProgramFiles%\Internet Explorer\iexplore.exe
    	Inject Process: %windir%\system32\svchost.exe
    	Inject Process: %ProgramFiles%\Internet Explorer\iexplore.exe
    	Inject Process: %windir%\system32\svchost.exe
    	Uac Bypass Injection: 0
    	Plugx Auth Str: admin#@1
    	Cnc Auth Str: message4
    	Mutex: g1bsTj
    	Screenshots: 1
    	Screenshots Sec: 0
    	Screenshots Zoom: 0
    	Screenshots Bits: 0
    	Screenshots Qual: 0
    	Screenshots Keep: 0
    	Lateral Tcp Enabled: 1
    	Lateral Tcp Port: 535
    	Lateral Udp Enabled: 1
    	Lateral Udp Port: 535
    	Lateral Unk Enabled: 1
    	Lateral Unk Port: 535
    	Unk 2D4C: 0
    	Unk 2D50: 0
    	Unk 2D58: 0
