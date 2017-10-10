# What is unlocker?

A head-only, fast, simple Ring3 unlocker library. 

Salute to Cedrick Collomb's famous tool - unlocker.

## Advantanges

* **[UNIQUE] support operations on unacceptable-name files** ([reserved names or name ends with a period or a space](https://msdn.microsoft.com/en-us/aa365247(VS.85).aspx#naming_conventions))
* **[UNIQUE] support detection of opened memory-mapping-file (abbr as mmf) handle and map view of mmf**
	* MS Office compatible mode (e.g. \*.doc, \*.xls, \*.ppt opened by MS Office 2007+)
	* file copy by explorer.exe
	* etc.
* low resource comsuption & quick scan improvement
    * hang-up handle check without creating a mount of threads ([Robert Simpson's answer at stackoverflow.com](http://stackoverflow.com/questions/16127948/hang-on-ntquerysysteminformation-in-winxpx32-but-works-fine-in-win7x64))
* support operating files in UNC/Network drive
* [:cross mark:] support terminate some of the protected Ring3 processes
* [:cross mark:] support all version of Visual C++ or Visual Studio (both UNICODE & non-UNICODE projects)
* [:cross mark:] support all version of OSs

## How it works?

#### Type of files
- Normal files: text files, image files, binary files and etc.
- Executable files: exe, dll, sys

File Type |Method | Unlock Solution
---|---|---
* | CreateFile | RemoteCloseHandle
* | CreateFileMapping | RemoteCloseHandle
* | MapViewOfFile | RemoteUnmapViewOfFile
exe | CreateProcess | TerminateProcess
dll | LoadLibrary | RemoteFreeLibrary
sys | CreateService/StartService | StopService/DeleteService

## Feedback

* email : [orca.zhang@yahoo.com](mailto:orca.zhang@yahoo.com)
* wechat : zw198932

## References
Thanks to following projects, in no particular order

* [宇文莺语 (wang huan)](https://code.csdn.net/snippets/713440/)

## About author

```javascript
  var orca = {
    name  : "Zhang Wei",
    site : "http://ez8.co"
  }
```