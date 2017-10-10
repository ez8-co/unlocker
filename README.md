## What is unlocker?

A head-only, fast, simple Ring3 unlocker library. 

Salute to Cedrick Collomb's famous tool - unlocker.

## Advantanges

* support operations on unacceptable-name files ([reserved names or name ends with a period or a space](https://msdn.microsoft.com/en-us/aa365247(VS.85).aspx#naming_conventions))
* low resource comsuption & quick scan improvement
    * hang-up handle check without creating a mount of threads ([Robert Simpson's answer at stackoverflow.com](http://stackoverflow.com/questions/16127948/hang-on-ntquerysysteminformation-in-winxpx32-but-works-fine-in-win7x64))
* support detection of opened memory-mapping-file (abbr as mmf) handle and map view of mmf
	* MS Office compatible mode (e.g. \*.doc, \*.xls, \*.ppt opened by MS Office 2007+)
	* file copy by explorer.exe
	* etc.
* support operate files in UNC/Network drive
* [NOT READY YET] support terminate some of the protected Ring3 processes
* [NOT READY YET] support all version of Visual C++ or Visual Studio (both UNICODE & non-UNICODE projects)
* [NOT READY YET] support all version of OSs

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