/*
  unlocker -- A header-only, fast, simple unlocker library under Ring3 for Windows.

  Copyright (c) 2010-2017 <http://ez8.co> <orca.zhang@yahoo.com>
  This library is released under the MIT License.

  Please see LICENSE file or visit https://github.com/ez8-co/unlocker for details.
*/
#pragma once

#include <tchar.h>
#include <windows.h>

#include <vector>
#include <map>
#include <list>
using namespace std;

#include <string>
typedef std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR> > tstring;

#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#define STATUS_SUCCESS				((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH	((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW		((NTSTATUS)0x80000005L)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)			(((NTSTATUS)(Status)) >= 0)
#endif

namespace unlocker {
	
	template<typename T = HANDLE, BOOL (__stdcall *Closer)(T) = CloseHandle>
	class SmartHandleTmpl
	{
		SmartHandleTmpl(const SmartHandleTmpl&);
		SmartHandleTmpl& operator=(const SmartHandleTmpl&);

	public:
		SmartHandleTmpl(T handle = NULL) : _handle(handle) {}
		~SmartHandleTmpl() {
			if (_handle) Closer(_handle);
		}

		operator T() const {return _handle;}
		template<typename F>
		operator F*() const {return (F*)_handle;}
		T* operator&() {return &_handle;}
		T operator=(T handle) {
			if (_handle) Closer(_handle);
			return _handle = handle;
		}

	private:
		T _handle;
	};

	typedef SmartHandleTmpl<> SmartHandle;

	BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
	{
		SmartHandle hToken;
		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
		LUID luid;
		if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) return FALSE;
		TOKEN_PRIVILEGES tp = {1, {luid, bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0}};
		AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES) NULL, 0); 
		return (GetLastError() == ERROR_SUCCESS);
	}

	class File;

	class Path
	{
	public:
		Path(const tstring& path) : _path() {
			if(path.length() > 2 && !_tcsnicmp(path.c_str(), _T("\\\\"), 2))
				_path = path;
			else {
				_path = _T("\\\\?\\");
				_path += path;
			}
		}
		static tstring Combine(const tstring& prefix, const tstring& path) {
			tstring ret(prefix);
			ret += '\\';
			tstring::size_type pos = path.find_first_not_of('\\');
			if(pos != tstring::npos) {
				ret.append(path, pos, path.length() - pos);
			}
			return ret;
		}
		const TCHAR* GetDevicePath() const { return &_path[0]; }
		operator tstring() const { return _path.substr(4, _path.length() - 4); }
		operator const TCHAR*() const { return &_path[4]; }

		static File* Exists(const tstring& path);

		static BOOL Contains(const tstring& path, const tstring& sub_path) {
			return path.length() <= sub_path.length()
				&& !_tcsnicmp(path.c_str(), sub_path.c_str(), path.length())
				&& (path.length() == sub_path.length() || path[path.length() - 1] == '\\' || sub_path[path.length()] == '\\');
		}

	private:
		tstring _path;
	};

	namespace {
		BOOL UnholdFile(const tstring& path);
	}

	class File
	{
	public:
		File(const tstring& path) : _path(path) {}
		virtual operator Path() const { return _path; }
		virtual const TCHAR* GetDevicePath() const { return _path.GetDevicePath(); }
		virtual BOOL Unlock() { 
			return UnholdFile(_path);
		}
		virtual BOOL ForceDelete() {
			return Delete() || (Unlock() && Delete());
		}
		virtual BOOL Delete() {
			SetFileAttributes(_path, FILE_ATTRIBUTE_NORMAL);
			return DeleteFile(_path);
		}

	protected:
		Path _path;
	};

	class Dir : public File
	{
	public:
		Dir(const tstring& path) : File((!path.empty() && path[path.length() - 1] == '\\') ? path.substr(0, path.length() - 1) : path) {}
		virtual BOOL Delete() {
			list<Dir> dirs;
			dirs.push_back(Dir(_path));
			while (!dirs.empty()) {
				Path dir(dirs.front());
				WIN32_FIND_DATA fd;
				SmartHandleTmpl<HANDLE, FindClose> hSearch = FindFirstFile(Path::Combine(dir.GetDevicePath(), _T("*")).c_str(), &fd);
				if (hSearch == INVALID_HANDLE_VALUE) // try to examine root directory
					hSearch = FindFirstFile(Path::Combine(dir, _T("*")).c_str(), &fd);
				if (hSearch != INVALID_HANDLE_VALUE) {
					INT subDirCnt = 0;
					do {
						if (!_tcscmp(fd.cFileName, _T(".")) || !_tcscmp(fd.cFileName, _T("..")))
							continue;
						else if(fd.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY)) {
							++subDirCnt;
							dirs.push_front(Dir(Path::Combine(dir, fd.cFileName)));
						}
						else {
							if (!File(Path::Combine(dir, fd.cFileName)).Delete())
								return FALSE;
						}
					} while (FindNextFile(hSearch, &fd) || GetLastError() != ERROR_NO_MORE_FILES);
					if (!subDirCnt) {
						if (!Dir(dir).DeleteDir())
							return FALSE;
						dirs.pop_front();
					}
				}
				else
					return FALSE;
			}
			return TRUE;
		}
		BOOL DeleteDir() {
			// add backslash for unacceptable-name files
			tstring path(Path::Combine(_path.GetDevicePath(), _T("")));
			SetFileAttributes(path.c_str(), FILE_ATTRIBUTE_NORMAL);
			return RemoveDirectory(path.c_str());
		}
	};

	File* Path::Exists(const tstring& path) {
		Path filePath(path);
		WIN32_FIND_DATA fd;
		SmartHandleTmpl<HANDLE, FindClose> hSearch = FindFirstFile(filePath.GetDevicePath(), &fd);
		if (hSearch == INVALID_HANDLE_VALUE) // try to examine root directory
			hSearch = FindFirstFile(filePath, &fd);
		if (hSearch != INVALID_HANDLE_VALUE)
			if (fd.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY))
				return new Dir(filePath);
			else
				return new File(filePath);
		return NULL;
	}

	namespace {
		typedef struct _UNICODE_STRING {
			WORD  Length;
			WORD  MaximumLength;
			PWSTR Buffer;
		} UNICODE_STRING;

		typedef struct _OBJECT_NAME_INFORMATION {
			UNICODE_STRING Name;
			WCHAR NameBuffer[1];
		} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

		typedef enum _OBJECT_INFORMATION_CLASS {
			ObjectNameInformation = 1,
			ObjectTypeInformation = 2,
		} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

		typedef enum _POOL_TYPE {
			NonPagedPool,
			// omit unused enumerations
		} POOL_TYPE, *PPOOL_TYPE;

		typedef struct _OBJECT_TYPE_INFORMATION {
			UNICODE_STRING Name;
			// omit unused members
		} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

		typedef NTSTATUS (WINAPI *NT_QUERY_OBJECT)(
			IN HANDLE Handle OPTIONAL,
			IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
			OUT PVOID ObjectInformation OPTIONAL,
			IN ULONG ObjectInformationLength,
			OUT PULONG ReturnLength OPTIONAL);

		typedef struct _SYSTEM_HANDLE {
			HANDLE ProcessId;
			BYTE ObjectType;
			BYTE Flags;
			WORD Handle;
			PVOID Address;
			DWORD GrantedAccess;
		} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

		typedef struct _SYSTEM_HANDLE_INFORMATION {
			DWORD HandleCount;
			SYSTEM_HANDLE Handles[1];
		} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

		typedef struct _SYSTEM_HANDLE_EX {
			PVOID Object;
			HANDLE ProcessId;
			HANDLE Handle;
			ULONG GrantedAccess;
			USHORT CreatorBackTraceIndex;
			USHORT ObjectTypeIndex;
			ULONG HandleAttributes;
			ULONG Reserved;
		} SYSTEM_HANDLE_EX, *PSYSTEM_HANDLE_EX;

		typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
			ULONG_PTR HandleCount;
			ULONG_PTR Reserved;
			SYSTEM_HANDLE_EX Handles[1];
		} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

		typedef enum _SYSTEM_INFORMATION_CLASS {
			SystemHandleInformation = 16,
			SystemHandleInformationEx = 64,
		} SYSTEM_INFORMATION_CLASS;

		typedef NTSTATUS (WINAPI *NT_QUERY_SYSTEM_INFORMATION)(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			OUT PVOID  SystemInformation,
			IN ULONG   SystemInformationLength,
			OUT PULONG ReturnLength OPTIONAL);

		typedef enum _SECTION_INFORMATION_CLASS {
			SectionBasicInformation = 0,
		} SECTION_INFORMATION_CLASS;

		typedef struct _SECTION_BASIC_INFORMATION {
			ULONG			SectionBaseAddress;
			ULONG			SectionAttributes;
			LARGE_INTEGER	SectionSize;
		} SECTION_BASIC_INFORMATION;

		typedef NTSTATUS (WINAPI *NT_QUERY_SECTION)(
			IN HANDLE	SectionHandle,
			IN SECTION_INFORMATION_CLASS	InformationClass,
			OUT PVOID	InformationBuffer,
			IN ULONG	InformationBufferSize,
			OUT PULONG	ResultLength OPTIONAL );

		typedef NTSTATUS (WINAPI *NT_QUERY_SYSTEM_INFORMATION)(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			OUT PVOID  SystemInformation,
			IN ULONG   SystemInformationLength,
			OUT PULONG ReturnLength OPTIONAL);

		static NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation = (NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandle (_T("ntdll")), "NtQuerySystemInformation");
		static NT_QUERY_OBJECT NtQueryObject = (NT_QUERY_OBJECT)GetProcAddress(GetModuleHandle (_T("ntdll")), "NtQueryObject");
		static NT_QUERY_SECTION NtQuerySection = (NT_QUERY_SECTION)GetProcAddress(GetModuleHandle (_T("ntdll")), "NtQuerySection");
		static HMODULE hKernel32 = LoadLibrary(_T("kernel32.dll"));

		typedef struct _HOLDER_INFO {
			vector<HANDLE> openHandles;
			vector<HANDLE> mmfSections;
		} HOLDER_INFO;

		void GetDeviceDriveMap(map<tstring, tstring>& pathMapping)
		{
			DWORD driveMask = GetLogicalDrives();
			TCHAR drivePath[_MAX_DRIVE] = _T("A:");

			while (driveMask) {
				if (driveMask & 1) {
					TCHAR devicePath[_MAX_PATH] = {0};
					if (QueryDosDevice(drivePath, devicePath, _MAX_PATH)) {
						// UNC or Network drive
						if (GetDriveType(drivePath) == DRIVE_REMOTE) {
							// \Device\HGFS\;z:0000000000010289\vmware-host\Shared Folders -> \Device\HGFS\vmware-host\Shared Folders
							TCHAR *pos = devicePath;
							UCHAR count = 3;
							do {
								if (*pos == '\\' && !--count) {
									count = pos - devicePath;
									while (*++pos && *pos != '\\');
									while (devicePath[++count] = *++pos);
									break;
								}
							} while (*pos++);
						}
						pathMapping[devicePath] = drivePath;
					}
				}
				driveMask >>= 1;
				++drivePath[0];
			}
		}

		BOOL DevicePathToDrivePath(tstring& path)
		{
			static map<tstring, tstring> pathMapping;
			if (pathMapping.empty()) GetDeviceDriveMap(pathMapping);

			if (path.empty()) return TRUE;

			if (!_tcsnicmp(path.c_str(), _T("\\SystemRoot"), 11)) {
				TCHAR windowsRoot[_MAX_PATH] = {0};
				GetWindowsDirectory(windowsRoot, sizeof(windowsRoot));
				path.replace(0, 11, windowsRoot);
				return TRUE;
			}
			else if (!_tcsnicmp(path.c_str(), _T("\\??\\"), 4)) {
				path.erase(0, 4);
				return TRUE;
			}
			for (map<tstring, tstring>::const_iterator it=pathMapping.begin(); it!=pathMapping.end(); ++it) {
				if (!_tcsnicmp(path.c_str(), it->first.c_str(), it->first.length())) {
					path.replace(0, it->first.length(), it->second);
					return TRUE;
				}
			}
			return FALSE;
		}

		BOOL GetHandlePath(HANDLE handle, tstring& path)
		{
			if (!NtQueryObject) return FALSE;

			DWORD dwLength = 0;
			OBJECT_NAME_INFORMATION info = {0};
			NTSTATUS status = NtQueryObject(handle, ObjectNameInformation, &info, sizeof (info), &dwLength);
			if (status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW && status != STATUS_INFO_LENGTH_MISMATCH) {
				return FALSE;
			}

			POBJECT_NAME_INFORMATION pInfo = (POBJECT_NAME_INFORMATION)malloc(dwLength);
			while (true) {
				status = NtQueryObject (handle, ObjectNameInformation, pInfo, dwLength, &dwLength);
				if (status != STATUS_BUFFER_OVERFLOW && status != STATUS_INFO_LENGTH_MISMATCH) {
					break;
				}
				pInfo = (POBJECT_NAME_INFORMATION)realloc(pInfo, dwLength);
			}

			BOOL bRet = FALSE;
			if (NT_SUCCESS(status)) {
				path = pInfo->Name.Buffer ? pInfo->Name.Buffer : _T("");
				bRet = DevicePathToDrivePath(path);
			}

			free(pInfo);
			return bRet;
		}

		template<typename SYS_HADNLE_INFO_TYPE, SYSTEM_INFORMATION_CLASS sys_info_class>
		SYS_HADNLE_INFO_TYPE* GetSystemHandleInfo()
		{
			if (!NtQuerySystemInformation) return NULL;

			DWORD dwLength = 0;
			SYS_HADNLE_INFO_TYPE shi = {0};
			NTSTATUS status = NtQuerySystemInformation(sys_info_class, &shi, sizeof (shi), &dwLength);
			if (status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW && status != STATUS_INFO_LENGTH_MISMATCH) {
				return NULL;
			}

			SYS_HADNLE_INFO_TYPE* pshi = (SYS_HADNLE_INFO_TYPE*)malloc(dwLength);
			while (true) {
				status = NtQuerySystemInformation (sys_info_class, pshi, dwLength, &dwLength);
				if (status != STATUS_BUFFER_OVERFLOW && status != STATUS_INFO_LENGTH_MISMATCH) {
					break;
				}
				pshi = (SYS_HADNLE_INFO_TYPE*)realloc(pshi, dwLength);
			}

			if (!NT_SUCCESS (status)) {
				free (pshi);
				pshi = NULL;
			}

			return pshi;
		}

		// IsDeviceHandle 
		// e.g. \Device\Afd, \Device\Beep, \Device\KsecDD, \Device\NamedPipe\XXXX, \Device\WMIDataDevice, \Device\Null
		// thanks to Robert Simpson <http://stackoverflow.com/questions/16127948/hang-on-ntquerysysteminformation-in-winxpx32-but-works-fine-in-win7x64>
		BOOL IsDeviceHandle(HANDLE handle)
		{
			SmartHandle hMapFile = CreateFileMapping(handle, NULL, PAGE_READONLY, 0, 0, NULL);
			return !hMapFile && GetLastError() == ERROR_BAD_EXE_FORMAT;
		}

		// FindFileHandleHolders
		template<typename SYS_HADNLE_INFO_TYPE, SYSTEM_INFORMATION_CLASS sys_info_class>
		BOOL FindFileHandleHolders(LPCTSTR path, map<DWORD, HOLDER_INFO>& holders)
		{
			holders.clear ();

			if (!path || !NtQueryObject || !NtQuerySection) return FALSE;

			SYS_HADNLE_INFO_TYPE* pshi = GetSystemHandleInfo<SYS_HADNLE_INFO_TYPE, sys_info_class> ();
			if (!pshi) return FALSE;

			HANDLE hCrtProc = GetCurrentProcess ();
			for (ULONG_PTR i = 0; i < pshi->HandleCount; ++i) {
				// duplicate handle
				SmartHandle hDupHandle;
				SmartHandle hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pshi->Handles[i].ProcessId);
				if (!hProcess || !DuplicateHandle(hProcess, (HANDLE)pshi->Handles[i].Handle, hCrtProc, &hDupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
					continue;

				// filter out device handle (some of them may cause NtQueryObject hang up, e.g. some pipe handle)
				if (IsDeviceHandle(hDupHandle))
					continue;

				// filter out non-file or non-section handle (identify by ObjectIndex is not correct)
				POBJECT_TYPE_INFORMATION poti = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
				NTSTATUS status = NtQueryObject(hDupHandle, ObjectTypeInformation, poti, 0x1000, NULL);
				if (NT_SUCCESS(status)) {
					if (!_wcsicmp(poti->Name.Buffer, L"File")) {
						tstring filePath;
						if (GetHandlePath(hDupHandle, filePath) && Path::Contains(path, filePath.c_str()))
							holders[(DWORD)pshi->Handles[i].ProcessId].openHandles.push_back((HANDLE)pshi->Handles[i].Handle);
					}
					else if (!_wcsicmp(poti->Name.Buffer, L"Section")) {
						SECTION_BASIC_INFORMATION sbi = {};
						if (NT_SUCCESS(NtQuerySection(hDupHandle, SectionBasicInformation, &sbi, sizeof(sbi), 0)) && sbi.SectionAttributes == SEC_FILE)
							holders[(DWORD)pshi->Handles[i].ProcessId].mmfSections.push_back((HANDLE)pshi->Handles[i].Handle);
					}
				}
				free(poti);
			}

			free(pshi);
			return TRUE;
		}

		BOOL CloseRemoteHandle(HANDLE hProcess, HANDLE hHandle)
		{
			SmartHandle hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "CloseHandle"), hHandle, 0, NULL);
			if (!hThread) return FALSE;
			return WaitForSingleObject(hThread, 1000) == WAIT_OBJECT_0;
		}

		BOOL CloseHandleWithProcess(DWORD dwProcessId, HANDLE hHandle)
		{
			SmartHandle hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId);
			if (hProcess) {
				SmartHandle hDup;
				if (DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &hDup, DUPLICATE_SAME_ACCESS, FALSE, DUPLICATE_CLOSE_SOURCE) && hDup)
					return TRUE;
			}
			return FALSE;
		}

		BOOL RemoteFreeLibrary(HANDLE hProcess, LPTSTR lpszDllName)
		{
			DWORD dwSize = (lstrlen(lpszDllName) + 1) * sizeof(TCHAR), dwWritten = 0;
			LPVOID lpBuf = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
			if (!lpBuf) return FALSE;
			if (!WriteProcessMemory(hProcess, lpBuf, lpszDllName, dwSize, &dwWritten))
				return FALSE;
			if (dwWritten != dwSize) {
				VirtualFreeEx(hProcess, lpBuf, dwSize, MEM_DECOMMIT);
				return FALSE;
			}
			SmartHandle hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, 
	#ifdef UNICODE
				"GetModuleHandleW"
	#else
				"GetModuleHandleA"
	#endif // !UNICODE
				), lpBuf, 0, NULL);
			if (!hThread) return FALSE;
			WaitForSingleObject(hThread, 1000);
			DWORD dwRet = 0;
			GetExitCodeThread(hThread, &dwRet);
			VirtualFreeEx(hProcess, lpBuf, dwSize, MEM_DECOMMIT);

			hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, 
	#ifdef UNICODE
				"FreeLibraryW"
	#else
				"FreeLibraryA"
	#endif // !UNICODE
				), NULL, 0, NULL);
			WaitForSingleObject(hThread, 1000);
			GetExitCodeThread(hThread, &dwRet);
			return (dwRet == ERROR_SUCCESS);
		}

		BOOL RemoteUnmapViewOfFile(HANDLE hProcess, LPVOID lpBaseAddress)
		{
			SmartHandle hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "UnmapViewOfFile"), lpBaseAddress, 0, NULL);
			if (!hThread) return FALSE;
			WaitForSingleObject(hThread, 1000);
			DWORD dwRet = 0;
			GetExitCodeThread(hThread, &dwRet);
			return (dwRet == ERROR_SUCCESS);
		}

		BOOL CloseMapViewOfFile(HANDLE hProcess, LPCTSTR path)
		{
			BOOL isWow64 = FALSE;
			IsWow64Process(hProcess, &isWow64);

			SYSTEM_INFO systemInfo = {0};
			GetNativeSystemInfo(&systemInfo);

			// Windows 32bit limit: 0xFFFFFFFF.
			// Windows 64bit limit: 0x7FFFFFFFFFF.
			unsigned long long maxAddress = (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 && !isWow64) ? 0x80000000000 : 0x100000000;

			MEMORY_BASIC_INFORMATION mbi = { 0 }, mbiLast = { 0 };
			BOOL found = FALSE;
			for (unsigned long long address = 0; address < maxAddress; address += mbi.RegionSize) {
				if (!VirtualQueryEx(hProcess, (void*)address, &mbi, sizeof(mbi))) break;
				if ((unsigned long long)mbi.AllocationBase + mbi.RegionSize > maxAddress) break;

				if (mbi.Type == MEM_MAPPED) {
					if (mbiLast.AllocationBase != mbi.AllocationBase) {
						tstring filepath(MAX_PATH, '\0');
						filepath.resize(GetMappedFileName(hProcess, mbi.BaseAddress, &filepath[0], filepath.size()));
						DevicePathToDrivePath(filepath);
						if (!filepath.empty() && Path::Contains(path, filepath.c_str())) {
							RemoteUnmapViewOfFile(hProcess, mbi.BaseAddress);
							found = TRUE;
						}
					}
					mbiLast = mbi;
				}
			}
			return found;
		}

		typedef enum FILE_TYPE
		{
			UNKNOWN_FILE,
			NORMAL_FILE,
			EXE_FILE,
			DLL_FILE
		};

		FILE_TYPE CheckFileType(const tstring& path)
		{
			SmartHandle hFile = CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE)
				return UNKNOWN_FILE;

			if ((hFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL)) == INVALID_HANDLE_VALUE)
				return UNKNOWN_FILE;

			SmartHandleTmpl<LPCVOID, UnmapViewOfFile> pvMem = MapViewOfFile(hFile, FILE_MAP_READ, 0, 0, 0);
			if (!pvMem || *(USHORT*)pvMem != IMAGE_DOS_SIGNATURE
				|| *((DWORD*)((PBYTE)pvMem + ((PIMAGE_DOS_HEADER)pvMem)->e_lfanew)) != IMAGE_NT_SIGNATURE)
				return NORMAL_FILE;

			return (((PIMAGE_FILE_HEADER)(PBYTE)pvMem + ((PIMAGE_DOS_HEADER)pvMem)->e_lfanew + sizeof(DWORD))->Characteristics
				& IMAGE_FILE_DLL) ? DLL_FILE : EXE_FILE;
		}

		BOOL UnholdFile(const tstring& path)
		{
			map<DWORD, HOLDER_INFO> holders;
			if (!FindFileHandleHolders<SYSTEM_HANDLE_INFORMATION_EX, SystemHandleInformationEx>(path.c_str(), holders))
				if (!FindFileHandleHolders<SYSTEM_HANDLE_INFORMATION, SystemHandleInformation>(path.c_str(), holders))
					return FALSE;
			for (map<DWORD, HOLDER_INFO>::const_iterator it=holders.begin(); it!=holders.end(); ++it) {
				SmartHandle hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, it->first);
				tstring holderPath(MAX_PATH, '\0');
				holderPath.resize(GetProcessImageFileName(hProcess, &holderPath[0], holderPath.size()));
				DevicePathToDrivePath(holderPath);
				if (CloseMapViewOfFile(hProcess, path.c_str())) {
					// check memory-mapping file handle in mmfSections
					for (vector<HANDLE>::const_iterator i=it->second.mmfSections.begin(); i!=it->second.mmfSections.end(); ++i) {
						SmartHandle hDupHandle;
						if (!DuplicateHandle(hProcess, *i, GetCurrentProcess(), &hDupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
							continue;
						// try MapViewOfFile on Handle
						LPVOID p = MapViewOfFile(hDupHandle, FILE_MAP_READ, 0, 0, 1);
						if (!p)
							continue;
						if (CloseMapViewOfFile(GetCurrentProcess(), path.c_str())) {
							// if specific file occurred, close this handle
							tstring mmfPath;
							GetHandlePath(hDupHandle, mmfPath);
							BOOL b = CloseHandleWithProcess(it->first, *i);//CloseRemoteHandle(hProcess, *i);
							_tprintf_s(_T("%s [%u](0x%X) <mmf:%s> %s\n"), b ? _T("OK") : _T("FAIL"), it->first, *i, mmfPath.c_str(), holderPath.c_str());
						}
						else
							// UnmapViewOfFile
							UnmapViewOfFile(p);
					}
				}
				for (vector<HANDLE>::const_iterator i=it->second.openHandles.begin(); i!=it->second.openHandles.end(); ++i) {
					BOOL b = CloseHandleWithProcess(it->first, *i);//CloseRemoteHandle(hProcess, *i);
					_tprintf_s(_T("%s [%u](0x%X) %s\n"), b ? _T("OK") : _T("FAIL"), it->first, *i, holderPath.c_str());
				}
			}
		}
	}
};
