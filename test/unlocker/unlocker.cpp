#pragma once

#include <stdio.h>

#include "..\..\unlocker.hpp"

#include <cstdlib>

// main
int _tmain(int argc, _TCHAR* argv[])
{
	unlocker::SetPrivilege(SE_DEBUG_NAME, TRUE);

	unlocker::File* file = unlocker::Path::Exists(_T("C:\\Users\\zhangwei01\\Desktop\\DllAgent\\x64\\Release\\x64.dll"));
	if (file) {
		file->Unlock();
		delete file;
	}

	unlocker::SetPrivilege(SE_DEBUG_NAME, FALSE);
	system("pause");
	return 0;
}
