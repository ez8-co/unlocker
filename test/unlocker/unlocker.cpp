#pragma once

#include <stdio.h>

#include "..\..\unlocker.hpp"

#include <cstdlib>

// main
int _tmain(int argc, _TCHAR* argv[])
{
	unlocker::SetPrivilege(SE_DEBUG_NAME, TRUE);

	unlocker::File* file = unlocker::Path::Exists(_T("f:\\a.xls"));
	if (file) {
		file->ForceDelete();
		delete file;
	}

	unlocker::SetPrivilege(SE_DEBUG_NAME, FALSE);
	system("pause");
	return 0;
}
