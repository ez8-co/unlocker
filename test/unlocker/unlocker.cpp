#pragma once

#include <stdio.h>

#include "..\..\unlocker.hpp"

#include <cstdlib>

// main
int _tmain(int argc, _TCHAR* argv[])
{
	unlocker::SetPrivilege(SE_DEBUG_NAME, TRUE);

	tstring path (_T("f:\\a.xls"));
	unlocker::UnholdFile(path);

	unlocker::SetPrivilege(SE_DEBUG_NAME, FALSE);
	system("pause");
	return 0;
}
