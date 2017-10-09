#pragma once

#include <stdio.h>

#include "..\..\unlocker.hpp"

// main
int _tmain(int argc, _TCHAR* argv[])
{
	SetPrivilege(SE_DEBUG_NAME, TRUE);

	tstring path (_T("f:\\a.xls"));
	UnholdFile(path);

	SetPrivilege(SE_DEBUG_NAME, FALSE);
	system("pause");
	return 0;
}
