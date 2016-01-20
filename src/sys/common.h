#ifndef _TL_COMMON_UTILS_H_
#define _TL_COMMON_UTILS_H_


BOOLEAN AcquireResourceExclusive(__inout PERESOURCE Resource);
BOOLEAN AcquireResourceShare(__inout PERESOURCE Resource);
VOID	ReleaseResource(__inout PERESOURCE Resource);

ULONGLONG BKDRHashW(PWCHAR wstr);

ULONGLONG APHashW(PWCHAR wstr);

ULONGLONG BKDRHashA(PCHAR wstr);

ULONGLONG APHashA(PCHAR wstr);

BOOLEAN GetHostFromPost(const char* http_block, ULONG	http_len, char* pOutBuf, ULONG OutBufLen, BOOLEAN* pbMail, BOOLEAN* pbSpecial);

NTSTATUS ToUpperStringW(WCHAR* Src, WCHAR* Dest, USHORT cbDestLen);

PWCHAR GetProcFullPathById(IN  HANDLE   dwProcessId, PWCHAR pPath, PULONG pPathLen);

PWCHAR GetProcNameById(IN  HANDLE   dwProcessId, PWCHAR pProcName, ULONG ProcNameLen);

typedef volatile LONG EX_SPIN_LOCK, *PEX_SPIN_LOCK;

KIRQL ExAcquireSpinLockExclusive( PEX_SPIN_LOCK SpinLock);

KIRQL ExAcquireSpinLockShared(PEX_SPIN_LOCK SpinLock);

VOID ExReleaseSpinLockShared( PEX_SPIN_LOCK SpinLock, KIRQL  OldIrql);

VOID ExReleaseSpinLockExclusive(PEX_SPIN_LOCK SpinLock, KIRQL  OldIrql);

BOOLEAN GetProcNameFromPath(WCHAR* pFullProcPath, ULONG Len, WCHAR* ProcName, ULONG cbProcNameLen);

NTSTATUS GetSysrootNtPath(PUNICODE_STRING sysrootNtPath);
NTSTATUS ResolveNtPathToDosPath(PUNICODE_STRING pNtPath, PUNICODE_STRING UmPath);
NTSTATUS ResolveDosPathToNtPath(PUNICODE_STRING pDosPath, PUNICODE_STRING UmPath);

BOOLEAN	 GetNtPathDir(const WCHAR* pNtPath, ULONG uNtPathLen, WCHAR* pNtPathDir, ULONG uNtPathDirLen);

PWCHAR wcsistr(PWCHAR wcs1, PWCHAR wcs2);

WCHAR* ReplaceString(WCHAR* pString, WCHAR* pOldString, WCHAR* pNewString, BOOLEAN IgnoreCase);

void PrintProcessById(HANDLE PID);

BOOLEAN  IsFileExist(PUNICODE_STRING pPath);

#endif 
