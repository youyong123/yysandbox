#pragma once

//#define		MAXPATHLEN         300        // 文件|进程|注册表最大长度
//#define		MAXNAMELEN         64         // 用户名最大长度
#define		LONG_NAME_LEN		300
#define		SHORT_NAME_LEN		64

#define		STATUS_SB_TRY_REPARSE			0xe0000001
#define		STATUS_SB_REPARSED				0xe0000002
#define		STATUS_SB_DIR_CREATED			0xe0000005
#define		MAX_VOLUME_CHARS				26	

#define MyNew(_type, _count) \
(_type*)ExAllocatePoolWithTag(NonPagedPool, sizeof(_type) * (_count), 'FCLM')

#define MyDelete(_p) \
do{if(!(_p)) break; ExFreePool((_p)); (_p) = NULL;}while(0)


#define	 RUN_ONCE	\
{ \
	static  BOOLEAN bUninit = FALSE;\
	if (bUninit==TRUE)\
	{\
		return;\
	}\
	bUninit = TRUE;\
}

#define UNICODE_STRING_CONST(x) \
{sizeof(L##x)-2, sizeof(L##x), L##x}
