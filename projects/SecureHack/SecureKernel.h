#pragma once

#pragma pack(push,1)
typedef struct _SECUREKERNEL_PROCESS
{
	union
	{
		struct
		{
			BYTE Padding0[0x38];
			DWORD ProcessId;
		};

		struct
		{
			BYTE Padding1[0x40];
			DWORD64 Cr3;
		};

	    struct
	    {
			BYTE Padding2[0xE0];
			LIST_ENTRY ProcessList;
	    };
	};
} SECUREKERNEL_PROCESS;
#pragma pack(pop)