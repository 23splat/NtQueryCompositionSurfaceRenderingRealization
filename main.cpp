// Reboot system to unload driver
// [OPT] Create your own Unlaod routine, pass PDRIVER_OBJECT as an arg (can be a VOID routine)
// Read 'Loaded' function before executing (Line 175)

// Bad habit returning false in functions that return an NTSTATUS, please correct this to STATUS_UNSUCCESSFUL where you see 'false' based on the func return type

/* Haven't testing this, don't know if NtQueryCompositionSurfaceRenderingRealization causes BSOD. If it does, replace the second argument passed to 
GET_EXPORTED_ROUTINE_ADDRESS (called on line 155) with NtQueryCompositionSurfaceStatistics or NtQueryCompositionSurfaceBinding */

struct IMAGE_BASE_INFORMATION
{
	ULONG ImageSize;
	PVOID ImageBase;
	const char* FullImageName;
	PVOID RoutineAddress;
	PVOID ModuleBase64;
	HANDLE ProcessID;
	ULONG NumberOfThreads;
	ULONG HandleCount;

	NTSTATUS GET_IMAGE_INFORMATION(const char* ModuleName)
	{
		ULONG Bytes = 0;
		if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, NULL, NULL, &Bytes))) return STATUS_UNSUCCESSFUL;
		if (!Bytes) return false;
		PRTL_PROCESS_MODULES Modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, Bytes, 0x4e554c4c); // 'NULL'
		if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, Modules, Bytes, &Bytes))) return STATUS_UNSUCCESSFUL;
		PRTL_PROCESS_MODULE_INFORMATION ModuleInformation = Modules->Modules;
		for (int j = 0; j < Modules->NumberOfModules; j++)
		{
			if (!strcmp((const char*)ModuleInformation[j].FullPathName, ModuleName))
			{
				this->ImageBase = ModuleInformation[j].ImageBase;
				this->ImageSize = ModuleInformation[j].ImageSize;
				this->FullImageName = (const char*)ModuleInformation[j].FullPathName;
				ExFreePoolWithTag(Modules, 0x4e554c4c);
				return STATUS_SUCCESS;
			}
		}
		ExFreePoolWithTag(Modules, 0x4e554c4c);
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS GET_EXPORTED_ROUTINE_ADDRESS(const char* ModuleName, const char* RoutineName)
	{
		if (!NT_SUCCESS(this->GET_IMAGE_INFORMATION(ModuleName))) return STATUS_UNSUCCESSFUL;
		this->RoutineAddress = RtlFindExportedRoutineByName(this->ImageBase, RoutineName);
		if (!this->RoutineAddress) return STATUS_UNSUCCESSFUL;
		return STATUS_SUCCESS;
	}

	NTSTATUS GET_MODULE_BASE_x64(PEPROCESS Process, const char* ModuleName)
	{
		PPEB pPeb = PsGetProcessPeb(Process);
		if (!pPeb) return STATUS_UNSUCCESSFUL;
		KAPC_STATE State;
		KeStackAttachProcess(Process, &State);
		ANSI_STRING ProcessNameAnsi;
		RtlInitAnsiString(&ProcessNameAnsi, ModuleName);
		UNICODE_STRING ProcessNameUnicode;
		if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&ProcessNameUnicode, &ProcessNameAnsi, TRUE))) return RtlAnsiStringToUnicodeString(&ProcessNameUnicode, &ProcessNameAnsi, TRUE);
		PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
		if (!pLdr)
		{
			KeUnstackDetachProcess(&State);
			return STATUS_UNSUCCESSFUL;
		}
		for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink; list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pLdrEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

			if (!RtlCompareUnicodeString(&pLdrEntry->BaseDllName, &ProcessNameUnicode, TRUE))
			{
				this->ModuleBase64 = pLdrEntry->DllBase;
				KeUnstackDetachProcess(&State);
				return STATUS_SUCCESS;
			}

		}
		KeUnstackDetachProcess(&State);
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS GET_PROCESS_INFORMATION(const char* ProcessName)
	{
		ULONG Bytes = 0;
		if (!NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes))) return STATUS_UNSUCCESSFUL;
		if (!Bytes) return STATUS_UNSUCCESSFUL;
		PSYSTEM_PROCESS_INFO ProcessInformation = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, Bytes, 0x4e554c4c);
		if (!NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, ProcessInformation, Bytes, &Bytes)))
		{
			ExFreePoolWithTag(ProcessInformation, 0x4e554c4c);
			return STATUS_UNSUCCESSFUL;
		}
		ANSI_STRING ProcNameAnsi = {};
		RtlInitAnsiString(&ProcNameAnsi, ProcessName);
		UNICODE_STRING ProcNameUnicode = {};
		if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&ProcNameUnicode, &ProcNameAnsi,  TRUE)))
		{
			ExFreePoolWithTag(ProcessInformation, 0x4e554c4c);
			return STATUS_UNSUCCESSFUL;
		}
		while (ProcessInformation->NextEntryOffset)
		{
			if (!RtlCompareUnicodeString(&ProcessInformation->ImageName, &ProcNameUnicode, TRUE))
			{
				this->ProcessID = ProcessInformation->UniqueProcessId;
				this->NumberOfThreads = ProcessInformation->NumberOfThreads;
				this->HandleCount = ProcessInformation->HandleCount;
				ExFreePoolWithTag(ProcessInformation, 0x4e554c4c);
				RtlFreeUnicodeString(&ProcNameUnicode);
				return STATUS_UNSUCCESSFUL;
			}
		}
		ExFreePoolWithTag(ProcessInformation, 0x4e554c4c);
		return STATUS_UNSUCCESSFUL;
	}
};

struct HOOK_MEMORY
{
	BOOLEAN WRITE_MEMORY(void* src, void* buffer, size_t size)
	{
		if (!src || !size) return FALSE;
		if (!RtlCopyMemory(src, buffer, size)) return FALSE;
		return TRUE;
	}

	BOOLEAN WRITE_READ_ONLY_MEMORY(void* src, void* buffer, size_t size)
	{
		if (!src || !size) return false;
		PMDL pMdl = IoAllocateMdl(src, (ULONG)size, FALSE, FALSE, NULL);
		if (!pMdl) return false;
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
		PVOID Mapping = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, NULL, NormalPagePriority);
		MmProtectMdlSystemAddress(pMdl, PAGE_EXECUTE_READWRITE);
		if (!this->WRITE_MEMORY(Mapping, buffer, size))
		{
			MmUnmapLockedPages(Mapping, pMdl);
			MmUnlockPages(pMdl);
			IoFreeMdl(pMdl);
			return FALSE;
		}
		MmUnmapLockedPages(Mapping, pMdl);
		MmUnlockPages(pMdl);
		IoFreeMdl(pMdl);
		return TRUE;
	}
};

struct _HOOK_FUNCTIONS
{
	BOOLEAN Hook(void* KernelRoutineAddress)
	{
		if (!KernelRoutineAddress) return FALSE;
		IMAGE_BASE_INFORMATION* ImageInformation = new IMAGE_BASE_INFORMATION;
		if(!NT_SUCCESS(ImageInformation->GET_EXPORTED_ROUTINE_ADDRESS("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceRenderingRealization"))) return FALSE;

		BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		BYTE shell_code[] = { 0x48, 0xB8 };
		BYTE shell_code_end[] = { 0xFF, 0xE0 };

		memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
		uintptr_t Custom = reinterpret_cast<uintptr_t>(KernelRoutineAddress);
		memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &Custom, sizeof(void*));
		memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));
		
		HOOK_MEMORY* HookMemory = {};
		if(!NT_SUCCESS(HookMemory->WRITE_READ_ONLY_MEMORY(KernelRoutineAddress, &orig, sizeof(orig)))) return FALSE;

		delete ImageInformation;
		return TRUE;
	}

};

NTSTATUS Loaded(PVOID Paramater)
{
	IMAGE_BASE_INFORMATION* ImageInformation = new IMAGE_BASE_INFORMATION;
	PEPROCESS Process = {};
	if (!NT_SUCCESS(ImageInformation->GET_PROCESS_INFORMATION("Your Target Process Here"))) return STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(ImageInformation->ProcessID, &Process))) return STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(ImageInformation->GET_MODULE_BASE_x64(Process, "Your Target Module Here"))) return STATUS_UNSUCCESSFUL;

	DbgPrintEx(0, 0, ("Process ID: ", (LPCSTR)ImageInformation->ProcessID));
	DbgPrintEx(0, 0, ("ModuleBase: ", (LPCSTR)ImageInformation->ModuleBase64));
	DbgPrintEx(0, 0, ("Handle Count: ", (LPCSTR)ImageInformation->HandleCount));
	DbgPrintEx(0, 0, ("Full Image Name: ", ImageInformation->FullImageName));
	DbgPrintEx(0, 0, ("Number of Threads: ", (LPCSTR)ImageInformation->NumberOfThreads));

	delete ImageInformation;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT Object, PUNICODE_STRING nPath)
{
	UNREFERENCED_PARAMETER(Object);
	UNREFERENCED_PARAMETER(nPath);

	_HOOK_FUNCTIONS* CallHookDirectly = {};
	CallHookDirectly->Hook(&Loaded);

	return STATUS_SUCCESS;
}
