#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <tlhelp32.h>
#include <time.h>
#include <string>


/*
* Function:  NtQueryInformationProcess 
* --------------------
* Retrieves information about the specified process.
*
*The function returns an NTSTATUS success or error code.
*/
typedef NTSTATUS (NTAPI *_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
    );


/*
* UNICODE_STRING structure
* --------------------
* counted Unicode string
*/
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;



/*
* PROCESS_BASIC_INFORMATION
* --------------------
*
*Process Information Class
*/
typedef struct _PROCESS_BASIC_INFORMATION
{
    LONG ExitStatus;
    PVOID PebBaseAddress; /* contains the PEB address */
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;



/*
* Function:  GetPebAddress 
* --------------------
* get the address of the The Process Environment Block (PEB)
*
*  param: ProcessHandle
*  
*/
PVOID GetPebAddress(HANDLE ProcessHandle)
{
    _NtQueryInformationProcess NtQueryInformationProcess =
        (_NtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION pbi;

    NtQueryInformationProcess(ProcessHandle, 0, &pbi, sizeof(pbi), NULL);

    return pbi.PebBaseAddress;
}


/*
* Function:  ConcatFileName 
* --------------------
* Set system local time in file name
*
*  param: localtime to set file name
*
*  returns: filename with .txt
*/
char* ConcatFileName ( char ch1[100])
{
	

	char s1[200]= "D:\\";
	char s2[100]= ".txt";
	strcat(s1 , ch1);
	strcat(s1 , s2);

return s1;
}



int main(int argc, char* argv[]) 
{

    HANDLE hSnap;
    PROCESSENTRY32 pe;
	DWORD dwWritten; // number of bytes written to file
	HANDLE hFile;  //  Writefile function handle
    HANDLE processHandle;
    PVOID pebAddress;
    PVOID rtlUserProcParamsAddress;
    UNICODE_STRING commandLine;
    WCHAR *commandLineContents;
	time_t now;
	char fname[100];
	char* ftname;
	int pid;


	if ( argc <= 1 || *argv == NULL ) // check argument 

		{
			argc =1;
			argv[1] = "a";
			printf ("Please enter 2 argument,Number of Operations and the time interval(millisecond)");		
	}

    

	for (int i = 0; i < atoi(argv[1]) ; ++i) // Loop for Number of Operations and The time interval
	{


	hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

    if (hSnap==INVALID_HANDLE_VALUE)

         return 1;


    pe.dwSize=sizeof(pe);

    if (Process32First(hSnap, &pe))



	now = time (0);

	strftime(fname, 100, "%Y-%m-%d %H %M %S.000", localtime (&now));

	ftname = ConcatFileName(fname);

	hFile=CreateFile(ftname,GENERIC_WRITE,FILE_SHARE_WRITE,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);



 while (Process32Next(hSnap,&pe))
 {
          MODULEENTRY32 me;

          HANDLE hMod;

		  pid = pe.th32ProcessID;

          if (pe.th32ProcessID==0)

     continue;


          hMod=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pe.th32ProcessID); 

          if (hMod==INVALID_HANDLE_VALUE) 

     continue;


		  if ((processHandle = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)) == 0)

		  {
			  printf("Could not open process\n");
			  return GetLastError();
		  }

		  pebAddress = GetPebAddress(processHandle);

   
 if (!ReadProcessMemory(processHandle, (PCHAR)pebAddress + 0x10, &rtlUserProcParamsAddress, sizeof(PVOID), NULL))  /* get the address of ProcessParameters */
    {
        printf("Could not read the address of ProcessParameters\n");
        return GetLastError();
    }

    
    if (!ReadProcessMemory(processHandle, (PCHAR)rtlUserProcParamsAddress + 0x40, &commandLine, sizeof(commandLine), NULL)) /* read the CommandLine UNICODE_STRING structure */
    {
        printf("Could not read CommandLine\n");
        return GetLastError();
    }
	   
    commandLineContents = (WCHAR *)malloc(commandLine.Length);   /* allocate memory to hold the command line */

   
    if (!ReadProcessMemory(processHandle, commandLine.Buffer, commandLineContents, commandLine.Length, NULL))  /* read the command line */
    {
        printf("Could not read the command line string\n");
        return GetLastError();
    }


         me.dwSize = sizeof(me); 

         Module32First(hMod, &me);
		 char buffer[4048]; 
		 memset(buffer, '\0', sizeof(buffer));


		 sprintf_s(buffer, "\n====================\nPID:%6d  ProcessName:%-15s  Path:%s  ParentID:%6d  CommandLine:%.*S\n",pe.th32ProcessID,me.szModule,me.szExePath, pe.th32ParentProcessID, commandLine.Length / 2, commandLineContents);
		 WriteFile(hFile,buffer,strlen(buffer),&dwWritten,0);

		
		 CloseHandle(processHandle);
		 free(commandLineContents);
         CloseHandle(hMod); 

     }
 
		CloseHandle(hSnap);

		CloseHandle(hFile);

		Sleep (atoi(argv[2]));

		}

     return 0;
}