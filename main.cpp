#include "windows.h"
#include "stdio.h"
#include "assert.h"
#include <profileapi.h>

#include <chrono>
#include <thread>
#include <iostream>
#include <vector>

const char* cShmName = "Global\\shm";
const char* cClientSemName = "Global\\client0xd";
const char* cServerSemName = "Global\\server0xd";

#define CLIENT_USE_ATOMIC
//#define SERVER_USE_ATOMIC


// Number of query of each test
const int cQueryCount = 1000;

/******************************************************************************/
BOOL EnablePrivilege()
{
	LUID PrivilegeRequired;
	BOOL bRes = FALSE;

	//bRes = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &PrivilegeRequired);
	bRes = LookupPrivilegeValue(NULL, SE_CREATE_GLOBAL_NAME, &PrivilegeRequired);
	// ...

	return bRes;
}

BOOL SetPrivilege(
	HANDLE hToken,     // access token handle
	LPCTSTR lpszPrivilege, // name of privilege to enable/disable
	BOOL bEnablePrivilege  // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValue(
		NULL,      // lookup privilege on local system
		lpszPrivilege,  // privilege to lookup 
		&luid))    // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}
	return TRUE;
}


BOOL SetPrivilege(DWORD desiredAccess = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), desiredAccess, &hToken))
	{
		printf("OpenProcessToken Error %u\n", GetLastError());
		return FALSE;
	}
	SetPrivilege(hToken, SE_CREATE_GLOBAL_NAME, TRUE);
	CloseHandle(hToken);

	return TRUE;
}

/******************************************************************************/
struct Timer
{
	Timer()
	{
		if (sFrequency.QuadPart == 0)
		{
			QueryPerformanceFrequency(&sFrequency);
		}
	}

	inline void start()
	{
		QueryPerformanceCounter(&StartingTime);
	}

	int64_t elapsedTicks() const
	{
		LARGE_INTEGER CurrentTicks;
		QueryPerformanceCounter(&CurrentTicks);
		return CurrentTicks.QuadPart - StartingTime.QuadPart;
	}

	// Nanosecond
	inline int64_t elapsed() const
	{
		LARGE_INTEGER CurrentTicks, Elapsed;
		QueryPerformanceCounter(&CurrentTicks);


		Elapsed.QuadPart = CurrentTicks.QuadPart - StartingTime.QuadPart;
		Elapsed.QuadPart *= 1000000000; //ns
		Elapsed.QuadPart /= sFrequency.QuadPart;
		return Elapsed.QuadPart;
	}

	static double ticksToMs(int64_t pTicks)
	{
		return (pTicks * 1000.0) / sFrequency.QuadPart;
	}

	static double ticksToUs(int64_t pTicks)
	{
		return (pTicks * 1000000.0) / sFrequency.QuadPart;
	}

	inline static double ticksToNs(int64_t pTicks)
	{
		return (pTicks * 1000000000.0) / sFrequency.QuadPart;
	}

private:
	LARGE_INTEGER StartingTime;

	static LARGE_INTEGER sFrequency;
};

LARGE_INTEGER Timer::sFrequency = {};

/******************************************************************************/
void PrintWin32Error()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return; //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	//std::string message(messageBuffer, size);
	printf("%s\n", messageBuffer);
	//Free the buffer.
	LocalFree(messageBuffer);
}

/******************************************************************************/
struct Win32Shm
{
	Win32Shm() : handle(0), mappedData(NULL) {}

	void create(const char* pName, int pSize)
	{
		size = pSize;

		handle = CreateFileMapping(
			INVALID_HANDLE_VALUE,	// use paging file
			NULL,					// default security
			PAGE_READWRITE,			// read/write access
			0,						// maximum object size (high-order DWORD)
			pSize,					// maximum object size (low-order DWORD)
			pName);					// name of mapping object

		if (!handle)
		{
			PrintWin32Error();
			assert(false);
		}

		mappedData = (uint8_t*)MapViewOfFile(handle,   // handle to map object
			FILE_MAP_ALL_ACCESS, // read/write permission
			0,
			0,
			pSize);
	}

	void open(const char* pName, int pSize)
	{
		size = pSize;

		handle = OpenFileMapping(
			FILE_MAP_ALL_ACCESS,   // read/write access
			FALSE,                 // do not inherit the name
			pName);               // name of mapping object

		if (handle == NULL)
		{
			PrintWin32Error();
			assert(false);
		}

		mappedData = (uint8_t*)MapViewOfFile(handle, // handle to map object
			FILE_MAP_ALL_ACCESS,  // read/write permission
			0,
			0,
			pSize);
	}

	~Win32Shm()
	{
		if (handle)
		{
			UnmapViewOfFile(mappedData);
			CloseHandle(handle);
		}
	}

	HANDLE handle;
	uint8_t* mappedData;
	uint32_t size;
};

/******************************************************************************/
struct Win32Semaphore
{
	Win32Semaphore() : handle(0) {}
	Win32Semaphore(int pInitialValue, const char* pName)
	{
		create(pInitialValue, pName);
	}

	void open(const char* pName)
	{
		handle = OpenSemaphoreA(SEMAPHORE_ALL_ACCESS, FALSE, pName);		// SEMAPHORE_ALL_ACCESS / SEMAPHORE_MODIFY_STATE
		if (! handle)
		{
			PrintWin32Error();
			assert(false);
		}
	}

	void create(int pInitialValue, const char* pName)
	{		
		// Set unrestricted
		BOOL s = InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
		s = SetSecurityDescriptorDacl(&sd, TRUE, (PACL)0, FALSE);
		sa.nLength = sizeof(sa);
		sa.lpSecurityDescriptor = &sd;
		sa.bInheritHandle = FALSE;

		handle = CreateSemaphoreExA(&sa,
			pInitialValue,
			1L,
			pName,
			0,
			SEMAPHORE_ALL_ACCESS); // SEMAPHORE_ALL_ACCESS  / SEMAPHORE_MODIFY_STATE

		if (! handle)
		{
			PrintWin32Error();
			assert(false);
		}
	}

	inline void notify_one() {
		BOOL s = ReleaseSemaphore(handle, 1, NULL);
		if (s == FALSE)
		{
			PrintWin32Error();
			assert(false);
		}
	}

	inline void wait() {
		DWORD r = WaitForSingleObject(handle, INFINITE);
		if (r == WAIT_FAILED)
		{
			PrintWin32Error();
			assert(false);
		}
	}

	~Win32Semaphore()
	{
		BOOL s = CloseHandle(handle);
		if (s == FALSE)
		{
			PrintWin32Error();
			assert(false);
		}
	}

	HANDLE handle;
	SECURITY_ATTRIBUTES sa, sd;
};
/******************************************************************************/

struct ShmHeader
{
	std::atomic_int32_t clientSync;
	std::atomic_int32_t serverSync;
	uint32_t dataSize;
};

struct ShmHandle
{
	ShmHeader* header;
	uint8_t* data;
};

/******************************************************************************/
void client()
{
	Win32Shm shm;
	shm.open(cShmName, 1024);

	ShmHandle shmHandle;
	shmHandle.header = (ShmHeader*)shm.mappedData;
	//shmHandle.header->dataSize = shm.size - sizeof(ShmHeader);
	shmHandle.data = shm.mappedData + sizeof(ShmHeader);


	// Dunno why OpenSemaphore fail on first Wait...
	Win32Semaphore clientSem(0, cClientSemName);
	Win32Semaphore serverSem(1, cServerSemName);

	// Establish connection
	serverSem.notify_one();
	clientSem.wait();

	std::vector<std::string> lResults;
	Timer global_timer;
	Timer local_timer;

	// Don't compare the 2 first result, some tile loading are done in the first loop
	//  -1 mean no job, -2 mean (yield), >= 0 mean sleep(x)
	// The first loop is here to preload tile
	int job_duration_us[] = { -1, -2, 0, 5, 50, 100, 200, 300, 500, 1000 };
	int job_test_count = sizeof(job_duration_us) / sizeof(job_duration_us[0]);
	int j = -1;
	while
		(1)
	{
		if (j < job_test_count - 1)
		{
			++j;			
		}
		else
		{
			break;
		}

		printf("\n");
		for (int c = 0; c < 5; ++c)
		{
			bool simulate_job = j % 2 == 1;
			global_timer.start();
			int64_t global_cumul_ticks = 0;
			int64_t global_ticks = 0;
			int job_duration = job_duration_us[j];
			for (int i = 0; i < cQueryCount; ++i)
			{
				local_timer.start();
				
				// Send message to server
#ifdef CLIENT_USE_ATOMIC
				shmHandle.header->clientSync = 0;		// prepare to client wait before wake up server
#endif
#ifdef SERVER_USE_ATOMIC
				shmHandle.header->serverSync = 1;	// ask server to compute something
#else
				serverSem.notify_one(); // ask server to compute something
#endif


				// Wait respond
#ifdef CLIENT_USE_ATOMIC				
				while (shmHandle.header->clientSync == 0);
				shmHandle.header->clientSync = 0;
#else
				clientSem.wait();		// wait server finished
#endif
				
				global_cumul_ticks += local_timer.elapsedTicks();

				if (job_duration >= 0)
				{
					Timer wait;
					wait.start();
					while (Timer::ticksToUs(wait.elapsedTicks()) < job_duration);

					//std::this_thread::sleep_for(std::chrono::microseconds(job_duration));
				}
				if (job_duration == -2)
				{
					std::this_thread::yield();
				}
			}
			global_ticks = global_timer.elapsedTicks();

			printf("%s (client_job=%04dus): total=%06.3f ms cumul=%06.3f ms avg=%03.3f ms avg_ns=%03.3f us\n"
				, job_duration >= 0 ? "JOB_ON" : "NO_JOB"
				, job_duration
				, Timer::ticksToMs(global_ticks)
				, Timer::ticksToMs(global_cumul_ticks)
				, Timer::ticksToMs(global_cumul_ticks) / cQueryCount
				, Timer::ticksToUs(global_cumul_ticks) / cQueryCount
			);
		}
	}

}

/******************************************************************************/
void server()
{
	Win32Shm shm;
	shm.create(cShmName, 1024);

	// Handle to acces shm easily
	ShmHandle shmHandle;	
	shmHandle.header = new (shm.mappedData) ShmHeader(); // inplace allocation on the shm
	shmHandle.header->dataSize = shm.size - sizeof(ShmHeader);
	shmHandle.data = shm.mappedData + sizeof(ShmHeader);


	Win32Semaphore clientSem(0, cClientSemName);
	Win32Semaphore serverSem(0, cServerSemName);

	printf("waiting connection...\n");
	serverSem.wait();	// Wait client
	printf("RECV client connection\n");
	clientSem.notify_one();

	Timer local_timer;
	Timer global_timer;
	int count = 0;
	int64_t cumul = 0;

	// Server are now waiting for request
	// Act as a slave that must execute command as fast as possible
	int64_t global_ticks = 0;
	double request_compute_time_us = 30;
	global_timer.start();
	while (1)
	{
#ifdef SERVER_USE_ATOMIC
		while (shmHandle.header->serverSync == 0);
		shmHandle.header->serverSync = 0;
#else
		serverSem.wait();
#endif
		local_timer.start();
		//std::this_thread::sleep_for(request_compute_time);

		while (Timer::ticksToUs(local_timer.elapsedTicks()) < request_compute_time_us);
		cumul += local_timer.elapsedTicks();

#ifdef CLIENT_USE_ATOMIC
		shmHandle.header->clientSync = 1;
#else
		clientSem.notify_one();
#endif

		++count;
		if (count == cQueryCount)
		{
			printf("server_total_job=%06.3f ms avg=%03.3f ms avg_ns=%03.3f us\n"
				, Timer::ticksToMs(global_timer.elapsedTicks())
				, Timer::ticksToMs(cumul) / cQueryCount
				, Timer::ticksToUs(cumul) / cQueryCount);
			
			count = 0;
			cumul = 0;
			global_timer.start();
		}
	}
}

/******************************************************************************/
int main(int argc, char* argv[])
{
	HANDLE dummy = OpenSemaphore(SEMAPHORE_ALL_ACCESS, FALSE, cServerSemName);
	if (dummy)
	{
		CloseHandle(dummy);
		client();
	}
	else
	{
		SetPrivilege();	// require UAC = requireAdministrator
		server();
	}

    return 0;
}