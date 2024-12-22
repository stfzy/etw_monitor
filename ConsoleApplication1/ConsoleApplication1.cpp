#include <iostream>
#include <thread>
#include <map>
#include <shared_mutex>

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <guiddef.h>

#include "../ResourceMonitor/ResourceMonitor.h"

using namespace std::chrono_literals;
 
std::wstring DosPathToNtPath(const std::wstring& strPath) {
  std::wstring strResultPath;
  TCHAR szDriveStrings[MAX_PATH] = {0};
  TCHAR szDosBuf[MAX_PATH] = {0};
  TCHAR szResultBuf[MAX_PATH] = {0};
  LPTSTR pDriveStr = NULL;

  // 获取盘符名到缓冲
  if (::GetLogicalDriveStrings(_countof(szDriveStrings), szDriveStrings)) {
    // 遍历盘符名
    for (int i = 0; i < _countof(szDriveStrings); i += 4) {
      pDriveStr = &szDriveStrings[i];
      pDriveStr[2] = L'\0';

      // 查询盘符对应的DOS设备名称
      if (!::QueryDosDevice(pDriveStr, szDosBuf, _countof(szDosBuf))) {
        break;
      }

      // 对比路径前缀
      size_t nLen = wcslen(szDosBuf);
      if (0 == _wcsnicmp(strPath.c_str(), szDosBuf, nLen)) {
        lstrcpy(szResultBuf, pDriveStr);
        lstrcat(szResultBuf, strPath.c_str() + nLen);
        strResultPath = szResultBuf;
        break;
      }
    }
  }
  if (strResultPath.empty()) {
    return strPath;
  }
  return strResultPath;
}

int main() {
  std::locale::global(std::locale(""));
  std::cout << "in " << std::endl;

  ResourceMonitor rm;
  auto ret = rm.StartResourceMonitor();
  if (0 != ret) {
    std::cout << "StartResourceMonitor failed with code " << ret << std::endl;
    return 0;
  }
#if 0
  while (true) {
    std::this_thread::sleep_for(1s);
    system("cls");
    std::vector<NetIOInfo> net_io_infos = rm.GetNetIoResourceUsage();

    for (const auto& i : net_io_infos) {
      std::wcout << i.pid << L" " << i.proc_path << L" " << i.remote_ip << L" " << i.send_bytes << L" " << i.recv_bytes << L" " << i.total_bytes << std::endl;
    }
  }

#else
  while (true) {
    std::this_thread::sleep_for(1s);
    system("cls");
    auto file_io_infos = rm.GetFileIoResourceUsage();

    for (const auto& f : file_io_infos) {
      for (const auto& f2 : f.second) {
        std::wcout << L"pid:" << f.first << L" process:" << f2.second << L" file :" << DosPathToNtPath(f2.first) << std::endl;
      }
    }
  }
#endif

  while (true) {
    std::this_thread::sleep_for(99999s);
  }
  return 0;
}
