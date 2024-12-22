#ifndef RESOURCE_MONITOR_H_
#define RESOURCE_MONITOR_H_

#include <iostream>
#include <thread>
#include <map>
#include <shared_mutex>
#include <vector>

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <guiddef.h>
#include <ws2tcpip.h>

struct DiskIo_TypeGroup1 {
  uint32_t DiskNumber;
  uint32_t IrpFlags;
  uint32_t TransferSize;
  uint32_t Reserved;
  uint64_t ByteOffset;
  uint32_t FileObject;
  uint32_t Irp;
  uint64_t HighResResponseTime;
  uint32_t IssuingThreadId;
};

struct FileIo_Name {
  uint64_t FileObject;
  wchar_t FileName[1];
};

struct FileIo_Create {
  uint64_t IrpPtr;
  uint64_t TTID;
  uint32_t FileObject;
  uint32_t CreateOptions;
  uint32_t FileAttributes;
  uint32_t ShareAccess;
  wchar_t OpenPath[1];
};

struct FileIo_Create_Win7 {
  uint64_t IrpPtr;
  uint64_t TTID;
  uint64_t FileObject;
  uint32_t CreateOptions;
  uint32_t FileAttributes;
  uint32_t ShareAccess;
  wchar_t OpenPath[1];
};

struct FileIo_ReadWrite {
  uint64_t Offset;
  uint64_t IrpPtr;
  uint64_t TTID;
  uint64_t FileObject;
  uint32_t FileKey;
  uint32_t IoSize;
  uint32_t IoFlags;
};

struct FileIo_ReadWrite_Win7 {
  uint64_t Offset;
  uint64_t IrpPtr;
  uint64_t TTID;
  uint64_t FileObject;
  uint64_t FileKey;
  uint32_t IoSize;
  uint32_t IoFlags;
};

struct FileIo_SimpleOp {
  uint64_t IrpPtr;
  uint64_t TTID;
  uint64_t FileObject;
  uint32_t FileKey;
};

struct TcpIp_TypeGroup1 {
  uint32_t PID;
  uint32_t size;
  uint32_t daddr;
  uint32_t saddr;
};

struct FileIOInfo {
  uint32_t pid{0};
  std::wstring file_path;
  std::wstring process_path;
  uint64_t read_bytes{0};
  uint64_t write_bytes{0};
  uint64_t total_bytes{0};
};

struct NetIOInfo {
  uint32_t pid{0};
  std::wstring proc_path;
  std::wstring remote_ip;
  uint64_t send_bytes{0};
  uint64_t recv_bytes{0};
  uint64_t total_bytes{0};
};

union NetIOKey {
  struct {
    uint32_t pid;
    uint32_t dst_ip;
  };

  uint64_t key;
};

using FileIoInfos = std::map<uint64_t, FileIOInfo>;
using NetIoInfos = std::map<uint64_t, NetIOInfo>;

class ResourceMonitor {
 public:
  ResourceMonitor() = default;
  ~ResourceMonitor() = default;

 public:
  int StartResourceMonitor() noexcept;
  void StopResourceMonitor() noexcept;
  std::map<uint32_t, std::map<std::wstring, std::wstring>> GetFileIoResourceUsage() noexcept;
  std::vector<NetIOInfo> GetNetIoResourceUsage() noexcept;

 private:
  void SetNetIoResourceUsage() noexcept;
  void ConsumerThread() noexcept;
  void ProcessDiskFileIo(PEVENT_RECORD event_record) noexcept;
  void ProcessNetworkIo(PEVENT_RECORD event_record) noexcept;

 private:
  bool init_{false};
  TRACEHANDLE trace_handle_{0};
  TRACEHANDLE consumer_trace_handle_{0};
  PEVENT_TRACE_PROPERTIES event_trace_properties_{nullptr};
  PEVENT_TRACE_PROPERTIES event_trace_properties_tmp_{nullptr};
  PEVENT_TRACE_LOGFILEW event_trace_logfile_{nullptr};
  std::thread consumer_thread_;
  std::shared_mutex file_mutex_;
  std::shared_mutex net_mutex_;
  FileIoInfos file_io_info_;
  NetIoInfos net_io_info_;

  std::map<uint32_t, std::map<std::wstring, std::wstring>> read_write_file_record_; 
  std::vector<NetIOInfo> current_net_io_info_;
  bool is_win10_{false};
  friend void __stdcall EventRecordCallback(PEVENT_RECORD event_record);
};
#endif