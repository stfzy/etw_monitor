#include "ResourceMonitor.h"

#include <fstream>
#include <string>

#include <Shlwapi.h>
#include <versionhelpers.h>

DEFINE_GUID(UdpIpGuid, 0xbf3a50c5, 0xa9c9, 0x4988, 0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80);
DEFINE_GUID(TcpIpGuid, 0x9a280ac0, 0xc8e0, 0x11d1, 0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2);
DEFINE_GUID(FileIoGuid, 0x90cbdc39, 0x4a3e, 0x11d1, 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3);
DEFINE_GUID(FileIoGuid2, 0xEDD08927, 0x9CC4, 0x4E65, 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89);
DEFINE_GUID(DiskIoGuid, 0x3d6fa8d4, 0xfe05, 0x11d0, 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c);
DEFINE_GUID(KernelRundownGuid_I, 0x3b9c9951, 0x3480, 0x4220, 0x93, 0x77, 0x9c, 0x8e, 0x51, 0x84, 0xf5, 0xcd);

std::wstring GetProcessPathFromPID(uint32_t pid) {
  if (pid == 4) {
    return L"SYSTEM";
  }

  if (pid == -1) {
    return L"";
  }

  HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (handle) {
    DWORD buffSize = 1024;
    WCHAR buffer[1024];
    if (QueryFullProcessImageNameW(handle, 0, buffer, &buffSize)) {
      CloseHandle(handle);

      return buffer;
    }
  }

  return L"NO NAME";
}

void WriteFileContent(const std::string& file_path, const std::string& file_content) {
  std::ofstream ifs(file_path, std::ios::binary | std::ios::out);

  if (!ifs.is_open()) {
    return;
  }

  if (!ifs.write(file_content.data(), file_content.size())) {
    return;
  }

  ifs.close();
}

void ResourceMonitor::ProcessDiskFileIo(PEVENT_RECORD event_record) noexcept {
  static bool init{false};
  static double next_tm{0};
  static int err_cnt{0};

  if (!init) {
    ENABLE_TRACE_PARAMETERS etp{0};
    etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    auto ret = EnableTraceEx2(trace_handle_, &KernelRundownGuid_I, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_NONE, 0x10, 0, INFINITE, &etp);
    if (!ret == ERROR_SUCCESS) {
      std::cout << "EnableTraceEx2 failed with code " << ret << std::endl;
      ret = EnableTraceEx(&KernelRundownGuid_I, 0, trace_handle_, 1, 0, 0x10, 0, 0, 0);
      std::cout << "EnableTraceEx return with code " << ret << std::endl;
    }

    init = true;
  }

  switch (event_record->EventHeader.EventDescriptor.Opcode) {
    case 32:
    case 36: {  // File rundown event. 所有已经打开的文件会到这里
      FileIo_Name* data = (FileIo_Name*)event_record->UserData;

      file_io_info_[data->FileObject].file_path = data->FileName;
      file_io_info_[data->FileObject].pid = event_record->EventHeader.ProcessId;
      file_io_info_[data->FileObject].process_path = GetProcessPathFromPID(event_record->EventHeader.ProcessId);
    } break;

    case 64: {  // file open
      if (is_win10_) {
        FileIo_Create* data = (FileIo_Create*)event_record->UserData;
        if (data->CreateOptions & 0x00000001 /*FILE_DIRECTORY_FILE*/) {
          break;
        }

        file_io_info_[data->FileObject].file_path = (wchar_t*)data->OpenPath;
        file_io_info_[data->FileObject].pid = event_record->EventHeader.ProcessId;
        file_io_info_[data->FileObject].process_path = GetProcessPathFromPID(event_record->EventHeader.ProcessId);
      } else {
        FileIo_Create_Win7* data = (FileIo_Create_Win7*)event_record->UserData;
        auto thandle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, data->TTID);
        if (thandle) {
          file_io_info_[data->FileObject].pid = GetProcessIdOfThread(thandle);
          CloseHandle(thandle);
        } else {
          file_io_info_[data->FileObject].pid = 4;
        }

        file_io_info_[data->FileObject].file_path = (wchar_t*)data->OpenPath;

        file_io_info_[data->FileObject].process_path = GetProcessPathFromPID(file_io_info_[data->FileObject].pid);
      }

      /*  WriteFileContent("./" + std::to_string(event_record->EventHeader.ProcessId) + ".txt", std::string((char*)data, 100));

        std::wcout << data->OpenPath << L" " << file_io_info_[data->FileObject].process_path << std::endl;*/
    } break;

    case 67:
    case 68: {  // file read write
      uint64_t file_key{0};
      uint32_t pid{event_record->EventHeader.ProcessId};
      if (is_win10_) {
        FileIo_ReadWrite* data = (FileIo_ReadWrite*)event_record->UserData;
        if (file_io_info_.find(data->FileKey) != file_io_info_.end()) {
          file_key = data->FileKey;
        } else if (file_io_info_.find(data->FileObject) != file_io_info_.end()) {
          file_key = data->FileObject;
        } else {
          break;
        }
      } else {
        FileIo_ReadWrite_Win7* data = (FileIo_ReadWrite_Win7*)event_record->UserData;
        if (pid <= 0) {
          auto thandle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, data->TTID);
          if (thandle) {
            pid = GetProcessIdOfThread(thandle);
            CloseHandle(thandle);
          } else {
            pid = 4;
          }
        }

        if (file_io_info_.find(data->FileKey) != file_io_info_.end()) {
          file_key = data->FileKey;
        } else if (file_io_info_.find(data->FileObject) != file_io_info_.end()) {
          file_key = data->FileObject;
        } else {
          break;
        }
      }

      if (0 == file_io_info_[file_key].pid || -1 == file_io_info_[file_key].pid) {
        file_io_info_[file_key].pid = pid;
        file_io_info_[file_key].process_path = GetProcessPathFromPID(pid);
      }
      if (file_io_info_[file_key].file_path == L"") {
        break;
      }

      std::unique_lock<std::shared_mutex> lck{file_mutex_};
      read_write_file_record_[file_io_info_[file_key].pid][file_io_info_[file_key].file_path] = file_io_info_[file_key].process_path;

    } break;
  }
}

void ResourceMonitor::ProcessNetworkIo(PEVENT_RECORD event_record) noexcept {
  static double next_tm{0};
  std::unique_lock<std::shared_mutex> lck{net_mutex_};

  auto current_s = (event_record->EventHeader.TimeStamp.QuadPart * 1.0) / (event_trace_logfile_->LogfileHeader.CpuSpeedInMHz * 1000000.0);
  if (0 == next_tm || (current_s > next_tm)) {
    next_tm = current_s + 1;

    SetNetIoResourceUsage();
  }

  switch (event_record->EventHeader.EventDescriptor.Opcode) {
    case EVENT_TRACE_TYPE_RECEIVE: {
      TcpIp_TypeGroup1* data = (TcpIp_TypeGroup1*)event_record->UserData;
      NetIOKey net_key;
      net_key.dst_ip = data->daddr;
      net_key.pid = data->PID;
      if (net_io_info_.find(net_key.key) == net_io_info_.end()) {
        NetIOInfo net_io_info;
        net_io_info.pid = data->PID;
        net_io_info.proc_path = GetProcessPathFromPID(data->PID);
        net_io_info.recv_bytes = data->size;
        wchar_t ipbuff[64];
        net_io_info.remote_ip = InetNtopW(AF_INET, &data->daddr, ipbuff, 64);
        net_io_info.total_bytes = net_io_info.recv_bytes + net_io_info.send_bytes;
        net_io_info_[net_key.key] = net_io_info;
      } else {
        net_io_info_[net_key.key].recv_bytes += data->size;
        net_io_info_[net_key.key].total_bytes = net_io_info_[net_key.key].recv_bytes + net_io_info_[net_key.key].send_bytes;
      }

    } break;
    case EVENT_TRACE_TYPE_SEND: {
      TcpIp_TypeGroup1* data = (TcpIp_TypeGroup1*)event_record->UserData;
      NetIOKey net_key;
      net_key.dst_ip = data->daddr;
      net_key.pid = data->PID;
      if (net_io_info_.find(net_key.key) == net_io_info_.end()) {
        NetIOInfo net_io_info;
        net_io_info.pid = data->PID;
        net_io_info.proc_path = GetProcessPathFromPID(data->PID);
        net_io_info.send_bytes = data->size;
        wchar_t ipbuff[64];
        net_io_info.remote_ip = InetNtopW(AF_INET, &data->daddr, ipbuff, 64);
        net_io_info.total_bytes = net_io_info.recv_bytes + net_io_info.send_bytes;
        net_io_info_[net_key.key] = net_io_info;
      } else {
        net_io_info_[net_key.key].send_bytes += data->size;
        net_io_info_[net_key.key].total_bytes = net_io_info_[net_key.key].recv_bytes + net_io_info_[net_key.key].send_bytes;
      }

    } break;
    case EVENT_TRACE_TYPE_DISCONNECT: {
      TcpIp_TypeGroup1* data = (TcpIp_TypeGroup1*)event_record->UserData;
      NetIOKey net_key;
      net_key.dst_ip = data->daddr;
      net_key.pid = data->PID;
      net_io_info_.erase(net_key.key);
    } break;
  }
}

void __stdcall EventRecordCallback(PEVENT_RECORD event_record) {
  ResourceMonitor* resource_mon = (ResourceMonitor*)event_record->UserContext;

  if (IsEqualGUID(FileIoGuid, event_record->EventHeader.ProviderId)) {
    resource_mon->ProcessDiskFileIo(event_record);
  } else if (IsEqualGUID(TcpIpGuid, event_record->EventHeader.ProviderId) || IsEqualGUID(UdpIpGuid, event_record->EventHeader.ProviderId)) {
    resource_mon->ProcessNetworkIo(event_record);
  }
}

int ResourceMonitor::StartResourceMonitor() noexcept {
  int ret = 0;

  is_win10_ = IsWindows10OrGreater();

  do {
    uint32_t event_trace_propertie_length{sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME)};
    event_trace_properties_ = static_cast<PEVENT_TRACE_PROPERTIES>(malloc(event_trace_propertie_length));
    event_trace_properties_tmp_ = static_cast<PEVENT_TRACE_PROPERTIES>(malloc(event_trace_propertie_length));
    if (nullptr == event_trace_properties_ || nullptr == event_trace_properties_tmp_) {
      ret = -1;
      break;
    }

    memset(event_trace_properties_, 0, event_trace_propertie_length);

    event_trace_properties_->Wnode.BufferSize = event_trace_propertie_length;
    event_trace_properties_->Wnode.Guid = SystemTraceControlGuid;
    event_trace_properties_->Wnode.ClientContext = 3;
    event_trace_properties_->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    event_trace_properties_->EnableFlags =
        EVENT_TRACE_FLAG_NETWORK_TCPIP | EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT;
    event_trace_properties_->BufferSize = 64;
    event_trace_properties_->FlushTimer = 1;
    event_trace_properties_->MinimumBuffers = 16;
    event_trace_properties_->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    event_trace_properties_->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    memcpy(event_trace_properties_tmp_, event_trace_properties_, event_trace_propertie_length);

    ret = StartTraceW(&trace_handle_, KERNEL_LOGGER_NAME, event_trace_properties_tmp_);
    if (ERROR_SUCCESS != ret) {
      if (ERROR_ALREADY_EXISTS != ret) {
        std::cout << "ResourceMonitor::StartResourceMonitor - StartTraceW failed with code " << ret << " and last err " << GetLastError() << std::endl;
        break;
      }

      // 如果已经启动，按照我们的配置重启一下
      ret = ControlTraceW(NULL, KERNEL_LOGGER_NAME, event_trace_properties_tmp_, EVENT_TRACE_CONTROL_STOP);
      if (SUCCEEDED(ret)) {
        ret = StartTraceW(&trace_handle_, KERNEL_LOGGER_NAME, event_trace_properties_);
        if (ERROR_SUCCESS != ret) {
          std::cout << "ResourceMonitor::StartResourceMonitor - StartTraceW 2 failed with code " << ret << " and last err " << GetLastError() << std::endl;
          break;
        }
      }
    }

    std::cout << "ResourceMonitor::StartResourceMonitor - StartTraceW success" << std::endl;

    // Initialize the memory for this structure to zero.
    event_trace_logfile_ = (PEVENT_TRACE_LOGFILEW)malloc(sizeof(EVENT_TRACE_LOGFILEW));
    if (!event_trace_logfile_) {
      ret = -3;
      break;
    }

    memset(event_trace_logfile_, 0, sizeof(EVENT_TRACE_LOGFILEW));

    event_trace_logfile_->LoggerName = (LPWSTR)KERNEL_LOGGER_NAME;
    event_trace_logfile_->ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    event_trace_logfile_->EventRecordCallback = EventRecordCallback;
    event_trace_logfile_->Context = this;

    consumer_trace_handle_ = OpenTraceW(event_trace_logfile_);
    if (INVALID_PROCESSTRACE_HANDLE == consumer_trace_handle_) {
      ret = -2;
      std::cout << "ResourceMonitor::StartResourceMonitor - OpenTraceW failed with code " << ret << " and last err " << GetLastError() << std::endl;
      break;
    }
    std::cout << "ResourceMonitor::StartResourceMonitor - OpenTraceW success" << std::endl;
    init_ = true;
    consumer_thread_ = std::thread(&ResourceMonitor::ConsumerThread, this);

  } while (false);

  if (0 != ret) {
    StopResourceMonitor();
  }

  return ret;
}

void ResourceMonitor::StopResourceMonitor() noexcept {
  if (0 != consumer_trace_handle_) {
    CloseTrace(consumer_trace_handle_);
    consumer_trace_handle_ = 0;
  }

  consumer_thread_.join();

  if (0 != trace_handle_) {
    ControlTraceW(NULL, KERNEL_LOGGER_NAME, event_trace_properties_, EVENT_TRACE_CONTROL_STOP);
    ControlTraceW(NULL, KERNEL_LOGGER_NAME, event_trace_properties_tmp_, EVENT_TRACE_CONTROL_STOP);
    trace_handle_ = 0;
  }

  if (event_trace_properties_) {
    free(event_trace_properties_);
    event_trace_properties_ = nullptr;
  }

  if (event_trace_properties_tmp_) {
    free(event_trace_properties_tmp_);
    event_trace_properties_tmp_ = nullptr;
  }

  if (event_trace_logfile_) {
    free(event_trace_logfile_);
    event_trace_logfile_ = nullptr;
  }

  file_io_info_.clear();
  net_io_info_.clear();
  read_write_file_record_.clear();
  current_net_io_info_.clear();

  init_ = false;
}

std::vector<NetIOInfo> ResourceMonitor::GetNetIoResourceUsage() noexcept {
  std::unique_lock<std::shared_mutex> lck{net_mutex_};
  return current_net_io_info_;
}

std::map<uint32_t, std::map<std::wstring, std::wstring>> ResourceMonitor::GetFileIoResourceUsage() noexcept {
  std::unique_lock<std::shared_mutex> lck{file_mutex_};
  return read_write_file_record_;
}

void ResourceMonitor::SetNetIoResourceUsage() noexcept {
  std::unique_lock<std::shared_mutex> lck{file_mutex_};
  current_net_io_info_.clear();

  for (auto& info : net_io_info_) {
    if (info.second.total_bytes == 0) {
      continue;
    }
    current_net_io_info_.push_back(info.second);
    info.second.send_bytes = 0;
    info.second.recv_bytes = 0;
    info.second.total_bytes = 0;
  }
}

void ResourceMonitor::ConsumerThread() noexcept {
  auto ret = ProcessTrace(&consumer_trace_handle_, 1, nullptr, nullptr);
  if (ret != ERROR_SUCCESS) {
    std::cout << "ResourceMonitor::ConsumerThread - ProcessTrace failed with code " << ret << " and last error " << GetLastError() << std::endl;
  }
  init_ = false;
}
