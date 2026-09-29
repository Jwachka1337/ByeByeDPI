#include "windivert_manager.hpp"
#include "windivert_deployer.hpp"

#include <iostream>
#include <sstream>
#include <vector>

namespace divert {

WinDivertManager::WinDivertManager(const DivertConfig& config) {
    open(config);
}

WinDivertManager::~WinDivertManager() noexcept {
    close();
}

WinDivertManager::WinDivertManager(WinDivertManager&& other) noexcept {
    std::lock_guard<std::mutex> lock(other.m_handle_mutex);
    m_handle = other.m_handle;
    m_config = std::move(other.m_config);
    m_is_open.store(other.m_is_open.load(std::memory_order_relaxed), std::memory_order_relaxed);

    other.m_handle = INVALID_HANDLE_VALUE;
    other.m_is_open.store(false, std::memory_order_relaxed);
}

WinDivertManager& WinDivertManager::operator=(WinDivertManager&& other) noexcept {
    if (this != &other) {
        std::scoped_lock lock(m_handle_mutex, other.m_handle_mutex);

        close();

        m_handle = other.m_handle;
        m_config = std::move(other.m_config);
        m_is_open.store(other.m_is_open.load(std::memory_order_relaxed), std::memory_order_relaxed);

        other.m_handle = INVALID_HANDLE_VALUE;
        other.m_is_open.store(false, std::memory_order_relaxed);
    }
    return *this;
}

bool WinDivertManager::open(const DivertConfig& config) {
    std::lock_guard<std::mutex> lock(m_handle_mutex);

    if (m_handle != INVALID_HANDLE_VALUE) {
        deployer::pWinDivertClose(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
        m_is_open.store(false, std::memory_order_relaxed);
    }

    m_config = config;

    m_handle = deployer::pWinDivertOpen(
        m_config.filter.c_str(),
        m_config.layer,
        m_config.priority,
        m_config.flags
    );

    if (m_handle == INVALID_HANDLE_VALUE) {
        m_is_open.store(false, std::memory_order_release);
        return false;
    }

    m_is_open.store(true, std::memory_order_release);

    if (m_config.queue_length > 0) {
        deployer::pWinDivertSetParam(m_handle, WINDIVERT_PARAM_QUEUE_LENGTH, m_config.queue_length);
    }

    if (m_config.queue_time > 0) {
        deployer::pWinDivertSetParam(m_handle, WINDIVERT_PARAM_QUEUE_TIME, m_config.queue_time);
    }

    if (m_config.queue_size > 0) {
        deployer::pWinDivertSetParam(m_handle, WINDIVERT_PARAM_QUEUE_SIZE, m_config.queue_size);
    }

    return true;
}

void WinDivertManager::shutdown(WINDIVERT_SHUTDOWN how) noexcept {
    std::lock_guard<std::mutex> lock(m_handle_mutex);
    if (m_handle != INVALID_HANDLE_VALUE) {
        deployer::pWinDivertShutdown(m_handle, how);
    }
}

void WinDivertManager::close() noexcept {
    std::lock_guard<std::mutex> lock(m_handle_mutex);
    if (m_handle != INVALID_HANDLE_VALUE) {
        HANDLE h = m_handle;
        m_handle = INVALID_HANDLE_VALUE;
        m_is_open.store(false, std::memory_order_release);
        deployer::pWinDivertClose(h);
    }
}

bool WinDivertManager::is_open() const noexcept {
    return m_is_open.load(std::memory_order_acquire) && (m_handle != INVALID_HANDLE_VALUE);
}

bool WinDivertManager::set_param(WINDIVERT_PARAM param, uint64_t value) noexcept {
    std::lock_guard<std::mutex> lock(m_handle_mutex);
    if (m_handle == INVALID_HANDLE_VALUE) return false;
    return deployer::pWinDivertSetParam(m_handle, param, value) != FALSE;
}

bool WinDivertManager::get_param(WINDIVERT_PARAM param, uint64_t& out_value) const noexcept {
    std::lock_guard<std::mutex> lock(m_handle_mutex);
    if (m_handle == INVALID_HANDLE_VALUE) return false;
    return deployer::pWinDivertGetParam(m_handle, param, &out_value) != FALSE;
}

// Чтение входящего пакета
bool WinDivertManager::recv(std::span<uint8_t> buffer, WINDIVERT_ADDRESS& out_addr, uint32_t& out_recv_len) noexcept {
    HANDLE h = m_handle;
    if (h == INVALID_HANDLE_VALUE) return false;

    UINT recv_bytes = 0;
    BOOL ok = deployer::pWinDivertRecv(
        h,
        buffer.data(),
        static_cast<UINT>(buffer.size()),
        &recv_bytes,
        &out_addr
    );

    if (ok) {
        out_recv_len = static_cast<uint32_t>(recv_bytes);
        return true;
    }

    out_recv_len = 0;
    return false;
}

// Инъекция пакета обратно в сеть
bool WinDivertManager::send(std::span<const uint8_t> packet, const WINDIVERT_ADDRESS& addr, uint32_t* out_send_len) noexcept {
    HANDLE h = m_handle;
    if (h == INVALID_HANDLE_VALUE) return false;

    UINT send_bytes = 0;
    BOOL ok = deployer::pWinDivertSend(
        h,
        packet.data(),
        static_cast<UINT>(packet.size()),
        &send_bytes,
        &addr
    );

    if (ok && out_send_len) {
        *out_send_len = static_cast<uint32_t>(send_bytes);
    }

    return ok != FALSE;
}

// Отправка с автоматическим расчетом контрольной суммы
bool WinDivertManager::send_recalc_checksums(std::span<uint8_t> packet, WINDIVERT_ADDRESS& addr, uint32_t* out_send_len) noexcept {
    HANDLE h = m_handle;
    if (h == INVALID_HANDLE_VALUE) return false;

    deployer::pWinDivertHelperCalcChecksums(
        packet.data(),
        static_cast<UINT>(packet.size()),
        &addr,
        0
    );

    UINT send_bytes = 0;
    BOOL ok = deployer::pWinDivertSend(
        h,
        packet.data(),
        static_cast<UINT>(packet.size()),
        &send_bytes,
        &addr
    );

    if (ok && out_send_len) {
        *out_send_len = static_cast<uint32_t>(send_bytes);
    }

    return ok != FALSE;
}

// Проверка корректности выражения фильтра
bool WinDivertManager::compile_filter(
    std::string_view filter,
    WINDIVERT_LAYER layer,
    std::string* error_message,
    uint32_t* error_pos)
{
    const char* err_str = nullptr;
    UINT pos = 0;

    std::string filter_null_terminated(filter);
    BOOL ok = deployer::pWinDivertHelperCompileFilter(
        filter_null_terminated.c_str(),
        layer,
        nullptr,
        0,
        &err_str,
        &pos
    );

    if (!ok) {
        if (error_message && err_str) {
            *error_message = err_str;
        }
        if (error_pos) {
            *error_pos = static_cast<uint32_t>(pos);
        }
        return false;
    }

    return true;
}

// Расчет контрольных сумм пакета
void WinDivertManager::calculate_checksums(
    std::span<uint8_t> packet,
    WINDIVERT_ADDRESS* addr,
    uint64_t flags) noexcept
{
    deployer::pWinDivertHelperCalcChecksums(
        packet.data(),
        static_cast<UINT>(packet.size()),
        addr,
        flags
    );
}

std::string WinDivertManager::format_error(DWORD error_code) {
    switch (error_code) {
    case ERROR_FILE_NOT_FOUND:
        return "Файл драйвера WinDivert (WinDivert.sys/WinDivert64.sys) не найден.";
    case ERROR_ACCESS_DENIED:
        return "Требуются права администратора для запуска фильтрации.";
    case ERROR_INVALID_PARAMETER:
        return "Неверный синтаксис фильтра или параметры очереди.";
    case ERROR_INVALID_IMAGE_HASH:
        return "Блокировка цифровой подписи драйвера Windows.";
    case ERROR_DRIVER_FAILED_PRIOR_UNLOAD:
        return "Конфликтующая версия драйвера WinDivert уже загружена в систему.";
    case ERROR_SERVICE_DOES_NOT_EXIST:
        return "Служба WinDivert не существует.";
    case ERROR_NO_DATA:
        return "Дескриптор WinDivert закрыт.";
    case ERROR_OPERATION_ABORTED:
        return "Операция прервана при остановке приложения.";
    case ERROR_HOST_UNREACHABLE:
        return "Обнаружена сетевая петля или узел недоступен.";
    default:
        break;
    }

    LPSTR message_buffer = nullptr;
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&message_buffer),
        0,
        nullptr
    );

    std::string message;
    if (size > 0 && message_buffer) {
        message = message_buffer;
        while (!message.empty() && (message.back() == '\r' || message.back() == '\n')) {
            message.pop_back();
        }
        LocalFree(message_buffer);
    } else {
        std::ostringstream oss;
        oss << "Системная ошибка (код " << error_code << ")";
        message = oss.str();
    }

    return message;
}

} 
