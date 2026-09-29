#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windivert.h>

#include <span>
#include <string>
#include <string_view>
#include <optional>
#include <memory>
#include <atomic>
#include <cstdint>
#include <mutex>

namespace divert {

// Фильтр трафика для перехвата HTTPS, QUIC и голосовых портов
inline constexpr const char* DEFAULT_FILTER =
    "outbound and !loopback and ("
    "tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 2053 or tcp.DstPort == 2083 or "
    "tcp.DstPort == 2087 or tcp.DstPort == 2096 or tcp.DstPort == 8443 or "
    "udp.DstPort == 443 or "
    "(udp.DstPort >= 19294 and udp.DstPort <= 19344) or "
    "(udp.DstPort >= 50000 and udp.DstPort <= 50100)"
    ")";

// Параметры очереди пакетов
inline constexpr uint64_t DEFAULT_QUEUE_LENGTH = 8192;
inline constexpr uint64_t DEFAULT_QUEUE_TIME   = 2000;
inline constexpr uint64_t DEFAULT_QUEUE_SIZE   = 16 * 1024 * 1024;

// Настройки драйвера
struct DivertConfig {
    std::string filter{DEFAULT_FILTER};
    WINDIVERT_LAYER layer{WINDIVERT_LAYER_NETWORK};
    int16_t priority{0};
    uint64_t flags{0};
    uint64_t queue_length{DEFAULT_QUEUE_LENGTH};
    uint64_t queue_time{DEFAULT_QUEUE_TIME};
    uint64_t queue_size{DEFAULT_QUEUE_SIZE};
};

// Класс управления фильтром WinDivert
class WinDivertManager {
public:
    WinDivertManager() noexcept = default;
    explicit WinDivertManager(const DivertConfig& config);

    ~WinDivertManager() noexcept;

    WinDivertManager(const WinDivertManager&) = delete;
    WinDivertManager& operator=(const WinDivertManager&) = delete;

    WinDivertManager(WinDivertManager&& other) noexcept;
    WinDivertManager& operator=(WinDivertManager&& other) noexcept;

    bool open(const DivertConfig& config = {});

    void shutdown(WINDIVERT_SHUTDOWN how = WINDIVERT_SHUTDOWN_BOTH) noexcept;

    void close() noexcept;

    [[nodiscard]] bool is_open() const noexcept;

    [[nodiscard]] HANDLE native_handle() const noexcept { return m_handle; }

    bool set_param(WINDIVERT_PARAM param, uint64_t value) noexcept;

    bool get_param(WINDIVERT_PARAM param, uint64_t& out_value) const noexcept;

    bool recv(std::span<uint8_t> buffer, WINDIVERT_ADDRESS& out_addr, uint32_t& out_recv_len) noexcept;
  
    bool send(std::span<const uint8_t> packet, const WINDIVERT_ADDRESS& addr, uint32_t* out_send_len = nullptr) noexcept;
   
    bool send_recalc_checksums(std::span<uint8_t> packet, WINDIVERT_ADDRESS& addr, uint32_t* out_send_len = nullptr) noexcept;

   
    static bool compile_filter(
        std::string_view filter,
        WINDIVERT_LAYER layer = WINDIVERT_LAYER_NETWORK,
        std::string* error_message = nullptr,
        uint32_t* error_pos = nullptr);

   
    static void calculate_checksums(
        std::span<uint8_t> packet,
        WINDIVERT_ADDRESS* addr = nullptr,
        uint64_t flags = 0) noexcept;


    static std::string format_error(DWORD error_code);

    [[nodiscard]] const DivertConfig& config() const noexcept { return m_config; }

private:
    HANDLE m_handle{INVALID_HANDLE_VALUE};
    DivertConfig m_config{};
    std::atomic<bool> m_is_open{false};
    mutable std::mutex m_handle_mutex{};
};

} 
