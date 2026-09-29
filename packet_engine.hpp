#pragma once

#include "protocol_headers.hpp"
#include "embedded_payloads.hpp"

#include <cstdint>
#include <vector>
#include <span>
#include <string>
#include <string_view>
#include <optional>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <atomic>

namespace engine {

// Политика для UDP 
enum class UdpRtcPolicy {
    None,
    IpFragmentation,
    LowTtlProbe,
    FakePayload
};

enum class FakePacketMode {
    None,
    BadChecksum,
    Ttl,
    TcpTimestamp
};

enum class DesyncMode {
    FakeSplit,
    SeqOverlap
};

// Стратегия нарезки TLS ClientHello
enum class TlsSplitStrategy {
    SplitPos2,
    SplitPos1,
    HostBoundary,
    MidSni
};

enum class ActionDisposition {
    PassUnmodified,
    Drop,
    EmitReplacement
};

struct EmittedPacket {
    std::vector<uint8_t> data;
    bool recalc_checksum{true};
};

struct ProcessResult {
    ActionDisposition disposition{ActionDisposition::PassUnmodified};
    std::vector<EmittedPacket> packets_to_emit;
    std::string diagnostics;
};

struct SniInfo {
    std::string hostname;
    size_t host_offset_in_payload{0};
    size_t host_length{0};
};

struct EngineMetrics {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> ipv4_packets{0};
    std::atomic<uint64_t> ipv6_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> tls_client_hellos{0};
    std::atomic<uint64_t> tcp_segments_created{0};
    std::atomic<uint64_t> tcp_fake_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> udp_443_blocked{0};
    std::atomic<uint64_t> udp_rtc_probes{0};
    std::atomic<uint64_t> udp_rtc_fragments{0};
    std::atomic<uint64_t> passthrough_packets{0};
    std::atomic<uint64_t> non_ip_or_ignored{0};
};

// Сессия UDP
struct UdpSessionKey {
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};

    bool operator==(const UdpSessionKey& other) const noexcept {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port;
    }
};

struct UdpSessionKeyHash {
    size_t operator()(const UdpSessionKey& k) const noexcept {
        size_t h1 = std::hash<uint32_t>{}(k.src_ip);
        size_t h2 = std::hash<uint32_t>{}(k.dst_ip);
        size_t h3 = std::hash<uint16_t>{}(k.src_port);
        size_t h4 = std::hash<uint16_t>{}(k.dst_port);
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
    }
};

struct UdpSessionState {
    std::chrono::steady_clock::time_point last_seen;
    uint32_t packet_count{0};
};

struct EngineConfig {
    std::vector<uint8_t> quic_fake_payload;
    uint32_t quic_fake_repeats{11};
    uint32_t udp_fake_cutoff{4};
    uint32_t udp_fake_repeats{4};
    std::vector<uint8_t> udp_fake_payload;
    bool enable_tcp_sni_segmentation{true};
    bool reverse_segment_order{true};
    FakePacketMode fake_mode{FakePacketMode::TcpTimestamp};
    uint32_t fake_repeats{4};
    uint8_t fake_ttl{3};
    std::string fake_sni{"www.google.com"};
    bool enable_udp_443_redirection{true};
    UdpRtcPolicy udp_rtc_policy{UdpRtcPolicy::FakePayload};
    uint8_t probe_ttl{2};
    std::chrono::seconds session_timeout{60};
    TlsSplitStrategy tls_split_strategy{TlsSplitStrategy::SplitPos1};
    size_t fallback_split_offset{1};
    bool drop_ipv6_target_ports{true};
    std::vector<uint8_t> custom_fake_payload;

    DesyncMode default_desync_mode{DesyncMode::FakeSplit};
    DesyncMode google_desync_mode{DesyncMode::SeqOverlap};
    size_t seqovl_offset{1};
    size_t seqovl_size{480};
    std::vector<uint8_t> seqovl_pattern_payload;
    std::string seqovl_substitute_host{"www.google.com"};
    bool ip_id_zero_google{true};

    bool bypass_all_domains{true};
    std::vector<std::string> google_hostlist;
    std::vector<std::string> custom_domains;
};

// Сетевой движок обработки пакетов
class PacketEngine {
public:
    explicit PacketEngine(EngineConfig config = {});

    [[nodiscard]] ProcessResult process_packet(std::span<const uint8_t> raw_packet);

    // Извлечение SNI из заголовка TLS
    [[nodiscard]] static std::optional<SniInfo> extract_sni(std::span<const uint8_t> payload) noexcept;

    // Нарезка TLS ClientHello по выбранной стратегии
    [[nodiscard]] static std::vector<EmittedPacket> segment_tcp_sni(
        std::span<const uint8_t> raw_packet,
        const SniInfo& sni,
        TlsSplitStrategy strategy = TlsSplitStrategy::SplitPos1);

    [[nodiscard]] static std::vector<EmittedPacket> segment_tcp_at_offset(
        std::span<const uint8_t> raw_packet,
        size_t split_offset);

    [[nodiscard]] static EmittedPacket create_fake_tls_packet(
        const ipv4_header* orig_ip,
        const tcp_header* orig_tcp,
        std::span<const uint8_t> tcp_options,
        std::string_view fake_sni,
        FakePacketMode mode,
        uint8_t fake_ttl,
        std::span<const uint8_t> custom_payload = {});

    [[nodiscard]] std::vector<EmittedPacket> create_seqovl_segments(
        std::span<const uint8_t> raw_packet,
        const SniInfo& sni,
        std::string_view substitute_host,
        size_t split_offset,
        FakePacketMode fooling_mode,
        uint8_t fake_ttl,
        bool set_ip_id_zero);

    [[nodiscard]] bool is_google_domain(std::string_view hostname) const;

    [[nodiscard]] bool is_target_domain(std::string_view hostname) const;

    void add_custom_domain(const std::string& domain);
    void remove_custom_domain(const std::string& domain);
    void set_custom_domains(const std::vector<std::string>& domains);
    [[nodiscard]] std::vector<std::string> get_custom_domains() const;

    // Фрагментация пакета UDP
    [[nodiscard]] static std::vector<EmittedPacket> fragment_udp_datagram(
        std::span<const uint8_t> raw_packet);

    [[nodiscard]] const EngineMetrics& metrics() const noexcept { return m_metrics; }
    [[nodiscard]] EngineConfig& config() noexcept { return m_config; }

    void reset_metrics() noexcept;

    static bool is_target_tcp_port(uint16_t port) noexcept {
        return port == 80 || port == 443 || port == 8443 ||
               port == 2053 || port == 2083 || port == 2087 || port == 2096;
    }

    static bool is_target_udp_rtc_port(uint16_t port) noexcept {
        return (port >= 19294 && port <= 19344) || (port >= 50000 && port <= 50100);
    }

private:
    ProcessResult handle_tcp(std::span<const uint8_t> packet, const ipv4_header* ip);
    ProcessResult handle_udp(std::span<const uint8_t> packet, const ipv4_header* ip);
    ProcessResult handle_ipv6(std::span<const uint8_t> packet);

    EngineConfig m_config;
    EngineMetrics m_metrics;
    std::mutex m_session_mutex;
    mutable std::mutex m_domains_mutex;
    std::unordered_map<UdpSessionKey, UdpSessionState, UdpSessionKeyHash> m_udp_sessions;
};

} 
