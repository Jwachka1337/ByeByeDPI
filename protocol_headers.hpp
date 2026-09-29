#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <optional>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma pack(push, 1)

// Заголовок IPv4
struct ipv4_header {
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;

    [[nodiscard]] constexpr size_t header_length() const noexcept {
        return static_cast<size_t>(ihl) * 4;
    }

    [[nodiscard]] uint16_t get_total_length() const noexcept {
        return ntohs(total_length);
    }

    [[nodiscard]] uint16_t get_id() const noexcept {
        return ntohs(id);
    }

    [[nodiscard]] uint16_t get_raw_flags_offset() const noexcept {
        return ntohs(flags_fragment_offset);
    }

    [[nodiscard]] bool is_dont_fragment() const noexcept {
        return (get_raw_flags_offset() & 0x4000) != 0;
    }

    [[nodiscard]] bool is_more_fragments() const noexcept {
        return (get_raw_flags_offset() & 0x2000) != 0;
    }

    [[nodiscard]] uint16_t get_fragment_offset_bytes() const noexcept {
        return (get_raw_flags_offset() & 0x1FFF) * 8;
    }

    void set_dont_fragment(bool df) noexcept {
        uint16_t val = ntohs(flags_fragment_offset);
        if (df) {
            val |= 0x4000;
        } else {
            val &= ~0x4000;
        }
        flags_fragment_offset = htons(val);
    }

    void set_more_fragments(bool mf) noexcept {
        uint16_t val = ntohs(flags_fragment_offset);
        if (mf) {
            val |= 0x2000;
        } else {
            val &= ~0x2000;
        }
        flags_fragment_offset = htons(val);
    }

    void set_fragment_offset_bytes(uint16_t offset_bytes) noexcept {
        uint16_t val = ntohs(flags_fragment_offset) & 0xE000;
        val |= (offset_bytes / 8) & 0x1FFF;
        flags_fragment_offset = htons(val);
    }
};

// Заголовок TCP
struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t reserved : 4;
    uint8_t data_offset : 4;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;

    [[nodiscard]] constexpr size_t header_length() const noexcept {
        return static_cast<size_t>(data_offset) * 4;
    }

    [[nodiscard]] uint16_t get_src_port() const noexcept {
        return ntohs(src_port);
    }

    [[nodiscard]] uint16_t get_dst_port() const noexcept {
        return ntohs(dst_port);
    }

    [[nodiscard]] uint32_t get_seq() const noexcept {
        return ntohl(seq_num);
    }

    [[nodiscard]] uint32_t get_ack() const noexcept {
        return ntohl(ack_num);
    }
};

// Флаги TCP
inline constexpr uint8_t TCP_FLAG_FIN = 0x01;
inline constexpr uint8_t TCP_FLAG_SYN = 0x02;
inline constexpr uint8_t TCP_FLAG_RST = 0x04;
inline constexpr uint8_t TCP_FLAG_PSH = 0x08;
inline constexpr uint8_t TCP_FLAG_ACK = 0x10;
inline constexpr uint8_t TCP_FLAG_URG = 0x20;
inline constexpr uint8_t TCP_FLAG_ECE = 0x40;
inline constexpr uint8_t TCP_FLAG_CWR = 0x80;

// Заголовок UDP
struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;

    [[nodiscard]] uint16_t get_src_port() const noexcept {
        return ntohs(src_port);
    }

    [[nodiscard]] uint16_t get_dst_port() const noexcept {
        return ntohs(dst_port);
    }

    [[nodiscard]] uint16_t get_length() const noexcept {
        return ntohs(length);
    }
};

// Псевдозаголовок IPv4 для подсчета контрольной суммы
struct ipv4_pseudo_header {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
};

#pragma pack(pop)

namespace tcp_options {

inline constexpr uint8_t OPT_EOL = 0;
inline constexpr uint8_t OPT_NOP = 1;
inline constexpr uint8_t OPT_TIMESTAMP = 8;

// Подмена метки времени TCP
inline bool corrupt_timestamp_option(uint8_t* options_ptr, size_t options_len, uint32_t new_tsval = 0) noexcept {
    if (!options_ptr || options_len < 10) return false;
    size_t offset = 0;
    while (offset < options_len) {
        uint8_t kind = options_ptr[offset];
        if (kind == OPT_EOL) {
            break;
        }
        if (kind == OPT_NOP) {
            offset += 1;
            continue;
        }
        if (offset + 1 >= options_len) {
            break;
        }
        uint8_t len = options_ptr[offset + 1];
        if (len < 2 || offset + len > options_len) {
            break;
        }
        if (kind == OPT_TIMESTAMP && len >= 10) {
            uint32_t val = htonl(new_tsval);
            std::memcpy(options_ptr + offset + 2, &val, 4);
            return true;
        }
        offset += len;
    }
    return false;
}

} 

inline constexpr uint8_t IPPROTO_ICMP_VAL = 1;
inline constexpr uint8_t IPPROTO_TCP_VAL  = 6;
inline constexpr uint8_t IPPROTO_UDP_VAL  = 17;

namespace checksum {

inline uint32_t accumulate(const void* buffer, size_t length, uint32_t initial = 0) noexcept {
    uint32_t sum = initial;
    const auto* bytes = static_cast<const uint8_t*>(buffer);

    while (length >= 2) {
        uint16_t word;
        std::memcpy(&word, bytes, 2);
        sum += word;
        bytes += 2;
        length -= 2;
    }

    if (length == 1) {
        uint16_t word = 0;
        std::memcpy(&word, bytes, 1);
        sum += word;
    }

    return sum;
}

inline uint16_t finalize(uint32_t sum) noexcept {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

// Контрольная сумма заголовка IPv4
inline uint16_t compute_ipv4_header_checksum(ipv4_header* ip) noexcept {
    ip->checksum = 0;
    uint32_t sum = accumulate(ip, ip->header_length());
    ip->checksum = finalize(sum);
    return ip->checksum;
}

// Проверка контрольной суммы IPv4
inline bool verify_ipv4_checksum(const ipv4_header* ip) noexcept {
    if (ip->header_length() < sizeof(ipv4_header)) return false;
    uint32_t sum = accumulate(ip, ip->header_length());
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(sum) == 0xFFFF;
}

// Контрольная сумма TCP
inline uint16_t compute_tcp_checksum(
    const ipv4_header* ip,
    tcp_header* tcp,
    std::span<const uint8_t> tcp_options,
    std::span<const uint8_t> payload) noexcept
{
    tcp->checksum = 0;

    const uint16_t l4_total_length = static_cast<uint16_t>(sizeof(tcp_header) + tcp_options.size() + payload.size());

    ipv4_pseudo_header pseudo{};
    pseudo.src_ip = ip->src_ip;
    pseudo.dst_ip = ip->dst_ip;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_TCP_VAL;
    pseudo.length = htons(l4_total_length);

    uint32_t sum = accumulate(&pseudo, sizeof(pseudo));
    sum = accumulate(tcp, sizeof(tcp_header), sum);

    if (!tcp_options.empty()) {
        sum = accumulate(tcp_options.data(), tcp_options.size(), sum);
    }
    if (!payload.empty()) {
        sum = accumulate(payload.data(), payload.size(), sum);
    }

    tcp->checksum = finalize(sum);
    return tcp->checksum;
}

// Контрольная сумма UDP
inline uint16_t compute_udp_checksum(
    const ipv4_header* ip,
    udp_header* udp,
    std::span<const uint8_t> payload) noexcept
{
    udp->checksum = 0;

    const uint16_t l4_total_length = static_cast<uint16_t>(sizeof(udp_header) + payload.size());

    ipv4_pseudo_header pseudo{};
    pseudo.src_ip = ip->src_ip;
    pseudo.dst_ip = ip->dst_ip;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_UDP_VAL;
    pseudo.length = htons(l4_total_length);

    uint32_t sum = accumulate(&pseudo, sizeof(pseudo));
    sum = accumulate(udp, sizeof(udp_header), sum);

    if (!payload.empty()) {
        sum = accumulate(payload.data(), payload.size(), sum);
    }

    uint16_t csum = finalize(sum);
    if (csum == 0) {
        csum = 0xFFFF;
    }
    udp->checksum = csum;
    return udp->checksum;
}

} 
