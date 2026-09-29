#include "packet_engine.hpp"

#include <iostream>
#include <algorithm>
#include <sstream>

namespace engine {

namespace {

const std::vector<std::string> DEFAULT_GOOGLE_DOMAINS = {
    "youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com",
    "youtu.be", "google.com", "googleapis.com", "googleusercontent.com",
    "youtube-nocookie.com", "youtubekids.com", "google.ru", "gvt1.com",
    "wide-youtube.l.google.com", "youtube-ui.l.google.com", "yt-video-upload.l.google.com",
    "yt3.ggpht.com", "yt4.ggpht.com", "yt3.googleusercontent.com", "jnn-pa.googleapis.com"
};

bool match_domain_suffix(std::string_view host, const std::string& domain) {
    if (host.size() == domain.size()) {
        return _strnicmp(host.data(), domain.data(), host.size()) == 0;
    } else if (host.size() > domain.size()) {
        size_t pos = host.size() - domain.size();
        return (host[pos - 1] == '.' && _strnicmp(host.data() + pos, domain.data(), domain.size()) == 0);
    }
    return false;
}

std::string generate_matching_fake_host(size_t host_size, std::string_view base_substitute) {
    if (base_substitute.empty()) {
        base_substitute = "www.google.com";
    }

    if (host_size <= base_substitute.size()) {
        return std::string(base_substitute.substr(base_substitute.size() - host_size, host_size));
    }

    std::string_view target_base = base_substitute;
    if (target_base.starts_with("www.") && (host_size - target_base.size() < 2)) {
        target_base = target_base.substr(4);
    }

    if (host_size <= target_base.size()) {
        return std::string(target_base.substr(target_base.size() - host_size, host_size));
    }

    size_t prefix_len = host_size - target_base.size() - 1;
    std::string fakehost;
    fakehost.reserve(host_size);
    static const char letters[] = "abcdefghijklmnopqrstuvwxyz";
    for (size_t i = 0; i < prefix_len; ++i) {
        fakehost.push_back(letters[(i * 7 + host_size) % 26]);
    }
    fakehost.push_back('.');
    fakehost.append(target_base);
    return fakehost;
}

} 

PacketEngine::PacketEngine(EngineConfig config)
    : m_config(std::move(config)) {
    // Инициализация встроенных пейлоадов по умолчанию
    if (m_config.custom_fake_payload.empty()) {
        m_config.custom_fake_payload.assign(
            std::begin(embedded::tls_clienthello_www_google_com),
            std::end(embedded::tls_clienthello_www_google_com)
        );
    }
    if (m_config.quic_fake_payload.empty()) {
        m_config.quic_fake_payload.assign(
            std::begin(embedded::quic_initial_www_google_com),
            std::end(embedded::quic_initial_www_google_com)
        );
    }
    if (m_config.udp_fake_payload.empty()) {
        m_config.udp_fake_payload.assign(
            std::begin(embedded::active_discord_udp),
            std::end(embedded::active_discord_udp)
        );
    }
    if (m_config.seqovl_pattern_payload.empty()) {
        m_config.seqovl_pattern_payload.assign(
            std::begin(embedded::stun2),
            std::end(embedded::stun2)
        );
    }
}

void PacketEngine::reset_metrics() noexcept {
    m_metrics.total_packets = 0;
    m_metrics.ipv4_packets = 0;
    m_metrics.ipv6_packets = 0;
    m_metrics.tcp_packets = 0;
    m_metrics.tls_client_hellos = 0;
    m_metrics.tcp_segments_created = 0;
    m_metrics.tcp_fake_packets = 0;
    m_metrics.udp_packets = 0;
    m_metrics.udp_443_blocked = 0;
    m_metrics.udp_rtc_probes = 0;
    m_metrics.udp_rtc_fragments = 0;
    m_metrics.passthrough_packets = 0;
    m_metrics.non_ip_or_ignored = 0;
}

bool PacketEngine::is_google_domain(std::string_view hostname) const {
    std::lock_guard<std::mutex> lock(m_domains_mutex);
    for (const auto& domain : m_config.google_hostlist) {
        if (match_domain_suffix(hostname, domain)) return true;
    }
    for (const auto& domain : DEFAULT_GOOGLE_DOMAINS) {
        if (match_domain_suffix(hostname, domain)) return true;
    }
    return false;
}

bool PacketEngine::is_target_domain(std::string_view hostname) const {
    if (is_google_domain(hostname)) return true;

    std::lock_guard<std::mutex> lock(m_domains_mutex);
    for (const auto& domain : m_config.custom_domains) {
        if (match_domain_suffix(hostname, domain)) return true;
    }
    return false;
}

void PacketEngine::add_custom_domain(const std::string& domain) {
    if (domain.empty()) return;
    std::lock_guard<std::mutex> lock(m_domains_mutex);
    for (const auto& d : m_config.custom_domains) {
        if (_stricmp(d.c_str(), domain.c_str()) == 0) return;
    }
    m_config.custom_domains.push_back(domain);
}

void PacketEngine::remove_custom_domain(const std::string& domain) {
    std::lock_guard<std::mutex> lock(m_domains_mutex);
    auto it = std::remove_if(m_config.custom_domains.begin(), m_config.custom_domains.end(),
        [&domain](const std::string& d) {
            return _stricmp(d.c_str(), domain.c_str()) == 0;
        });
    m_config.custom_domains.erase(it, m_config.custom_domains.end());
}

void PacketEngine::set_custom_domains(const std::vector<std::string>& domains) {
    std::lock_guard<std::mutex> lock(m_domains_mutex);
    m_config.custom_domains = domains;
}

std::vector<std::string> PacketEngine::get_custom_domains() const {
    std::lock_guard<std::mutex> lock(m_domains_mutex);
    return m_config.custom_domains;
}

ProcessResult PacketEngine::process_packet(std::span<const uint8_t> raw_packet) {
    m_metrics.total_packets++;

    if (raw_packet.empty()) {
        m_metrics.non_ip_or_ignored++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    const uint8_t ip_ver = (raw_packet[0] >> 4) & 0x0F;

    if (ip_ver == 6) {
        m_metrics.ipv6_packets++;
        return handle_ipv6(raw_packet);
    }

    if (ip_ver != 4 || raw_packet.size() < sizeof(ipv4_header)) {
        m_metrics.non_ip_or_ignored++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    m_metrics.ipv4_packets++;

    const auto* ip = reinterpret_cast<const ipv4_header*>(raw_packet.data());
    const size_t ip_len = ip->header_length();
    if (ip_len < sizeof(ipv4_header) || ip_len > raw_packet.size()) {
        m_metrics.non_ip_or_ignored++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    const size_t total_ip_len = ip->get_total_length();
    if (total_ip_len > raw_packet.size()) {
        m_metrics.non_ip_or_ignored++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    std::span<const uint8_t> datagram = raw_packet.subspan(0, total_ip_len);

    if (ip->protocol == IPPROTO_TCP_VAL) {
        return handle_tcp(datagram, ip);
    } else if (ip->protocol == IPPROTO_UDP_VAL) {
        return handle_udp(datagram, ip);
    }

    m_metrics.passthrough_packets++;
    return { ActionDisposition::PassUnmodified, {}, "" };
}

// Обработка IPv6
ProcessResult PacketEngine::handle_ipv6(std::span<const uint8_t> packet) {
    if (packet.size() < 40) {
        m_metrics.passthrough_packets++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    const uint8_t next_hdr = packet[6];
    if (next_hdr == IPPROTO_TCP_VAL || next_hdr == IPPROTO_UDP_VAL) {
        if (packet.size() >= 44) {
            const uint16_t dst_port = (static_cast<uint16_t>(packet[42]) << 8) | packet[43];
            const bool is_target = is_target_tcp_port(dst_port) || (dst_port == 443) || is_target_udp_rtc_port(dst_port);

            if (is_target && m_config.drop_ipv6_target_ports) {
                m_metrics.non_ip_or_ignored++;
                return { ActionDisposition::Drop, {}, "" };
            }
        }
    }

    m_metrics.passthrough_packets++;
    return { ActionDisposition::PassUnmodified, {}, "" };
}

// Обработка TCP трафика
ProcessResult PacketEngine::handle_tcp(std::span<const uint8_t> packet, const ipv4_header* ip) {
    m_metrics.tcp_packets++;

    const size_t ip_len = ip->header_length();
    if (packet.size() < ip_len + sizeof(tcp_header)) {
        m_metrics.passthrough_packets++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    const auto* tcp = reinterpret_cast<const tcp_header*>(packet.data() + ip_len);
    const size_t tcp_len = tcp->header_length();
    if (tcp_len < sizeof(tcp_header) || packet.size() < ip_len + tcp_len) {
        m_metrics.passthrough_packets++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    const uint16_t dst_port = tcp->get_dst_port();
    if (!is_target_tcp_port(dst_port)) {
        m_metrics.passthrough_packets++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    const size_t payload_offset = ip_len + tcp_len;
    const size_t payload_len = packet.size() - payload_offset;

    if (payload_len == 0) {
        m_metrics.passthrough_packets++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    if (!m_config.enable_tcp_sni_segmentation) {
        m_metrics.passthrough_packets++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    std::span<const uint8_t> payload = packet.subspan(payload_offset, payload_len);
    if (payload.size() < 5) {
        m_metrics.passthrough_packets++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    bool is_tls_handshake = (payload[0] == 0x16);
    if (is_tls_handshake) {
        m_metrics.tls_client_hellos++;
    }

    auto sni_opt = extract_sni(payload);

    if (!m_config.bypass_all_domains && sni_opt.has_value()) {
        if (!is_target_domain(sni_opt->hostname)) {
            m_metrics.passthrough_packets++;
            return { ActionDisposition::PassUnmodified, {}, "" };
        }
    }

    std::ostringstream oss;

    if (sni_opt.has_value() && is_google_domain(sni_opt->hostname) &&
        m_config.google_desync_mode == DesyncMode::SeqOverlap) {
        const auto& sni = *sni_opt;

        auto segments = create_seqovl_segments(
            packet, sni,
            m_config.seqovl_substitute_host,
            m_config.seqovl_offset,
            m_config.fake_mode,
            m_config.fake_ttl,
            m_config.ip_id_zero_google);

        m_metrics.tcp_segments_created += segments.size();
        m_metrics.tcp_fake_packets++;

        return { ActionDisposition::EmitReplacement, std::move(segments), oss.str() };
    }

    std::vector<EmittedPacket> real_segments;

    if (sni_opt.has_value()) {
        const auto& sni = *sni_opt;
        real_segments = segment_tcp_sni(packet, sni, m_config.tls_split_strategy);
        m_metrics.tcp_segments_created += real_segments.size();
    } else {
        size_t split_offset = (m_config.fallback_split_offset >= 1 && m_config.fallback_split_offset < payload.size())
                              ? m_config.fallback_split_offset : 2;

        real_segments = segment_tcp_at_offset(packet, split_offset);
        m_metrics.tcp_segments_created += real_segments.size();
    }

    std::vector<EmittedPacket> emit_list;

    if (m_config.fake_mode != FakePacketMode::None) {
        std::span<const uint8_t> tcp_options = packet.subspan(ip_len + sizeof(tcp_header), tcp_len - sizeof(tcp_header));
        auto fake_pkt = create_fake_tls_packet(
            ip, tcp, tcp_options, m_config.fake_sni, m_config.fake_mode, m_config.fake_ttl,
            m_config.custom_fake_payload
        );
        for (uint32_t r = 0; r < m_config.fake_repeats; ++r) {
            std::vector<uint8_t> pkt_copy = fake_pkt.data;
            auto* ip_copy = reinterpret_cast<ipv4_header*>(pkt_copy.data());
            static std::atomic<uint16_t> s_fake_copy_id{0x6666};
            ip_copy->id = htons(s_fake_copy_id.fetch_add(1, std::memory_order_relaxed));
            checksum::compute_ipv4_header_checksum(ip_copy);
            emit_list.push_back(EmittedPacket{ std::move(pkt_copy), fake_pkt.recalc_checksum });
        }
        m_metrics.tcp_fake_packets += m_config.fake_repeats;
    }

    if (!m_config.seqovl_pattern_payload.empty() && real_segments.size() == 2 && !m_config.reverse_segment_order) {
        size_t ovl_size = m_config.seqovl_size;
        std::vector<uint8_t> ovl_payload(ovl_size, 0);
        for (size_t i = 0; i < ovl_size; ++i) {
            ovl_payload[i] = m_config.seqovl_pattern_payload[i % m_config.seqovl_pattern_payload.size()];
        }
        const size_t orig_tcp_opts_len = tcp_len - sizeof(tcp_header);
        const uint8_t* orig_tcp_opts = packet.data() + ip_len + sizeof(tcp_header);
        const size_t headers_len = ip_len + tcp_len;
        std::vector<uint8_t> pkt(headers_len + ovl_size);
        std::memcpy(pkt.data(), ip, ip_len);
        auto* nip = reinterpret_cast<ipv4_header*>(pkt.data());
        nip->total_length = htons(static_cast<uint16_t>(pkt.size()));
        
        static std::atomic<uint16_t> s_ovl_id_gen{0x8765};
        nip->id = htons(s_ovl_id_gen.fetch_add(1, std::memory_order_relaxed));

        std::memcpy(pkt.data() + ip_len, tcp, sizeof(tcp_header));
        auto* ntcp = reinterpret_cast<tcp_header*>(pkt.data() + ip_len);
        uint32_t seg2_seq = ntohl(reinterpret_cast<const tcp_header*>(real_segments[1].data.data() + ip_len)->seq_num);
        ntcp->seq_num = htonl(seg2_seq);
        uint8_t* dst_opts = pkt.data() + ip_len + sizeof(tcp_header);
        if (orig_tcp_opts_len > 0) std::memcpy(dst_opts, orig_tcp_opts, orig_tcp_opts_len);
        std::memcpy(pkt.data() + headers_len, ovl_payload.data(), ovl_size);
        bool ts_corrupted = false;
        if (m_config.fake_mode == FakePacketMode::TcpTimestamp && orig_tcp_opts_len > 0) {
            ts_corrupted = tcp_options::corrupt_timestamp_option(dst_opts, orig_tcp_opts_len, 0);
        }
        if (m_config.fake_mode == FakePacketMode::Ttl || (!ts_corrupted && m_config.fake_mode == FakePacketMode::TcpTimestamp)) {
            nip->ttl = (m_config.fake_ttl > 0 ? m_config.fake_ttl : 3);
        }
        checksum::compute_ipv4_header_checksum(nip);
        checksum::compute_tcp_checksum(nip, ntcp, std::span<const uint8_t>(dst_opts, orig_tcp_opts_len), ovl_payload);
        
        EmittedPacket ovl_seg{ std::move(pkt), true };
        if (m_config.fake_mode == FakePacketMode::BadChecksum) {
            auto* p_tcp = reinterpret_cast<tcp_header*>(ovl_seg.data.data() + ip_len);
            p_tcp->checksum = htons(0xDEAD);
            ovl_seg.recalc_checksum = false;
        }
        
        emit_list.push_back(std::move(real_segments[0]));
        emit_list.push_back(std::move(ovl_seg));
        emit_list.push_back(std::move(real_segments[1]));
    } else if (m_config.reverse_segment_order && real_segments.size() == 2) {
        emit_list.push_back(std::move(real_segments[1]));
        emit_list.push_back(std::move(real_segments[0]));
    } else {
        for (auto& seg : real_segments) {
            emit_list.push_back(std::move(seg));
        }
    }

    return { ActionDisposition::EmitReplacement, std::move(emit_list), oss.str() };
}

// Обработка UDP трафика
ProcessResult PacketEngine::handle_udp(std::span<const uint8_t> packet, const ipv4_header* ip) {
    m_metrics.udp_packets++;

    const size_t ip_len = ip->header_length();
    if (packet.size() < ip_len + sizeof(udp_header)) {
        m_metrics.passthrough_packets++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    const auto* udp = reinterpret_cast<const udp_header*>(packet.data() + ip_len);
    const uint16_t dst_port = udp->get_dst_port();
    const uint16_t src_port = udp->get_src_port();

    const bool is_quic = (dst_port == 443);
    const bool is_rtc  = is_target_udp_rtc_port(dst_port);

    if (!is_quic && !is_rtc) {
        m_metrics.passthrough_packets++;
        return { ActionDisposition::PassUnmodified, {}, "" };
    }

    UdpSessionKey key{ ip->src_ip, ip->dst_ip, src_port, dst_port };
    const auto now = std::chrono::steady_clock::now();
    uint32_t current_count = 0;

    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        auto it = m_udp_sessions.find(key);
        if (it == m_udp_sessions.end() || (now - it->second.last_seen) > m_config.session_timeout) {
            m_udp_sessions[key] = { now, 1 };
            current_count = 1;
        } else {
            it->second.last_seen = now;
            it->second.packet_count++;
            current_count = it->second.packet_count;
        }
    }

    std::vector<EmittedPacket> emit_list;

    // Обход QUIC (UDP 443)
    if (is_quic) {
        if (!m_config.quic_fake_payload.empty()) {
            const size_t udp_hdr_len = sizeof(udp_header);
            const uint8_t* udp_payload = packet.data() + ip_len + udp_hdr_len;
            const size_t udp_payload_len = packet.size() - ip_len - udp_hdr_len;
            bool is_quic_initial = (udp_payload_len > 0 && (udp_payload[0] & 0x80) != 0);

            if (is_quic_initial || current_count <= 2) {
                std::vector<uint8_t> fake_pkt(ip_len + sizeof(udp_header) + m_config.quic_fake_payload.size());
                std::memcpy(fake_pkt.data(), packet.data(), ip_len + sizeof(udp_header));
                std::memcpy(fake_pkt.data() + ip_len + sizeof(udp_header), m_config.quic_fake_payload.data(), m_config.quic_fake_payload.size());

                auto* fake_ip = reinterpret_cast<ipv4_header*>(fake_pkt.data());
                fake_ip->total_length = htons(static_cast<uint16_t>(fake_pkt.size()));
                
                static std::atomic<uint16_t> s_quic_fake_id{0x4444};
                fake_ip->id = htons(s_quic_fake_id.fetch_add(1, std::memory_order_relaxed));

                checksum::compute_ipv4_header_checksum(fake_ip);

                auto* fake_udp = reinterpret_cast<udp_header*>(fake_pkt.data() + ip_len);
                fake_udp->length = htons(static_cast<uint16_t>(sizeof(udp_header) + m_config.quic_fake_payload.size()));

                for (uint32_t i = 0; i < m_config.quic_fake_repeats; ++i) {
                    std::vector<uint8_t> pkt_copy = fake_pkt;
                    auto* ip_copy = reinterpret_cast<ipv4_header*>(pkt_copy.data());
                    static std::atomic<uint16_t> s_quic_copy_id{0x4445};
                    ip_copy->id = htons(s_quic_copy_id.fetch_add(1, std::memory_order_relaxed));
                    checksum::compute_ipv4_header_checksum(ip_copy);
                    emit_list.push_back(EmittedPacket{ std::move(pkt_copy), true });
                }
            }
        } else if (m_config.enable_udp_443_redirection) {
            m_metrics.udp_443_blocked++;
            return { ActionDisposition::Drop, {}, "" };
        }
    }
    // Обход голосового трафика 
    else if (is_rtc && m_config.udp_rtc_policy == UdpRtcPolicy::FakePayload && !m_config.udp_fake_payload.empty() && current_count <= m_config.udp_fake_cutoff) {
        std::vector<uint8_t> fake_pkt(ip_len + sizeof(udp_header) + m_config.udp_fake_payload.size());
        std::memcpy(fake_pkt.data(), packet.data(), ip_len + sizeof(udp_header));
        std::memcpy(fake_pkt.data() + ip_len + sizeof(udp_header), m_config.udp_fake_payload.data(), m_config.udp_fake_payload.size());

        auto* fake_ip = reinterpret_cast<ipv4_header*>(fake_pkt.data());
        fake_ip->total_length = htons(static_cast<uint16_t>(fake_pkt.size()));
        
        static std::atomic<uint16_t> s_rtc_fake_id{0x3333};
        fake_ip->id = htons(s_rtc_fake_id.fetch_add(1, std::memory_order_relaxed));

        checksum::compute_ipv4_header_checksum(fake_ip);

        auto* fake_udp = reinterpret_cast<udp_header*>(fake_pkt.data() + ip_len);
        fake_udp->length = htons(static_cast<uint16_t>(sizeof(udp_header) + m_config.udp_fake_payload.size()));

        for (uint32_t i = 0; i < m_config.udp_fake_repeats; ++i) {
            std::vector<uint8_t> pkt_copy = fake_pkt;
            auto* ip_copy = reinterpret_cast<ipv4_header*>(pkt_copy.data());
            static std::atomic<uint16_t> s_rtc_copy_id{0x3334};
            ip_copy->id = htons(s_rtc_copy_id.fetch_add(1, std::memory_order_relaxed));
            checksum::compute_ipv4_header_checksum(ip_copy);
            emit_list.push_back(EmittedPacket{ std::move(pkt_copy), true });
        }
    }

    std::vector<uint8_t> original(packet.begin(), packet.end());
    emit_list.push_back(EmittedPacket{ std::move(original), true });

    return { ActionDisposition::EmitReplacement, std::move(emit_list), "" };
}

// Извлечение имени хоста (SNI) из пакета
std::optional<SniInfo> PacketEngine::extract_sni(std::span<const uint8_t> payload) noexcept {
    if (payload.size() < 9) return std::nullopt;
    if (payload[0] != 0x16) return std::nullopt;
    if (payload[5] != 0x01) return std::nullopt;

    size_t pos = 43;
    if (pos >= payload.size()) return std::nullopt;

    const uint8_t session_id_len = payload[pos];
    pos += 1 + session_id_len;

    if (pos + 2 > payload.size()) return std::nullopt;
    const uint16_t cipher_suites_len = (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
    pos += 2 + cipher_suites_len;

    if (pos + 1 > payload.size()) return std::nullopt;
    const uint8_t compression_len = payload[pos];
    pos += 1 + compression_len;

    if (pos + 2 > payload.size()) return std::nullopt;
    const uint16_t extensions_len = (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
    pos += 2;

    const size_t extensions_end = std::min(payload.size(), pos + extensions_len);

    while (pos + 4 <= extensions_end) {
        const uint16_t ext_type = (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
        const uint16_t ext_len  = (static_cast<uint16_t>(payload[pos + 2]) << 8) | payload[pos + 3];
        pos += 4;

        if (pos + ext_len > extensions_end) break;

        // Расширение SNI
        if (ext_type == 0x0000) {
            size_t sni_pos = pos;
            const size_t sni_end = pos + ext_len;

            if (sni_pos + 2 > sni_end) return std::nullopt;
            const uint16_t server_name_list_len = (static_cast<uint16_t>(payload[sni_pos]) << 8) | payload[sni_pos + 1];
            sni_pos += 2;

            const size_t list_end = std::min(sni_end, sni_pos + server_name_list_len);

            while (sni_pos + 3 <= list_end) {
                const uint8_t name_type = payload[sni_pos];
                const uint16_t name_len = (static_cast<uint16_t>(payload[sni_pos + 1]) << 8) | payload[sni_pos + 2];
                sni_pos += 3;

                if (name_type == 0x00 && sni_pos + name_len <= list_end) {
                    SniInfo info;
                    info.host_offset_in_payload = sni_pos;
                    info.host_length = name_len;
                    info.hostname = std::string(reinterpret_cast<const char*>(&payload[sni_pos]), name_len);
                    return info;
                }
                sni_pos += name_len;
            }
        }

        pos += ext_len;
    }

    return std::nullopt;
}

// Создание фейкового пакета TLS
EmittedPacket PacketEngine::create_fake_tls_packet(
    const ipv4_header* orig_ip,
    const tcp_header* orig_tcp,
    std::span<const uint8_t> tcp_options,
    std::string_view fake_sni,
    FakePacketMode mode,
    uint8_t fake_ttl,
    std::span<const uint8_t> custom_payload)
{
    std::vector<uint8_t> tls_record;

    if (!custom_payload.empty()) {
        tls_record.assign(custom_payload.begin(), custom_payload.end());
    } else {
        std::vector<uint8_t> body;

        body.push_back(0x03);
        body.push_back(0x03);

        for (int i = 0; i < 32; ++i) {
            body.push_back(static_cast<uint8_t>(i ^ 0x5A));
        }

        body.push_back(0x00);
        body.push_back(0x00);
        body.push_back(0x02);
        body.push_back(0x13);
        body.push_back(0x01);
        body.push_back(0x01);
        body.push_back(0x00);

        std::vector<uint8_t> sni_ext_data;
        uint16_t host_len = static_cast<uint16_t>(fake_sni.size());
        uint16_t list_len = host_len + 3;

        sni_ext_data.push_back(static_cast<uint8_t>(list_len >> 8));
        sni_ext_data.push_back(static_cast<uint8_t>(list_len & 0xFF));
        sni_ext_data.push_back(0x00);
        sni_ext_data.push_back(static_cast<uint8_t>(host_len >> 8));
        sni_ext_data.push_back(static_cast<uint8_t>(host_len & 0xFF));
        for (char c : fake_sni) {
            sni_ext_data.push_back(static_cast<uint8_t>(c));
        }

        std::vector<uint8_t> extensions;
        extensions.push_back(0x00);
        extensions.push_back(0x00);
        uint16_t ext_data_len = static_cast<uint16_t>(sni_ext_data.size());
        extensions.push_back(static_cast<uint8_t>(ext_data_len >> 8));
        extensions.push_back(static_cast<uint8_t>(ext_data_len & 0xFF));
        extensions.insert(extensions.end(), sni_ext_data.begin(), sni_ext_data.end());

        uint16_t total_ext_len = static_cast<uint16_t>(extensions.size());
        body.push_back(static_cast<uint8_t>(total_ext_len >> 8));
        body.push_back(static_cast<uint8_t>(total_ext_len & 0xFF));
        body.insert(body.end(), extensions.begin(), extensions.end());

        std::vector<uint8_t> handshake;
        handshake.push_back(0x01);
        uint32_t hs_len = static_cast<uint32_t>(body.size());
        handshake.push_back(static_cast<uint8_t>((hs_len >> 16) & 0xFF));
        handshake.push_back(static_cast<uint8_t>((hs_len >> 8) & 0xFF));
        handshake.push_back(static_cast<uint8_t>(hs_len & 0xFF));
        handshake.insert(handshake.end(), body.begin(), body.end());

        tls_record.push_back(0x16);
        tls_record.push_back(0x03);
        tls_record.push_back(0x01);
        uint16_t rec_len = static_cast<uint16_t>(handshake.size());
        tls_record.push_back(static_cast<uint8_t>(rec_len >> 8));
        tls_record.push_back(static_cast<uint8_t>(rec_len & 0xFF));
        tls_record.insert(tls_record.end(), handshake.begin(), handshake.end());
    }

    const size_t headers_len = orig_ip->header_length() + orig_tcp->header_length();
    const size_t total_size = headers_len + tls_record.size();
    std::vector<uint8_t> packet(total_size);

    auto* ip = reinterpret_cast<ipv4_header*>(packet.data());
    std::memcpy(ip, orig_ip, orig_ip->header_length());
    ip->total_length = htons(static_cast<uint16_t>(total_size));
    
    static std::atomic<uint16_t> s_fake_id_gen{0x5678};
    ip->id = htons(s_fake_id_gen.fetch_add(1, std::memory_order_relaxed));

    if (mode == FakePacketMode::Ttl) {
        ip->ttl = fake_ttl;
    }
    checksum::compute_ipv4_header_checksum(ip);

    auto* tcp = reinterpret_cast<tcp_header*>(packet.data() + orig_ip->header_length());
    std::memcpy(tcp, orig_tcp, orig_tcp->header_length());
    tcp->flags |= TCP_FLAG_PSH;

    uint8_t* tcp_options_dst = packet.data() + orig_ip->header_length() + sizeof(tcp_header);
    const size_t options_len = orig_tcp->header_length() - sizeof(tcp_header);
    if (options_len > 0 && !tcp_options.empty()) {
        std::memcpy(tcp_options_dst, tcp_options.data(), options_len);
    }

    std::memcpy(packet.data() + headers_len, tls_record.data(), tls_record.size());

    if (mode == FakePacketMode::BadChecksum) {
        tcp->checksum = htons(0xDEAD);
        return EmittedPacket{ std::move(packet), false };
    } else if (mode == FakePacketMode::TcpTimestamp) {
        bool ts_corrupted = false;
        if (options_len > 0) {
            ts_corrupted = tcp_options::corrupt_timestamp_option(tcp_options_dst, options_len, 0);
        }
        if (!ts_corrupted) {
            ip->ttl = (fake_ttl > 0 ? fake_ttl : 3);
            checksum::compute_ipv4_header_checksum(ip);
        }
        checksum::compute_tcp_checksum(ip, tcp, std::span<const uint8_t>(tcp_options_dst, options_len), tls_record);
        return EmittedPacket{ std::move(packet), true };
    } else {
        checksum::compute_tcp_checksum(ip, tcp, std::span<const uint8_t>(tcp_options_dst, options_len), tls_record);
        return EmittedPacket{ std::move(packet), true };
    }
}

std::vector<EmittedPacket> PacketEngine::create_seqovl_segments(
    std::span<const uint8_t> raw_packet,
    const SniInfo& sni,
    std::string_view substitute_host,
    size_t split_offset,
    FakePacketMode fooling_mode,
    uint8_t fake_ttl,
    bool set_ip_id_zero)
{
    const auto* orig_ip = reinterpret_cast<const ipv4_header*>(raw_packet.data());
    const size_t ip_len = orig_ip->header_length();
    const auto* orig_tcp = reinterpret_cast<const tcp_header*>(raw_packet.data() + ip_len);
    const size_t tcp_len = orig_tcp->header_length();
    const size_t headers_len = ip_len + tcp_len;

    const size_t total_ip_len = orig_ip->get_total_length();
    const size_t total_payload_len = (total_ip_len > headers_len) ? (total_ip_len - headers_len) : 0;

    const size_t pos_host = sni.host_offset_in_payload;
    const size_t host_size = sni.host_length;
    const size_t pos_endhost = pos_host + host_size;

    if (pos_host == 0 || pos_endhost > total_payload_len || host_size == 0) {
        return segment_tcp_at_offset(raw_packet, split_offset > 0 ? split_offset : 1);
    }

    std::span<const uint8_t> payload = raw_packet.subspan(headers_len, total_payload_len);
    const uint8_t* orig_tcp_opts = raw_packet.data() + ip_len + sizeof(tcp_header);
    const size_t orig_tcp_opts_len = tcp_len - sizeof(tcp_header);
    const uint32_t orig_seq = ntohl(orig_tcp->seq_num);

    std::string fakehost = generate_matching_fake_host(host_size, substitute_host);

    auto build_segment = [&](uint32_t seq, uint8_t flags, std::span<const uint8_t> seg_data, bool is_fake) -> EmittedPacket {
        std::vector<uint8_t> pkt(headers_len + seg_data.size());

        std::memcpy(pkt.data(), orig_ip, ip_len);
        auto* ip = reinterpret_cast<ipv4_header*>(pkt.data());
        ip->total_length = htons(static_cast<uint16_t>(pkt.size()));
        
        if (set_ip_id_zero) {
            ip->id = 0;
        } else if (is_fake) {
            static std::atomic<uint16_t> s_fake_id{0x9999};
            ip->id = htons(s_fake_id.fetch_add(1, std::memory_order_relaxed));
        }

        if (is_fake && fooling_mode == FakePacketMode::Ttl) {
            ip->ttl = fake_ttl;
        }
        checksum::compute_ipv4_header_checksum(ip);

        std::memcpy(pkt.data() + ip_len, orig_tcp, sizeof(tcp_header));
        auto* tcp = reinterpret_cast<tcp_header*>(pkt.data() + ip_len);
        tcp->seq_num = htonl(seq);
        tcp->flags = flags;

        uint8_t* dst_opts = pkt.data() + ip_len + sizeof(tcp_header);
        if (orig_tcp_opts_len > 0) {
            std::memcpy(dst_opts, orig_tcp_opts, orig_tcp_opts_len);
        }

        if (!seg_data.empty()) {
            std::memcpy(pkt.data() + headers_len, seg_data.data(), seg_data.size());
        }

        if (is_fake) {
            if (fooling_mode == FakePacketMode::TcpTimestamp) {
                bool ts_corrupted = false;
                if (orig_tcp_opts_len > 0) {
                    ts_corrupted = tcp_options::corrupt_timestamp_option(dst_opts, orig_tcp_opts_len, 0);
                }
                if (!ts_corrupted) {
                    ip->ttl = (fake_ttl > 0 ? fake_ttl : 3);
                    checksum::compute_ipv4_header_checksum(ip);
                }
                checksum::compute_tcp_checksum(ip, tcp, std::span<const uint8_t>(dst_opts, orig_tcp_opts_len), seg_data);
                return EmittedPacket{ std::move(pkt), true };
            } else if (fooling_mode == FakePacketMode::BadChecksum) {
                tcp->checksum = htons(0xDEAD);
                return EmittedPacket{ std::move(pkt), false };
            }
        }

        checksum::compute_tcp_checksum(ip, tcp, std::span<const uint8_t>(dst_opts, orig_tcp_opts_len), seg_data);
        return EmittedPacket{ std::move(pkt), true };
    };

    std::vector<EmittedPacket> result;

    result.push_back(build_segment(
        orig_seq,
        orig_tcp->flags,
        payload.subspan(0, pos_host),
        false
    ));

    std::span<const uint8_t> fake_span(reinterpret_cast<const uint8_t*>(fakehost.data()), fakehost.size());
    result.push_back(build_segment(
        orig_seq + static_cast<uint32_t>(pos_host),
        orig_tcp->flags,
        fake_span,
        true
    ));

    result.push_back(build_segment(
        orig_seq + static_cast<uint32_t>(pos_host),
        orig_tcp->flags,
        payload.subspan(pos_host, host_size),
        false
    ));

    result.push_back(build_segment(
        orig_seq + static_cast<uint32_t>(pos_host),
        orig_tcp->flags,
        fake_span,
        true
    ));

    result.push_back(build_segment(
        orig_seq + static_cast<uint32_t>(pos_endhost),
        orig_tcp->flags,
        payload.subspan(pos_endhost, total_payload_len - pos_endhost),
        false
    ));

    return result;
}

// Нарезка TCP-сегмента по смещению
std::vector<EmittedPacket> PacketEngine::segment_tcp_at_offset(
    std::span<const uint8_t> raw_packet,
    size_t split_offset)
{
    const auto* ip = reinterpret_cast<const ipv4_header*>(raw_packet.data());
    const size_t ip_len = ip->header_length();
    const auto* tcp = reinterpret_cast<const tcp_header*>(raw_packet.data() + ip_len);
    const size_t tcp_len = tcp->header_length();
    const size_t headers_len = ip_len + tcp_len;

    const size_t total_ip_len = ip->get_total_length();
    const size_t total_payload_len = (total_ip_len > headers_len) ? (total_ip_len - headers_len) : 0;
    if (total_payload_len <= 1 || headers_len > raw_packet.size()) {
        return { EmittedPacket{ std::vector<uint8_t>(raw_packet.begin(), raw_packet.end()), true } };
    }

    std::span<const uint8_t> payload = raw_packet.subspan(headers_len, total_payload_len);

    if (split_offset == 0 || split_offset >= total_payload_len) {
        split_offset = (total_payload_len > 2) ? 2 : 1;
    }

    const size_t seg1_payload_len = split_offset;
    const size_t seg2_payload_len = total_payload_len - split_offset;

    std::span<const uint8_t> tcp_options = raw_packet.subspan(ip_len + sizeof(tcp_header), tcp_len - sizeof(tcp_header));

    // Сегмент 1
    std::vector<uint8_t> seg1(headers_len + seg1_payload_len);
    std::memcpy(seg1.data(), raw_packet.data(), headers_len);
    std::memcpy(seg1.data() + headers_len, payload.data(), seg1_payload_len);

    auto* seg1_ip = reinterpret_cast<ipv4_header*>(seg1.data());
    seg1_ip->total_length = htons(static_cast<uint16_t>(seg1.size()));
    checksum::compute_ipv4_header_checksum(seg1_ip);

    auto* seg1_tcp = reinterpret_cast<tcp_header*>(seg1.data() + ip_len);
    seg1_tcp->flags &= ~TCP_FLAG_PSH;
    checksum::compute_tcp_checksum(seg1_ip, seg1_tcp, tcp_options, payload.subspan(0, seg1_payload_len));

    // Сегмент 2
    std::vector<uint8_t> seg2(headers_len + seg2_payload_len);
    std::memcpy(seg2.data(), raw_packet.data(), headers_len);
    std::memcpy(seg2.data() + headers_len, payload.data() + seg1_payload_len, seg2_payload_len);

    auto* seg2_ip = reinterpret_cast<ipv4_header*>(seg2.data());
    seg2_ip->id = htons(ntohs(ip->id) + 1);
    seg2_ip->total_length = htons(static_cast<uint16_t>(seg2.size()));
    checksum::compute_ipv4_header_checksum(seg2_ip);

    auto* seg2_tcp = reinterpret_cast<tcp_header*>(seg2.data() + ip_len);
    const uint32_t orig_seq = ntohl(tcp->seq_num);
    seg2_tcp->seq_num = htonl(orig_seq + static_cast<uint32_t>(seg1_payload_len));
    seg2_tcp->flags = tcp->flags;
    checksum::compute_tcp_checksum(seg2_ip, seg2_tcp, tcp_options, payload.subspan(seg1_payload_len));

    return { EmittedPacket{ std::move(seg1), true }, EmittedPacket{ std::move(seg2), true } };
}

// Нарезка пакета по выбранной стратегии
std::vector<EmittedPacket> PacketEngine::segment_tcp_sni(
    std::span<const uint8_t> raw_packet,
    const SniInfo& sni,
    TlsSplitStrategy strategy)
{
    const auto* ip = reinterpret_cast<const ipv4_header*>(raw_packet.data());
    const size_t ip_len = ip->header_length();
    const auto* tcp = reinterpret_cast<const tcp_header*>(raw_packet.data() + ip_len);
    const size_t tcp_len = tcp->header_length();
    const size_t headers_len = ip_len + tcp_len;

    const size_t total_ip_len = ip->get_total_length();
    const size_t total_payload_len = (total_ip_len > headers_len) ? (total_ip_len - headers_len) : 0;
    if (total_payload_len <= 1 || headers_len > raw_packet.size()) {
        return { EmittedPacket{ std::vector<uint8_t>(raw_packet.begin(), raw_packet.end()), true } };
    }

    size_t split_offset = 2;

    switch (strategy) {
    case TlsSplitStrategy::SplitPos2:
        split_offset = 2;
        break;
    case TlsSplitStrategy::SplitPos1:
        split_offset = 1;
        break;
    case TlsSplitStrategy::HostBoundary:
        split_offset = sni.host_offset_in_payload;
        break;
    case TlsSplitStrategy::MidSni:
        split_offset = sni.host_offset_in_payload + (sni.host_length / 2);
        if (sni.host_length <= 1) {
            split_offset = sni.host_offset_in_payload + 1;
        }
        break;
    }

    return segment_tcp_at_offset(raw_packet, split_offset);
}

// Фрагментация дейтаграммы UDP
std::vector<EmittedPacket> PacketEngine::fragment_udp_datagram(
    std::span<const uint8_t> raw_packet)
{
    const auto* ip = reinterpret_cast<const ipv4_header*>(raw_packet.data());
    const size_t ip_len = ip->header_length();
    const size_t total_l4_len = ip->get_total_length() - ip_len;

    if (total_l4_len <= 8 || raw_packet.size() < ip_len + total_l4_len) {
        return { EmittedPacket{ std::vector<uint8_t>(raw_packet.begin(), raw_packet.end()), false } };
    }

    const auto* l4_data = raw_packet.data() + ip_len;

    size_t frag1_l4_len = total_l4_len / 2;
    frag1_l4_len = (frag1_l4_len / 8) * 8;
    if (frag1_l4_len == 0) {
        frag1_l4_len = 8;
    }
    const size_t frag2_l4_len = total_l4_len - frag1_l4_len;

    static std::atomic<uint16_t> s_frag_id_gen{0x2345};
    uint16_t orig_id = ip->get_id();
    if (orig_id == 0) {
        orig_id = s_frag_id_gen.fetch_add(1, std::memory_order_relaxed);
    }

    // Первый фрагмент
    std::vector<uint8_t> frag1(ip_len + frag1_l4_len);
    std::memcpy(frag1.data(), raw_packet.data(), ip_len);
    std::memcpy(frag1.data() + ip_len, l4_data, frag1_l4_len);

    auto* frag1_ip = reinterpret_cast<ipv4_header*>(frag1.data());
    frag1_ip->total_length = htons(static_cast<uint16_t>(frag1.size()));
    frag1_ip->id = htons(orig_id);
    frag1_ip->set_dont_fragment(false);
    frag1_ip->set_more_fragments(true);
    frag1_ip->set_fragment_offset_bytes(0);
    checksum::compute_ipv4_header_checksum(frag1_ip);

    // Второй фрагмент
    std::vector<uint8_t> frag2(ip_len + frag2_l4_len);
    std::memcpy(frag2.data(), raw_packet.data(), ip_len);
    std::memcpy(frag2.data() + ip_len, l4_data + frag1_l4_len, frag2_l4_len);

    auto* frag2_ip = reinterpret_cast<ipv4_header*>(frag2.data());
    frag2_ip->total_length = htons(static_cast<uint16_t>(frag2.size()));
    frag2_ip->id = htons(orig_id);
    frag2_ip->set_dont_fragment(false);
    frag2_ip->set_more_fragments(false);
    frag2_ip->set_fragment_offset_bytes(static_cast<uint16_t>(frag1_l4_len));
    checksum::compute_ipv4_header_checksum(frag2_ip);

    return { EmittedPacket{ std::move(frag1), false }, EmittedPacket{ std::move(frag2), false } };
}

} 
