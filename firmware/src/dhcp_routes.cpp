// =============================================================
// dhcp_routes.cpp — RFC 3442 classless static routes (option 121)
//
// Why this exists
// ---------------
// ESP-IDF's lwIP client requests only options 1/3/6/28/42 and ignores
// option 121. ISC dhcpd (and several other servers) only return options
// listed in the client's Parameter Request List, so the modem never
// even sees the classless routes. On a LAN where a VPN prefix is
// reachable through a different router than the default gateway, the
// modem then sends replies for VPN clients to the default gateway,
// where connection tracking drops them (asymmetric routing).
//
// Implementation notes
// --------------------
// The precompiled ESP-IDF lwIP allows three link-time hooks:
//   - dhcp_parse_extra_opts()  -> sees every option lwIP does not parse
//   - dhcp_append_extra_opts() -> lets us add to the outgoing DHCP msg
//   - ip4_route_src_hook()     -> called for off-link destinations
// We intercept them with GNU ld --wrap (see platformio.ini) instead of
// defining the symbols directly, which would collide with the archive
// members shipped by ESP-IDF.
//
// lwIP has one gateway per netif, not a routing table. The IPv4 route
// hook is therefore used to point netif->gw at the learned next hop for
// the duration of each off-link transmit. Every off-link packet goes
// through the hook, so the correct next hop is installed before
// etharp_output() resolves the gateway.
// =============================================================
#include "dhcp_routes.h"

#if defined(ARDUINO_ARCH_ESP32)

#include <Arduino.h>
#include <WiFi.h>
#include <cstdio>
#include <cstring>

extern "C" {
#include <lwip/def.h>
#include <lwip/dhcp.h>
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/prot/dhcp.h>
}

// ESP-IDF archive members (wrapped by the linker).
extern "C" void __real_dhcp_append_extra_opts(struct netif *netif, uint8_t state,
                                              struct dhcp_msg *msg_out,
                                              uint16_t *options_out_len);
extern "C" void __real_dhcp_parse_extra_opts(struct dhcp *dhcp, uint8_t state,
                                             uint8_t option, uint8_t len,
                                             struct pbuf *p, uint16_t offset);
extern "C" struct netif *__real_ip4_route_src_hook(const ip4_addr_t *src,
                                                   const ip4_addr_t *dest);

namespace DhcpRoutes {
namespace {

constexpr size_t  MAX_ROUTES                 = 8;
constexpr uint8_t OPTION_CLASSLESS_ROUTES    = 121;  // RFC 3442
constexpr uint8_t OPTION_MS_CLASSLESS_ROUTES = 249;  // Microsoft alias

struct Entry {
    uint32_t dest;     // network byte order
    uint8_t  prefix;   // significant bits
    uint32_t gateway;  // network byte order
};

portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

Entry    s_routes[MAX_ROUTES];
size_t   s_count        = 0;
bool     s_active       = false;
uint32_t s_default_gw   = 0;
bool     s_has_default  = false;

uint32_t s_base_gw      = 0;
bool     s_base_gw_ok   = false;

// Set when a 121/249 option was seen during the current lease. If the
// following GOT_IP event finds it clear, the new lease has no routes
// and stale entries from the previous network must go away.


void formatIp(uint32_t value, char *out, size_t out_len) {
    snprintf(out, out_len, "%u.%u.%u.%u",
             (unsigned)((value >> 24) & 0xFFu), (unsigned)((value >> 16) & 0xFFu),
             (unsigned)((value >> 8) & 0xFFu), (unsigned)(value & 0xFFu));
}

// Route tables are kept in host byte order (the natural RFC 3442
// representation). lwIP's ip4_addr_t stores addresses in network byte
// order, so convert explicitly at every lwIP boundary.
uint32_t rawToHost(uint32_t raw) { return lwip_ntohl(raw); }
uint32_t hostToRaw(uint32_t host) { return lwip_htonl(host); }

bool routeMatches(const Entry &route, uint32_t dest) {
    const uint32_t mask = route.prefix == 0
                              ? 0u
                              : (0xFFFFFFFFu << (32u - route.prefix));
    return (dest & mask) == (route.dest & mask);
}

void logRoutesLockedSnapshot() {
    Entry    copy[MAX_ROUTES];
    size_t   n;
    bool     active;
    bool     has_default;
    uint32_t default_gw;

    portENTER_CRITICAL(&s_mux);
    n            = s_count;
    active       = s_active;
    has_default  = s_has_default;
    default_gw   = s_default_gw;
    for (size_t i = 0; i < n; i++) copy[i] = s_routes[i];
    portEXIT_CRITICAL(&s_mux);

    if (!active) {
        Serial.println("[DHCP] option 121: no classless static routes for this lease");
        return;
    }

    Serial.printf("[DHCP] option 121: %u classless route(s)\n", (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        char dest[16];
        char gw[16];
        formatIp(copy[i].dest, dest, sizeof(dest));
        formatIp(copy[i].gateway, gw, sizeof(gw));
        Serial.printf("[DHCP]   %s/%u via %s\n", dest, (unsigned)copy[i].prefix, gw);
    }
    if (has_default) {
        char gw[16];
        formatIp(default_gw, gw, sizeof(gw));
        Serial.printf("[DHCP]   default (0.0.0.0/0) via %s\n", gw);
    }
}

// Replace the table from a fully parsed option. Malformed or empty
// options are rejected by the caller, so a bad duplicate cannot erase a
// good lease.
void commitRoutes(const Entry *routes, size_t count, bool has_default,
                  uint32_t default_gw) {
    portENTER_CRITICAL(&s_mux);
    s_count = count > MAX_ROUTES ? MAX_ROUTES : count;
    for (size_t i = 0; i < s_count; i++) s_routes[i] = routes[i];
    s_active      = true;
    s_has_default = has_default;
    s_default_gw  = default_gw;
    portEXIT_CRITICAL(&s_mux);

    logRoutesLockedSnapshot();
}

// RFC 3442 wire format:
//   width (bits), ceil(width/8) destination octets, 4-byte router.
// width 0 is the default route.
void parseClasslessOption(uint8_t option, uint8_t len, struct pbuf *p,
                          uint16_t offset) {
    uint8_t  buffer[255];
    Entry    parsed[MAX_ROUTES] = {};
    size_t   parsed_count = 0;
    bool     has_default  = false;
    uint32_t default_gw   = 0;

    if (p == nullptr || len == 0) {
        Serial.printf("[DHCP] option %u: empty payload, keeping known routes\n",
                      (unsigned)option);
        return;
    }
    if (pbuf_copy_partial(p, buffer, len, offset) != len) {
        Serial.printf("[DHCP] option %u: short read, keeping known routes\n",
                      (unsigned)option);
        return;
    }

    size_t i = 0;
    bool   ok = true;
    while (i < len) {
        const uint8_t width  = buffer[i++];
        const uint8_t octets = (uint8_t)((width + 7u) / 8u);
        if (width > 32u || (size_t)i + octets + 4u > len) {
            ok = false;
            break;
        }

        uint32_t dest = 0;
        for (uint8_t b = 0; b < octets; b++) {
            dest |= (uint32_t)buffer[i + b] << (24u - 8u * b);
        }
        i += octets;

        const uint32_t gateway = ((uint32_t)buffer[i] << 24) |
                                 ((uint32_t)buffer[i + 1] << 16) |
                                 ((uint32_t)buffer[i + 2] << 8) |
                                 (uint32_t)buffer[i + 3];
        i += 4;

        if (width == 0) {
            has_default = true;
            default_gw  = gateway;
        } else if (parsed_count < MAX_ROUTES) {
            parsed[parsed_count++] = Entry{dest, width, gateway};
        } else {
            Serial.printf("[DHCP] option %u: more than %u routes, remainder ignored\n",
                          (unsigned)option, (unsigned)MAX_ROUTES);
        }
    }

    if (!ok) {
        Serial.printf("[DHCP] option %u: malformed payload, keeping known routes\n",
                      (unsigned)option);
        return;
    }

    commitRoutes(parsed, parsed_count, has_default, default_gw);
}

// Insert 121 at the front of the Parameter Request List so it is both
// requested and ordered ahead of option 3, as required by RFC 3442.
void requestOption121(struct dhcp_msg *msg, uint16_t *options_out_len) {
    if (msg == nullptr || options_out_len == nullptr) return;

    uint16_t      total = *options_out_len;
    uint8_t      *opts  = msg->options;

    if (total > DHCP_OPTIONS_LEN) return;

    uint16_t i = 0;
    while ((uint16_t)(i + 2u) <= total) {
        const uint8_t code = opts[i];
        if (code == DHCP_OPTION_PAD) {
            i++;
            continue;
        }
        if (code == DHCP_OPTION_END) return;

        const uint8_t opt_len = opts[i + 1];
        if ((uint32_t)i + 2u + opt_len > total) return;

        if (code == DHCP_OPTION_PARAMETER_REQUEST_LIST) {
            for (uint8_t k = 0; k < opt_len; k++) {
                if (opts[i + 2u + k] == OPTION_CLASSLESS_ROUTES) return;
            }
            if (opt_len == 0xFFu) return;
            if ((uint32_t)total + 1u > DHCP_OPTIONS_LEN) return;

            memmove(&opts[i + 3u], &opts[i + 2u], (size_t)(total - (i + 2u)));
            opts[i + 2u] = OPTION_CLASSLESS_ROUTES;
            opts[i + 1u] = (uint8_t)(opt_len + 1u);
            *options_out_len = (uint16_t)(total + 1u);
            return;
        }
        i = (uint16_t)(i + 2u + opt_len);
    }
}

// Accept the OFFER (SELECTING) as well as the ACK states: some servers
// put option 121 in only one of them.
bool dhcpStateApplies(uint8_t state) {
    return state == DHCP_STATE_SELECTING || state == DHCP_STATE_REQUESTING ||
           state == DHCP_STATE_RENEWING || state == DHCP_STATE_REBINDING ||
           state == DHCP_STATE_REBOOTING;
}

} // namespace

// ─── internal entry points used by the link-time wrappers ──────
void handleExtraOption(uint8_t option, uint8_t len, struct pbuf *p,
                       uint16_t offset, uint8_t state) {
    if (option != OPTION_CLASSLESS_ROUTES &&
        option != OPTION_MS_CLASSLESS_ROUTES) {
        return;
    }

    if (!dhcpStateApplies(state)) return;
    parseClasslessOption(option, len, p, offset);
}

void appendRequest(struct dhcp_msg *msg, uint16_t *options_out_len) {
    requestOption121(msg, options_out_len);
}

void applyGateway(struct netif *nif, const ip4_addr_t *dest) {
    if (nif == nullptr || dest == nullptr) return;

    const uint32_t d = rawToHost(ip4_addr_get_u32(dest));
    uint32_t       gateway      = 0;
    bool           have_gateway = false;

    portENTER_CRITICAL(&s_mux);
    if (s_active) {
        int best = -1;
        for (size_t i = 0; i < s_count; i++) {
            if (routeMatches(s_routes[i], d) &&
                (best < 0 || s_routes[i].prefix > s_routes[best].prefix)) {
                best = (int)i;
            }
        }

        if (!s_base_gw_ok) {
            const uint32_t current = rawToHost(ip4_addr_get_u32(netif_ip4_gw(nif)));
            if (current != 0) {
                s_base_gw    = current;
                s_base_gw_ok = true;
            }
        }

        if (best >= 0) {
            gateway      = s_routes[best].gateway;
            have_gateway = true;
        } else if (s_has_default) {
            gateway      = s_default_gw;
            have_gateway = true;
        } else if (s_base_gw_ok) {
            gateway      = s_base_gw;
            have_gateway = true;
        }
    }
    portEXIT_CRITICAL(&s_mux);

    if (have_gateway && gateway != 0) {
        ip4_addr_t gw_addr;
        ip4_addr_set_u32(&gw_addr, hostToRaw(gateway));
        netif_set_gw(nif, &gw_addr);
    }
}

void onNetworkEvent(arduino_event_id_t event, arduino_event_info_t info) {
    switch (event) {
        case ARDUINO_EVENT_WIFI_STA_GOT_IP:
            onGotIp(info.got_ip.ip_info.gw.addr);
            break;
        case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
        case ARDUINO_EVENT_WIFI_STA_STOP:
        case ARDUINO_EVENT_WIFI_STA_LOST_IP:
            reset();
            break;
        default:
            break;
    }
}

void begin() {
    reset();
    // Multiple NetworkEvents handlers are supported; WifiManager keeps its own.
    WiFi.onEvent(onNetworkEvent);
    Serial.println("[DHCP] option 121 (RFC 3442 classless static routes) enabled");
}

void reset() {
    portENTER_CRITICAL(&s_mux);
    s_count       = 0;
    s_active      = false;
    s_has_default = false;
    s_default_gw  = 0;
    s_base_gw     = 0;
    s_base_gw_ok  = false;
    portEXIT_CRITICAL(&s_mux);
}

void onGotIp(uint32_t gateway) {
    portENTER_CRITICAL(&s_mux);
    uint32_t host_gateway = rawToHost(gateway);
    if (host_gateway == 0) {
        // Some Arduino/IDF event paths leave the event gw zero. DHCP has
        // already bound the lease here, so read the live netif gateway.
        struct netif *nif = netif_default;
        if (nif != nullptr) {
            host_gateway = rawToHost(ip4_addr_get_u32(netif_ip4_gw(nif)));
        }
    }
    s_base_gw    = host_gateway;
    s_base_gw_ok = host_gateway != 0;
    portEXIT_CRITICAL(&s_mux);

    char gw[16];
    formatIp(host_gateway, gw, sizeof(gw));
    Serial.printf("[DHCP] option-3 gateway %s\n", host_gateway ? gw : "none");
}

size_t count() {
    portENTER_CRITICAL(&s_mux);
    const size_t n = s_count;
    portEXIT_CRITICAL(&s_mux);
    return n;
}

bool get(size_t index, Route &out) {
    bool ok = false;
    portENTER_CRITICAL(&s_mux);
    if (index < s_count) {
        out.destination = IPAddress(hostToRaw(s_routes[index].dest));
        out.prefix      = s_routes[index].prefix;
        out.gateway     = IPAddress(hostToRaw(s_routes[index].gateway));
        ok = true;
    }
    portEXIT_CRITICAL(&s_mux);
    return ok;
}

bool hasDefaultRoute() {
    portENTER_CRITICAL(&s_mux);
    const bool value = s_active && s_has_default;
    portEXIT_CRITICAL(&s_mux);
    return value;
}

IPAddress defaultGateway() {
    portENTER_CRITICAL(&s_mux);
    const uint32_t value = s_has_default ? s_default_gw : 0;
    portEXIT_CRITICAL(&s_mux);
    return IPAddress(hostToRaw(value));
}

bool active() {
    portENTER_CRITICAL(&s_mux);
    const bool value = s_active;
    portEXIT_CRITICAL(&s_mux);
    return value;
}

IPAddress baseGateway() {
    portENTER_CRITICAL(&s_mux);
    const uint32_t value = s_base_gw_ok ? s_base_gw : 0;
    portEXIT_CRITICAL(&s_mux);
    return IPAddress(hostToRaw(value));
}

bool baseGatewayValid() {
    portENTER_CRITICAL(&s_mux);
    const bool value = s_base_gw_ok;
    portEXIT_CRITICAL(&s_mux);
    return value;
}

} // namespace DhcpRoutes

extern "C" void __wrap_dhcp_append_extra_opts(struct netif *netif, uint8_t state,
                                              struct dhcp_msg *msg_out,
                                              uint16_t *options_out_len) {
    DhcpRoutes::appendRequest(msg_out, options_out_len);
    __real_dhcp_append_extra_opts(netif, state, msg_out, options_out_len);
}

extern "C" void __wrap_dhcp_parse_extra_opts(struct dhcp *dhcp, uint8_t state,
                                             uint8_t option, uint8_t len,
                                             struct pbuf *p, uint16_t offset) {
    __real_dhcp_parse_extra_opts(dhcp, state, option, len, p, offset);
    DhcpRoutes::handleExtraOption(option, len, p, offset, state);
}

extern "C" struct netif *__wrap_ip4_route_src_hook(const ip4_addr_t *src,
                                                   const ip4_addr_t *dest) {
    struct netif *nif = __real_ip4_route_src_hook(src, dest);
    if (nif == nullptr) nif = netif_default;
    if (nif == nullptr || dest == nullptr) return nif;

    DhcpRoutes::applyGateway(nif, dest);
    return nif;
}

#endif // ARDUINO_ARCH_ESP32
