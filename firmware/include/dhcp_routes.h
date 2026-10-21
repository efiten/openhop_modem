// =============================================================
// dhcp_routes.h — RFC 3442 classless static routes (DHCP option 121)
//
// The ESP-IDF lwIP build used by the Arduino core does not request,
// parse or install DHCP option 121 routes. On networks where VPN or
// other non-local prefixes are reachable through a different next hop
// than the default router, replies from the modem take the default
// route and are dropped by the router's connection tracking.
//
// This module:
//   * adds option 121 to the DHCP Parameter Request List,
//   * parses option 121 (and the Microsoft 249 alias) from OFFER/ACK,
//   * selects the learned next hop for matching IPv4 destinations.
//
// The route table is runtime-only: a valid option 121 replaces it,
// malformed/duplicate options keep the last good table, and link loss
// clears it.
// =============================================================
#pragma once

#if defined(ARDUINO_ARCH_ESP32)

#include <Arduino.h>
#include <IPAddress.h>

namespace DhcpRoutes {

struct Route {
    IPAddress destination;
    uint8_t   prefix;
    IPAddress gateway;
};

// Reset state, register the event handler, announce support.
void begin();

// Drop all learned routes and the cached DHCP router address.
void reset();

// Called from the Wi-Fi event handler on ARDUINO_EVENT_WIFI_STA_GOT_IP.
// gateway is in network byte order (esp_ip4_addr_t.addr). The module
// prefers the lease's option-3 value and uses this argument as fallback.
void onGotIp(uint32_t gateway);

size_t count();
bool   get(size_t index, Route& out);

bool      hasDefaultRoute();
IPAddress defaultGateway();
bool      active();

// The gateway supplied by DHCP option 3, kept separately because the
// route hook rewrites netif->gw before each off-link transmit.
IPAddress baseGateway();
bool      baseGatewayValid();

} // namespace DhcpRoutes

#endif // ARDUINO_ARCH_ESP32
