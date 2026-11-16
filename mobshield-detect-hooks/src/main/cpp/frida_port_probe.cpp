/*
 * Copyright 2025 MobShield Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hooks_checks.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

constexpr int kConnectTimeoutMs = 100;

// A non-blocking connect() to a listening loopback port normally returns -1 with EINPROGRESS,
// not 0, and SO_SNDTIMEO does not apply to it. Wait for writability and read SO_ERROR instead.
bool probe_port(uint16_t port) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }

    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return false;
    }

    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    bool open = false;
    if (connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) {
        open = true;
    } else if (errno == EINPROGRESS) {
        pollfd pfd {};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        int ready;
        do {
            ready = poll(&pfd, 1, kConnectTimeoutMs);
        } while (ready < 0 && errno == EINTR);
        if (ready > 0) {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            open = getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0 && so_error == 0;
        }
    }
    close(fd);
    return open;
}

}  // namespace

int mobshield_frida_port_probe(char* evidence, int evidence_len) {
    const uint16_t ports[] = {27042, 27043};
    for (uint16_t port : ports) {
        if (!probe_port(port)) {
            continue;
        }
        if (evidence != nullptr && evidence_len > 0) {
            snprintf(evidence, static_cast<size_t>(evidence_len), "port:%u", port);
        }
        return MOBSHIELD_HOOKS_DETECTED;
    }
    return MOBSHIELD_HOOKS_OK;
}
