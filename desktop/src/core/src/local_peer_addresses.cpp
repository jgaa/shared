#include "shared/desktop/core/local_peer_addresses.h"

#include <QtCore/QSet>

namespace shared::desktop::core {

namespace {

bool is_container_interface(const QString &interface_name)
{
    const auto normalized = interface_name.trimmed().toLower();
    return normalized.startsWith(QStringLiteral("docker"))
        || normalized.startsWith(QStringLiteral("br-"))
        || normalized.startsWith(QStringLiteral("veth"))
        || normalized.startsWith(QStringLiteral("cni"))
        || normalized.startsWith(QStringLiteral("podman"));
}

bool is_usable_local_address(
    const QString &interface_name,
    QNetworkInterface::InterfaceFlags interface_flags,
    const QHostAddress &address)
{
    if (!(interface_flags.testFlag(QNetworkInterface::IsUp)
            && interface_flags.testFlag(QNetworkInterface::IsRunning))
        || interface_flags.testFlag(QNetworkInterface::IsLoopBack)
        || is_container_interface(interface_name)
        || address.isNull()
        || address.isLoopback()
        || address.isMulticast()) {
        return false;
    }

    const auto protocol = address.protocol();
    if (protocol != QAbstractSocket::IPv4Protocol && protocol != QAbstractSocket::IPv6Protocol) {
        return false;
    }

    const auto text = address.toString().trimmed().toLower();
    if (text.isEmpty()) {
        return false;
    }

    if (protocol == QAbstractSocket::IPv4Protocol) {
        return !text.startsWith(QStringLiteral("169.254."));
    }

    return !text.startsWith(QStringLiteral("fe80:"));
}

}

QList<local_interface_address> discover_local_interface_addresses()
{
    QList<local_interface_address> candidates{};
    const auto interfaces = QNetworkInterface::allInterfaces();
    for (const auto &interface : interfaces) {
        const auto entries = interface.addressEntries();
        for (const auto &entry : entries) {
            candidates.append({
                interface.name(),
                interface.flags(),
                entry.ip(),
            });
        }
    }

    return candidates;
}

QList<shared::v1::PeerAddress> local_peer_addresses(quint16 listen_port)
{
    return local_peer_addresses_for_candidates(listen_port, discover_local_interface_addresses());
}

QList<shared::v1::PeerAddress> local_peer_addresses_for_candidates(
    quint16 listen_port,
    const QList<local_interface_address> &candidates)
{
    QList<shared::v1::PeerAddress> result{};
    if (listen_port == 0) {
        return result;
    }

    QSet<QString> seen_addresses{};
    for (const auto &candidate : candidates) {
        if (!is_usable_local_address(candidate.interface_name, candidate.interface_flags, candidate.address)) {
            continue;
        }

        const auto ip = candidate.address.toString().trimmed();
        const auto dedupe_key = QStringLiteral("%1|%2").arg(ip).arg(listen_port);
        if (seen_addresses.contains(dedupe_key)) {
            continue;
        }

        seen_addresses.insert(dedupe_key);

        shared::v1::PeerAddress address{};
        address.setIp(ip);
        address.setPort(listen_port);
        address.setSource(QStringLiteral("local"));
        address.setObservedTimeMs(0);
        result.append(address);
    }

    return result;
}

}
