#pragma once

#include "shared.qpb.h"

#include <QtCore/QList>
#include <QtCore/QString>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QNetworkInterface>

namespace shared::desktop::core {

struct local_interface_address {
    QString interface_name{};
    QNetworkInterface::InterfaceFlags interface_flags{};
    QHostAddress address{};
};

[[nodiscard]] QList<local_interface_address> discover_local_interface_addresses();
[[nodiscard]] QList<shared::v1::PeerAddress> local_peer_addresses(quint16 listen_port);
[[nodiscard]] QList<shared::v1::PeerAddress> local_peer_addresses_for_candidates(
    quint16 listen_port,
    const QList<local_interface_address> &candidates);

}
