#pragma once

#include "shared/desktop/core/app_paths.h"
#include "shared.qpb.h"

#include <QtCore/QHash>
#include <QtCore/QList>
#include <QtCore/QString>

namespace shared::desktop::core {

class address_hint_repository {
public:
    explicit address_hint_repository(const app_paths &app_paths);

    [[nodiscard]] QHash<QString, QList<shared::v1::PeerAddress>> load_all() const;
    [[nodiscard]] QList<shared::v1::PeerAddress> load_for_peer(const QString &peer_id) const;

    void merge_address(
        const QString &peer_id,
        const shared::v1::PeerAddress &address,
        bool &changed) const;
    void merge_addresses(
        const QString &peer_id,
        const QList<shared::v1::PeerAddress> &addresses,
        bool &changed) const;
    void replace_source_addresses(
        const QString &peer_id,
        const QString &source,
        const QList<shared::v1::PeerAddress> &addresses,
        bool &changed) const;

private:
    [[nodiscard]] QHash<QString, QList<shared::v1::PeerAddress>> read_file() const;
    void write_file(const QHash<QString, QList<shared::v1::PeerAddress>> &addresses) const;

    const app_paths &app_paths_;
};

}
