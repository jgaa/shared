#include "shared/desktop/core/address_hint_repository.h"

#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QLoggingCategory>
#include <QtCore/QSaveFile>

#include <stdexcept>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_address_hint_repository_log, "shared.desktop.core.address_hint_repository")

namespace {

[[noreturn]] void throw_address_hint_error(const QString &message)
{
    qCCritical(shared_address_hint_repository_log) << message;
    throw std::runtime_error(message.toStdString());
}

QJsonObject to_json(const shared::v1::PeerAddress &address)
{
    return {
        {QStringLiteral("ip"), address.ip()},
        {QStringLiteral("port"), static_cast<int>(address.port())},
        {QStringLiteral("source"), address.source()},
        {QStringLiteral("observed_time_ms"), QString::number(address.observedTimeMs())},
    };
}

shared::v1::PeerAddress from_json(const QJsonObject &object)
{
    shared::v1::PeerAddress address{};
    address.setIp(object.value(QStringLiteral("ip")).toString());
    address.setPort(object.value(QStringLiteral("port")).toInt());
    address.setSource(object.value(QStringLiteral("source")).toString());
    address.setObservedTimeMs(object.value(QStringLiteral("observed_time_ms")).toString().toULongLong());
    return address;
}

bool addresses_match(const shared::v1::PeerAddress &left, const shared::v1::PeerAddress &right)
{
    return left.ip() == right.ip()
        && left.port() == right.port()
        && left.source() == right.source();
}

}

address_hint_repository::address_hint_repository(const app_paths &app_paths)
    : app_paths_{app_paths}
{
}

QHash<QString, QList<shared::v1::PeerAddress>> address_hint_repository::load_all() const
{
    return read_file();
}

QList<shared::v1::PeerAddress> address_hint_repository::load_for_peer(const QString &peer_id) const
{
    return read_file().value(peer_id);
}

void address_hint_repository::merge_address(
    const QString &peer_id,
    const shared::v1::PeerAddress &address,
    bool &changed) const
{
    changed = false;
    merge_addresses(peer_id, {address}, changed);
}

void address_hint_repository::merge_addresses(
    const QString &peer_id,
    const QList<shared::v1::PeerAddress> &addresses,
    bool &changed) const
{
    changed = false;
    auto all_addresses = read_file();
    auto peer_addresses = all_addresses.value(peer_id);

    for (const auto &address : addresses) {
        if (address.ip().isEmpty() || address.port() == 0) {
            continue;
        }

        auto updated_existing = false;
        for (auto &existing : peer_addresses) {
            if (!addresses_match(existing, address)) {
                continue;
            }

            if (address.observedTimeMs() > existing.observedTimeMs()) {
                existing.setObservedTimeMs(address.observedTimeMs());
                changed = true;
            }
            updated_existing = true;
            break;
        }

        if (!updated_existing) {
            peer_addresses.append(address);
            changed = true;
        }
    }

    if (!changed) {
        return;
    }

    all_addresses.insert(peer_id, peer_addresses);
    write_file(all_addresses);
}

QHash<QString, QList<shared::v1::PeerAddress>> address_hint_repository::read_file() const
{
    QFile file{app_paths_.address_hints_path()};
    if (!file.exists()) {
        return {};
    }

    if (!file.open(QIODevice::ReadOnly)) {
        throw_address_hint_error(
            QStringLiteral("Failed to open address-hints file for read: %1").arg(file.fileName()));
    }

    const auto document = QJsonDocument::fromJson(file.readAll());
    if (!document.isObject()) {
        throw_address_hint_error(QStringLiteral("Failed to parse address-hints file: %1").arg(file.fileName()));
    }

    QHash<QString, QList<shared::v1::PeerAddress>> result{};
    const auto root = document.object();
    for (auto it = root.begin(); it != root.end(); ++it) {
        QList<shared::v1::PeerAddress> addresses{};
        for (const auto &value : it->toArray()) {
            if (!value.isObject()) {
                continue;
            }
            addresses.append(from_json(value.toObject()));
        }
        result.insert(it.key(), addresses);
    }

    return result;
}

void address_hint_repository::write_file(
    const QHash<QString, QList<shared::v1::PeerAddress>> &addresses) const
{
    QJsonObject root{};
    for (auto it = addresses.begin(); it != addresses.end(); ++it) {
        QJsonArray array{};
        for (const auto &address : it.value()) {
            array.append(to_json(address));
        }
        root.insert(it.key(), array);
    }

    QSaveFile file{app_paths_.address_hints_path()};
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        throw_address_hint_error(
            QStringLiteral("Failed to open address-hints file for write: %1").arg(file.fileName()));
    }

    const auto bytes = QJsonDocument{root}.toJson(QJsonDocument::Compact);
    if (file.write(bytes) != bytes.size()) {
        throw_address_hint_error(
            QStringLiteral("Failed to write address-hints file: %1").arg(file.fileName()));
    }

    if (!file.commit()) {
        throw_address_hint_error(
            QStringLiteral("Failed to commit address-hints file: %1").arg(file.fileName()));
    }
}

}
