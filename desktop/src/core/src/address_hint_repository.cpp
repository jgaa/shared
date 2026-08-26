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

constexpr qint64 maximum_address_hints_file_size{1024 * 1024};
constexpr qsizetype maximum_address_hint_peers{256};
constexpr qsizetype maximum_addresses_per_peer{16};

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

int address_source_priority(const QString &source)
{
    if (source == QStringLiteral("manual")) {
        return 0;
    }
    if (source == QStringLiteral("local")) {
        return 1;
    }
    if (source == QStringLiteral("direct")) {
        return 2;
    }
    if (source == QStringLiteral("observed")) {
        return 3;
    }
    return 4;
}

void touch_lru_address(
    QList<shared::v1::PeerAddress> &addresses,
    const shared::v1::PeerAddress &address)
{
    auto existing_index = -1;
    for (qsizetype index = 0; index < addresses.size(); ++index) {
        if (addresses.at(index).ip() != address.ip()) {
            continue;
        }
        if (existing_index < 0
            || address_source_priority(addresses.at(index).source())
                < address_source_priority(addresses.at(existing_index).source())) {
            existing_index = static_cast<int>(index);
        }
    }

    // An observed transport address must never displace a peer's own advertised
    // endpoint for the same IP.
    const auto use_existing = existing_index >= 0
        && address_source_priority(addresses.at(existing_index).source())
            < address_source_priority(address.source());
    const auto selected = use_existing ? addresses.at(existing_index) : address;
    for (qsizetype index = addresses.size(); index > 0; --index) {
        if (addresses.at(index - 1).ip() == address.ip()) {
            addresses.removeAt(index - 1);
        }
    }
    addresses.prepend(selected);
}

void trim_lru_addresses(QList<shared::v1::PeerAddress> &addresses, qsizetype maximum)
{
    QList<shared::v1::PeerAddress> normalized{};
    for (const auto &address : addresses) {
        if (address.ip().isEmpty() || address.port() == 0) {
            continue;
        }
        auto already_present = false;
        for (const auto &existing : normalized) {
            if (existing.ip() == address.ip()) {
                already_present = true;
                break;
            }
        }
        if (!already_present && normalized.size() < maximum) {
            normalized.append(address);
        }
    }
    addresses = std::move(normalized);
}

bool address_lists_match(
    const QList<shared::v1::PeerAddress> &left,
    const QList<shared::v1::PeerAddress> &right)
{
    if (left.size() != right.size()) {
        return false;
    }

    for (qsizetype index = 0; index < left.size(); ++index) {
        if (!addresses_match(left.at(index), right.at(index))
            || left.at(index).observedTimeMs() != right.at(index).observedTimeMs()) {
            return false;
        }
    }

    return true;
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
    const auto original_addresses = peer_addresses;

    // Hints are serialized newest-first. Process them backwards because each
    // accepted endpoint is moved to the LRU front.
    for (auto it = addresses.crbegin(); it != addresses.crend(); ++it) {
        const auto &address = *it;
        if (address.ip().isEmpty() || address.port() == 0) {
            continue;
        }

        touch_lru_address(peer_addresses, address);
    }

    trim_lru_addresses(peer_addresses, 5);
    changed = !address_lists_match(original_addresses, peer_addresses);

    if (!changed) {
        return;
    }

    all_addresses.insert(peer_id, peer_addresses);
    write_file(all_addresses);
}

void address_hint_repository::replace_source_addresses(
    const QString &peer_id,
    const QString &source,
    const QList<shared::v1::PeerAddress> &addresses,
    bool &changed) const
{
    changed = false;
    if (peer_id.isEmpty() || source.isEmpty()) {
        return;
    }

    auto all_addresses = read_file();
    const auto peer_addresses = all_addresses.value(peer_id);

    QList<shared::v1::PeerAddress> updated_addresses{};
    for (const auto &existing : peer_addresses) {
        if (existing.source() != source) {
            updated_addresses.append(existing);
        }
    }

    for (const auto &address : addresses) {
        if (address.ip().isEmpty() || address.port() == 0 || address.source() != source) {
            continue;
        }

        auto already_present = false;
        for (const auto &existing : updated_addresses) {
            if (addresses_match(existing, address)
                && existing.observedTimeMs() == address.observedTimeMs()) {
                already_present = true;
                break;
            }
        }

        if (!already_present) {
            updated_addresses.append(address);
        }
    }

    trim_lru_addresses(updated_addresses, 5);

    if (address_lists_match(peer_addresses, updated_addresses)) {
        return;
    }

    if (updated_addresses.isEmpty()) {
        all_addresses.remove(peer_id);
    } else {
        all_addresses.insert(peer_id, updated_addresses);
    }
    changed = true;
    write_file(all_addresses);
}

void address_hint_repository::cap_addresses_per_peer(qsizetype maximum, bool &changed) const
{
    changed = false;
    auto all_addresses = read_file();
    for (auto it = all_addresses.begin(); it != all_addresses.end(); ++it) {
        const auto previous = it.value();
        trim_lru_addresses(it.value(), maximum);
        changed = changed || !address_lists_match(previous, it.value());
    }
    if (changed) {
        write_file(all_addresses);
    }
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
    if (file.size() > maximum_address_hints_file_size) {
        throw_address_hint_error(QStringLiteral("Address-hints file exceeds the maximum allowed size"));
    }

    const auto document = QJsonDocument::fromJson(file.readAll());
    if (!document.isObject()) {
        throw_address_hint_error(QStringLiteral("Failed to parse address-hints file: %1").arg(file.fileName()));
    }

    QHash<QString, QList<shared::v1::PeerAddress>> result{};
    const auto root = document.object();
    auto it = root.begin();
    for (qsizetype peer_count{}; it != root.end() && peer_count < maximum_address_hint_peers; ++it, ++peer_count) {
        QList<shared::v1::PeerAddress> addresses{};
        const auto stored_addresses = it->toArray();
        for (qsizetype address_index{};
             address_index < stored_addresses.size() && address_index < maximum_addresses_per_peer;
             ++address_index) {
            const auto &value = stored_addresses.at(address_index);
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
