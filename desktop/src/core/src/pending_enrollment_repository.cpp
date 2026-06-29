#include "shared/desktop/core/pending_enrollment_repository.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QLoggingCategory>
#include <QtCore/QSaveFile>

#include <stdexcept>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_pending_enrollment_log, "shared.desktop.core.pending_enrollment")

namespace {

[[noreturn]] void throw_io_error(const QString &message)
{
    qCCritical(shared_pending_enrollment_log) << message;
    throw std::runtime_error(message.toStdString());
}

QJsonObject to_json(const pending_enrollment_request &request)
{
    return {
        {QStringLiteral("request_id"), request.request_id},
        {QStringLiteral("peer_id"), request.peer_id},
        {QStringLiteral("name"), request.name},
        {QStringLiteral("verification_code"), request.verification_code},
        {QStringLiteral("certificate_request"), QString::fromLatin1(request.certificate_request.toBase64())},
        {QStringLiteral("x25519_public_key"), QString::fromLatin1(request.x25519_public_key.toBase64())},
        {QStringLiteral("created_time_ms"), QString::number(request.created_time_ms)},
    };
}

pending_enrollment_request from_json(const QJsonObject &object)
{
    return {
        .request_id = object.value(QStringLiteral("request_id")).toString(),
        .peer_id = object.value(QStringLiteral("peer_id")).toString(),
        .name = object.value(QStringLiteral("name")).toString(),
        .verification_code = object.value(QStringLiteral("verification_code")).toString(),
        .certificate_request = QByteArray::fromBase64(object.value(QStringLiteral("certificate_request")).toString().toLatin1()),
        .x25519_public_key = QByteArray::fromBase64(object.value(QStringLiteral("x25519_public_key")).toString().toLatin1()),
        .created_time_ms = object.value(QStringLiteral("created_time_ms")).toString().toLongLong(),
    };
}

}

pending_enrollment_repository::pending_enrollment_repository(const app_paths &app_paths)
    : app_paths_{app_paths}
{
}

void pending_enrollment_repository::save_request(const pending_enrollment_request &request) const
{
    QSaveFile file{request_path(request.request_id)};
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        throw_io_error(QStringLiteral("Failed to open pending enrollment request file for write: %1").arg(file.fileName()));
    }

    if (file.write(QJsonDocument{to_json(request)}.toJson(QJsonDocument::Compact)) == -1) {
        throw_io_error(QStringLiteral("Failed to write pending enrollment request file: %1").arg(file.fileName()));
    }

    if (!file.commit()) {
        throw_io_error(QStringLiteral("Failed to commit pending enrollment request file: %1").arg(file.fileName()));
    }
}

QList<pending_enrollment_request> pending_enrollment_repository::load_requests() const
{
    QList<pending_enrollment_request> requests{};
    QDir directory{app_paths_.pending_enrollments_dir()};

    const auto files = directory.entryList({QStringLiteral("*.request.json")}, QDir::Files, QDir::Name);
    for (const auto &file_name : files) {
        QFile file{directory.filePath(file_name)};
        if (!file.open(QIODevice::ReadOnly)) {
            continue;
        }

        const auto document = QJsonDocument::fromJson(file.readAll());
        if (!document.isObject()) {
            continue;
        }

        requests.append(from_json(document.object()));
    }

    return requests;
}

std::optional<pending_enrollment_request> pending_enrollment_repository::load_request(const QString &request_id) const
{
    QFile file{request_path(request_id)};
    if (!file.open(QIODevice::ReadOnly)) {
        return std::nullopt;
    }

    const auto document = QJsonDocument::fromJson(file.readAll());
    if (!document.isObject()) {
        return std::nullopt;
    }

    return from_json(document.object());
}

void pending_enrollment_repository::save_decision(
    const QString &request_id,
    bool approved,
    const QString &message) const
{
    QSaveFile file{decision_path(request_id)};
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        throw_io_error(QStringLiteral("Failed to open pending enrollment decision file for write: %1").arg(file.fileName()));
    }

    const QJsonObject object{
        {QStringLiteral("decided"), true},
        {QStringLiteral("approved"), approved},
        {QStringLiteral("message"), message},
    };

    if (file.write(QJsonDocument{object}.toJson(QJsonDocument::Compact)) == -1) {
        throw_io_error(QStringLiteral("Failed to write pending enrollment decision file: %1").arg(file.fileName()));
    }

    if (!file.commit()) {
        throw_io_error(QStringLiteral("Failed to commit pending enrollment decision file: %1").arg(file.fileName()));
    }
}

std::optional<pending_enrollment_decision> pending_enrollment_repository::load_decision(const QString &request_id) const
{
    QFile file{decision_path(request_id)};
    if (!file.open(QIODevice::ReadOnly)) {
        return std::nullopt;
    }

    const auto document = QJsonDocument::fromJson(file.readAll());
    if (!document.isObject()) {
        return std::nullopt;
    }

    return pending_enrollment_decision{
        .decided = document.object().value(QStringLiteral("decided")).toBool(),
        .approved = document.object().value(QStringLiteral("approved")).toBool(),
        .message = document.object().value(QStringLiteral("message")).toString(),
    };
}

void pending_enrollment_repository::remove_request(const QString &request_id) const
{
    QFile::remove(request_path(request_id));
    QFile::remove(decision_path(request_id));
}

void pending_enrollment_repository::remove_all_requests() const
{
    for (const auto &request : load_requests()) {
        remove_request(request.request_id);
    }
}

QString pending_enrollment_repository::request_path(const QString &request_id) const
{
    return app_paths_.pending_enrollments_dir() + QStringLiteral("/") + request_id + QStringLiteral(".request.json");
}

QString pending_enrollment_repository::decision_path(const QString &request_id) const
{
    return app_paths_.pending_enrollments_dir() + QStringLiteral("/") + request_id + QStringLiteral(".decision.json");
}

}
