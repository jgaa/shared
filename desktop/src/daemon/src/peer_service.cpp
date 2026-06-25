#include "peer_service.h"

#include "shared/desktop/core/envelope_io.h"

#include <QtCore/QDateTime>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QLoggingCategory>
#include <QtCore/QSaveFile>
#include <QtCore/QUuid>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslKey>
#include <QtProtobuf/QProtobufSerializer>

namespace shared::desktop::daemon {

Q_LOGGING_CATEGORY(shared_peer_service_log, "shared.desktop.daemon.peer_service")

namespace {

QList<QSslCertificate> load_certificates(const QString &path, QSsl::EncodingFormat format)
{
    QFile file{path};
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }

    return QSslCertificate::fromData(file.readAll(), format);
}

QByteArray read_file_bytes(const QString &path)
{
    QFile file{path};
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }

    return file.readAll();
}

QString socket_address(const QSslSocket &socket)
{
    return socket.peerAddress().toString();
}

shared::v1::Envelope make_envelope(const QString &message_id)
{
    shared::v1::Envelope envelope{};
    envelope.setProtocolVersion(1);
    envelope.setMessageId(message_id);
    return envelope;
}

QByteArray serialize_peer_list(const shared::v1::PeerList &peer_list)
{
    QProtobufSerializer serializer{};
    return peer_list.serialize(&serializer);
}

bool resolve_listen_address(const QString &host, QHostAddress &address)
{
    const auto trimmed_host = host.trimmed();
    if (trimmed_host.isEmpty() || trimmed_host == QStringLiteral("0.0.0.0")) {
        address = QHostAddress{QHostAddress::AnyIPv4};
        return true;
    }

    if (trimmed_host == QStringLiteral("::")) {
        address = QHostAddress{QHostAddress::AnyIPv6};
        return true;
    }

    return address.setAddress(trimmed_host);
}

}

peer_service::peer_service(
    const core::agent_configuration &configuration,
    const core::app_paths &app_paths,
    QObject *parent)
    : QObject{parent}
    , configuration_{configuration}
    , app_paths_{app_paths}
    , security_materials_{app_paths}
    , address_hint_repository_{app_paths}
{
    peer_list_refresh_timer_.setInterval(1000);
    connect(&peer_list_refresh_timer_, &QTimer::timeout, this, &peer_service::refresh_peer_list);

    connect_timer_.setInterval(3000);
    connect(&connect_timer_, &QTimer::timeout, this, &peer_service::attempt_connections);
}

bool peer_service::start(QString &error_message)
{
    QString peer_list_error{};
    const auto peer_list = load_current_peer_list(peer_list_error);
    if (!peer_list_error.isEmpty()) {
        error_message = peer_list_error;
        qCCritical(shared_peer_service_log) << "Failed to load signed peer list before starting peer service" << error_message;
        return false;
    }

    current_peer_list_version_ = peer_list.version();
    current_peer_list_bytes_ = serialize_peer_list(peer_list);

    if (!configure_server(error_message)) {
        return false;
    }

    peer_list_refresh_timer_.start();
    connect_timer_.start();
    attempt_connections();

    qCInfo(shared_peer_service_log)
        << "peer service listening"
        << "port=" << configuration_.peer_port
        << "role=" << static_cast<int>(configuration_.role)
        << "peer_list_version=" << current_peer_list_version_;
    write_peer_status_snapshot();
    return true;
}

void peer_service::stop()
{
    peer_list_refresh_timer_.stop();
    connect_timer_.stop();

    server_.close();
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.key() != nullptr) {
            it.key()->disconnectFromHost();
            it.key()->deleteLater();
        }
    }
    sessions_.clear();
    pending_connections_.clear();
    write_peer_status_snapshot();
}

void peer_service::handle_pending_connection()
{
    while (server_.hasPendingConnections()) {
        auto *socket = qobject_cast<QSslSocket *>(server_.nextPendingConnection());
        if (socket == nullptr) {
            qCWarning(shared_peer_service_log) << "Ignoring non-SSL peer connection";
            continue;
        }

        qCInfo(shared_peer_service_log)
            << "accepted peer connection"
            << socket->peerAddress().toString()
            << socket->peerPort();
        attach_socket(socket, false);
    }
}

void peer_service::refresh_peer_list()
{
    QString error_message{};
    const auto peer_list = load_current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        qCCritical(shared_peer_service_log) << "Failed to refresh signed peer list" << error_message;
        return;
    }

    const auto next_bytes = serialize_peer_list(peer_list);
    if (next_bytes == current_peer_list_bytes_) {
        return;
    }

    current_peer_list_bytes_ = next_bytes;
    current_peer_list_version_ = peer_list.version();
    qCInfo(shared_peer_service_log) << "peer list changed locally" << "version=" << current_peer_list_version_;
    write_peer_status_snapshot();
    broadcast_peer_list();
    attempt_connections();
}

void peer_service::attempt_connections()
{
    QString error_message{};
    const auto peer_list = load_current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        qCCritical(shared_peer_service_log) << "Failed to load peer list for connection attempts" << error_message;
        return;
    }

    for (const auto &peer : peer_list.peers()) {
        const auto peer_id = peer.identity().peerId().uuid();
        if (peer_id.isEmpty() || peer_id == configuration_.peer_id) {
            continue;
        }

        auto addresses = address_hint_repository_.load_for_peer(peer_id);
        if (peer_id == peer_list.trustedAgentPeerId().uuid()
            && !configuration_.trusted_agent.host.isEmpty()) {
            shared::v1::PeerAddress trusted_address{};
            trusted_address.setIp(configuration_.trusted_agent.host);
            trusted_address.setPort(configuration_.trusted_agent.peer_port);
            trusted_address.setSource(QStringLiteral("manual"));
            trusted_address.setObservedTimeMs(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch());
            addresses.prepend(trusted_address);
        }

        maybe_connect_to_peer(peer, addresses);
    }
}

bool peer_service::configure_server(QString &error_message)
{
    const auto local_certificates = load_certificates(app_paths_.peer_certificate_path(), QSsl::Pem);
    if (local_certificates.isEmpty()) {
        error_message = QStringLiteral("Failed to load local peer certificate");
        qCCritical(shared_peer_service_log) << error_message << app_paths_.peer_certificate_path();
        return false;
    }

    const auto key_bytes = read_file_bytes(app_paths_.peer_key_path());
    if (key_bytes.isEmpty()) {
        error_message = QStringLiteral("Failed to load local peer private key");
        qCCritical(shared_peer_service_log) << error_message << app_paths_.peer_key_path();
        return false;
    }

    QSslKey private_key{key_bytes, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey};
    if (private_key.isNull()) {
        error_message = QStringLiteral("Failed to parse local peer private key");
        qCCritical(shared_peer_service_log) << error_message;
        return false;
    }

    QList<QSslCertificate> ca_certificates{};
    if (configuration_.role == core::agent_role::local_trusted_agent) {
        ca_certificates = load_certificates(app_paths_.ca_certificate_path(), QSsl::Pem);
    } else {
        ca_certificates = load_certificates(app_paths_.pinned_trusted_agent_ca_certificate_path(), QSsl::Der);
    }
    if (ca_certificates.isEmpty()) {
        error_message = QStringLiteral("Failed to load trusted-agent CA certificate for peer authentication");
        qCCritical(shared_peer_service_log) << error_message;
        return false;
    }

    auto ssl_configuration = QSslConfiguration::defaultConfiguration();
    ssl_configuration.setLocalCertificateChain(local_certificates);
    ssl_configuration.setPrivateKey(private_key);
    ssl_configuration.setCaCertificates(ca_certificates);
    ssl_configuration.setPeerVerifyMode(QSslSocket::VerifyPeer);
    server_.setSslConfiguration(ssl_configuration);

    connect(&server_, &QSslServer::pendingConnectionAvailable, this, &peer_service::handle_pending_connection);
    QHostAddress listen_address{};
    if (!resolve_listen_address(configuration_.peer_host, listen_address)) {
        error_message = QStringLiteral("Invalid peer-service listen IP: %1").arg(configuration_.peer_host);
        qCCritical(shared_peer_service_log) << error_message;
        return false;
    }

    if (!server_.listen(listen_address, configuration_.peer_port)) {
        error_message = server_.errorString();
        qCCritical(shared_peer_service_log) << "Failed to listen for peer connections" << error_message;
        return false;
    }

    return true;
}

bool peer_service::configure_client_socket(QSslSocket &socket, QString &error_message) const
{
    const auto local_certificates = load_certificates(app_paths_.peer_certificate_path(), QSsl::Pem);
    if (local_certificates.isEmpty()) {
        error_message = QStringLiteral("Failed to load local peer certificate");
        return false;
    }

    const auto key_bytes = read_file_bytes(app_paths_.peer_key_path());
    if (key_bytes.isEmpty()) {
        error_message = QStringLiteral("Failed to load local peer private key");
        return false;
    }

    QSslKey private_key{key_bytes, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey};
    if (private_key.isNull()) {
        error_message = QStringLiteral("Failed to parse local peer private key");
        return false;
    }

    QList<QSslCertificate> ca_certificates{};
    if (configuration_.role == core::agent_role::local_trusted_agent) {
        ca_certificates = load_certificates(app_paths_.ca_certificate_path(), QSsl::Pem);
    } else {
        ca_certificates = load_certificates(app_paths_.pinned_trusted_agent_ca_certificate_path(), QSsl::Der);
    }
    if (ca_certificates.isEmpty()) {
        error_message = QStringLiteral("Failed to load trusted-agent CA certificate");
        return false;
    }

    auto ssl_configuration = QSslConfiguration::defaultConfiguration();
    ssl_configuration.setLocalCertificateChain(local_certificates);
    ssl_configuration.setPrivateKey(private_key);
    ssl_configuration.setCaCertificates(ca_certificates);
    ssl_configuration.setPeerVerifyMode(QSslSocket::VerifyPeer);
    socket.setSslConfiguration(ssl_configuration);
    socket.setPeerVerifyName(QString{});
    return true;
}

shared::v1::PeerList peer_service::load_current_peer_list(QString &error_message) const
{
    const auto peer_list = security_materials_.current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        return peer_list;
    }

    if (peer_list.version() != 0 && !security_materials_.validate_peer_list(peer_list, error_message)) {
        return {};
    }

    return peer_list;
}

QString peer_service::next_message_id() const
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

QString peer_service::next_connection_id() const
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

void peer_service::attach_socket(QSslSocket *socket, bool outbound)
{
    session_state session{};
    session.outbound = outbound;
    session.local_connection_id = next_connection_id();
    sessions_.insert(socket, session);

    connect(socket, &QSslSocket::readyRead, this, [this, socket]() {
        handle_socket_ready_read(socket);
    });
    connect(socket, &QSslSocket::encrypted, this, [this, socket]() {
        handle_encrypted(socket);
    });
    connect(socket, &QSslSocket::errorOccurred, this, [this, socket](QAbstractSocket::SocketError) {
        handle_socket_error(socket);
    });
    connect(socket, &QSslSocket::sslErrors, this, [this, socket](const QList<QSslError> &errors) {
        handle_ssl_errors(socket, errors);
    });
    connect(socket, &QSslSocket::disconnected, this, [this, socket]() {
        handle_disconnected(socket);
    });
}

void peer_service::close_socket(QSslSocket *socket, const QString &reason)
{
    if (socket == nullptr) {
        return;
    }

    const auto session = sessions_.value(socket);
    if (session.outbound && !session.target_peer_id.isEmpty()) {
        pending_connections_.remove(session.target_peer_id);
    }

    qCInfo(shared_peer_service_log)
        << "closing peer socket"
        << "peer_id=" << session.remote_peer_id
        << "address=" << socket->peerAddress().toString()
        << "port=" << socket->peerPort()
        << "reason=" << reason;
    socket->disconnectFromHost();
}

void peer_service::send_local_peer_info(QSslSocket *socket)
{
    auto session_it = sessions_.find(socket);
    if (session_it == sessions_.end() || session_it->peer_info_sent) {
        return;
    }

    QString error_message{};
    const auto peer_list = load_current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        qCCritical(shared_peer_service_log) << "Failed to load peer list before sending peer info" << error_message;
        close_socket(socket, error_message);
        return;
    }

    shared::v1::PeerId peer_id{};
    peer_id.setUuid(configuration_.peer_id);

    shared::v1::PeerIdentity identity{};
    identity.setPeerId(peer_id);
    identity.setName(configuration_.name);
    identity.setPlatform(shared::v1::PlatformGadget::Platform::PLATFORM_LINUX);

    shared::v1::PeerInfo peer_info{};
    peer_info.setIdentity(identity);
    peer_info.setPeerListVersion(peer_list.version());
    peer_info.setListenPort(configuration_.peer_port);
    peer_info.setConnectionId(session_it->local_connection_id);
    peer_info.setKnownAddresses(address_hint_repository_.load_for_peer(configuration_.peer_id));

    auto envelope = make_envelope(next_message_id());
    envelope.setPeerInfo(peer_info);
    send_envelope(socket, envelope, QStringLiteral("peer-info"));
    session_it->peer_info_sent = true;
}

void peer_service::send_current_peer_list(QSslSocket *socket)
{
    QString error_message{};
    const auto peer_list = load_current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        qCCritical(shared_peer_service_log) << "Failed to load peer list for send" << error_message;
        close_socket(socket, error_message);
        return;
    }

    auto envelope = make_envelope(next_message_id());
    envelope.setPeerList(peer_list);
    send_envelope(socket, envelope, QStringLiteral("peer-list"));
}

void peer_service::send_known_address_hints(QSslSocket *socket)
{
    const auto all_addresses = address_hint_repository_.load_all();
    for (auto it = all_addresses.begin(); it != all_addresses.end(); ++it) {
        if (it.value().isEmpty()) {
            continue;
        }

        shared::v1::PeerId peer_id{};
        peer_id.setUuid(it.key());

        shared::v1::AddressHint address_hint{};
        address_hint.setPeerId(peer_id);
        address_hint.setAddresses(it.value());

        auto envelope = make_envelope(next_message_id());
        envelope.setAddressHint(address_hint);
        send_envelope(socket, envelope, QStringLiteral("address-hint"));
    }
}

void peer_service::broadcast_peer_list(QSslSocket *exclude_socket)
{
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.key() == exclude_socket || !it.value().authenticated) {
            continue;
        }
        send_current_peer_list(it.key());
    }
}

void peer_service::broadcast_address_hint(const shared::v1::AddressHint &hint, QSslSocket *exclude_socket)
{
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.key() == exclude_socket || !it.value().authenticated) {
            continue;
        }

        auto envelope = make_envelope(next_message_id());
        envelope.setAddressHint(hint);
        send_envelope(it.key(), envelope, QStringLiteral("address-hint"));
    }
}

void peer_service::send_envelope(
    QSslSocket *socket,
    const shared::v1::Envelope &envelope,
    const QString &context)
{
    const auto bytes = core::envelope_io::serialize(envelope);
    qCInfo(shared_peer_service_log)
        << "sending"
        << context
        << "message_id=" << envelope.messageId()
        << "bytes=" << bytes.size()
        << "peer=" << sessions_.value(socket).remote_peer_id;
    if (socket->write(bytes) != bytes.size()) {
        qCCritical(shared_peer_service_log) << "Failed to queue" << context << socket->errorString();
        close_socket(socket, QStringLiteral("Failed to queue %1").arg(context));
        return;
    }
    if (!socket->flush()) {
        qCWarning(shared_peer_service_log) << "Failed to flush" << context << socket->errorString();
    }
    note_peer_activity(socket);
}

void peer_service::note_peer_activity(QSslSocket *socket)
{
    const auto session = sessions_.value(socket);
    if (session.remote_peer_id.isEmpty()) {
        return;
    }

    auto &runtime_state = peer_runtime_states_[session.remote_peer_id];
    runtime_state.last_communication_time_ms = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
    runtime_state.last_ip = socket->peerAddress().toString();
    runtime_state.last_port = session.remote_listen_port == 0
        ? static_cast<quint16>(socket->peerPort())
        : session.remote_listen_port;
    write_peer_status_snapshot();
}

void peer_service::write_peer_status_snapshot()
{
    QString error_message{};
    const auto peer_list = load_current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        qCCritical(shared_peer_service_log) << "Failed to write peer status snapshot" << error_message;
        return;
    }

    const auto all_addresses = address_hint_repository_.load_all();

    auto connected_peer_count = 0;
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.value().authenticated) {
            ++connected_peer_count;
        }
    }

    QJsonArray peers{};
    for (const auto &entry : peer_list.peers()) {
        const auto peer_id = entry.identity().peerId().uuid();
        if (peer_id.isEmpty() || peer_id == configuration_.peer_id) {
            continue;
        }

        auto connected = false;
        QString address{};
        quint16 port{};
        for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
            if (!it.value().authenticated || it.value().remote_peer_id != peer_id) {
                continue;
            }

            connected = true;
            address = it.key()->peerAddress().toString();
            port = it.value().remote_listen_port == 0
                ? static_cast<quint16>(it.key()->peerPort())
                : it.value().remote_listen_port;
            break;
        }

        auto known_addresses = all_addresses.value(peer_id);
        if (peer_id == peer_list.trustedAgentPeerId().uuid()
            && !configuration_.trusted_agent.host.isEmpty()) {
            shared::v1::PeerAddress trusted_address{};
            trusted_address.setIp(configuration_.trusted_agent.host);
            trusted_address.setPort(configuration_.trusted_agent.peer_port);
            trusted_address.setSource(QStringLiteral("manual"));
            trusted_address.setObservedTimeMs(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch());
            known_addresses.prepend(trusted_address);
        }

        const auto runtime_state = peer_runtime_states_.value(peer_id);
        const auto has_direct_address = !known_addresses.isEmpty();
        const auto has_runtime_address = !runtime_state.last_ip.isEmpty() && runtime_state.last_port != 0;
        const auto relay_available = !connected && connected_peer_count > 0 && !has_direct_address && !has_runtime_address;

        if (!connected && has_direct_address) {
            address = known_addresses.first().ip();
            port = static_cast<quint16>(known_addresses.first().port());
        } else if (!connected && has_runtime_address) {
            address = runtime_state.last_ip;
            port = runtime_state.last_port;
        }

        QJsonObject object{};
        object.insert(QStringLiteral("peer_id"), peer_id);
        object.insert(QStringLiteral("name"), entry.identity().name());
        object.insert(QStringLiteral("connected"), connected);
        object.insert(QStringLiteral("relay_available"), relay_available);
        object.insert(QStringLiteral("address_available"), has_direct_address || has_runtime_address || connected);
        object.insert(QStringLiteral("address"), address);
        object.insert(QStringLiteral("port"), static_cast<int>(port));
        object.insert(QStringLiteral("last_communication_time_ms"), QString::number(runtime_state.last_communication_time_ms));
        peers.append(object);
    }

    QSaveFile file{app_paths_.peer_status_path()};
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qCCritical(shared_peer_service_log) << "Failed to open peer status file for write" << file.fileName() << file.errorString();
        return;
    }

    const auto bytes = QJsonDocument{peers}.toJson(QJsonDocument::Compact);
    if (file.write(bytes) != bytes.size()) {
        qCCritical(shared_peer_service_log) << "Failed to write peer status file" << file.fileName() << file.errorString();
        return;
    }

    if (!file.commit()) {
        qCCritical(shared_peer_service_log) << "Failed to commit peer status file" << file.fileName() << file.errorString();
    }
}

void peer_service::handle_socket_ready_read(QSslSocket *socket)
{
    auto session_it = sessions_.find(socket);
    if (session_it == sessions_.end()) {
        return;
    }

    session_it->buffer.append(socket->readAll());
    qCInfo(shared_peer_service_log)
        << "received peer bytes"
        << "address=" << socket->peerAddress().toString()
        << "port=" << socket->peerPort()
        << "buffer=" << session_it->buffer.size();

    while (!session_it->buffer.isEmpty()) {
        shared::v1::Envelope envelope{};
        QString error_message{};
        if (!core::envelope_io::try_read_message(session_it->buffer, envelope, error_message)) {
            if (!error_message.isEmpty()) {
                qCCritical(shared_peer_service_log) << "Failed to decode peer envelope" << error_message;
                close_socket(socket, QStringLiteral("Invalid envelope"));
            }
            return;
        }

        if (envelope.hasPeerInfo()) {
            qCInfo(shared_peer_service_log) << "received peer-info" << envelope.messageId();
            handle_peer_info(socket, envelope.peerInfo());
            continue;
        }

        if (!session_it->authenticated) {
            qCCritical(shared_peer_service_log) << "Received non-auth message before peer-info" << envelope.messageId();
            close_socket(socket, QStringLiteral("Expected peer-info before other messages"));
            return;
        }

        if (envelope.hasPeerList()) {
            qCInfo(shared_peer_service_log) << "received peer-list" << envelope.messageId();
            note_peer_activity(socket);
            handle_peer_list(socket, envelope.peerList());
            continue;
        }

        if (envelope.hasAddressHint()) {
            qCInfo(shared_peer_service_log) << "received address-hint" << envelope.messageId();
            note_peer_activity(socket);
            handle_address_hint(socket, envelope.addressHint());
            continue;
        }

        if (envelope.hasKeepAlive()) {
            qCInfo(shared_peer_service_log) << "received keep-alive" << envelope.messageId();
            note_peer_activity(socket);
            continue;
        }

        qCWarning(shared_peer_service_log) << "Ignoring unsupported peer message" << envelope.messageId();
    }
}

void peer_service::handle_encrypted(QSslSocket *socket)
{
    qCInfo(shared_peer_service_log)
        << "peer TLS session established"
        << "outbound=" << sessions_.value(socket).outbound
        << "address=" << socket->peerAddress().toString()
        << "port=" << socket->peerPort();
    send_local_peer_info(socket);
}

void peer_service::handle_socket_error(QSslSocket *socket)
{
    qCWarning(shared_peer_service_log)
        << "peer socket error"
        << "peer=" << sessions_.value(socket).remote_peer_id
        << "address=" << socket->peerAddress().toString()
        << "port=" << socket->peerPort()
        << socket->errorString();
}

void peer_service::handle_ssl_errors(QSslSocket *socket, const QList<QSslError> &errors)
{
    QList<QSslError> fatal_errors{};

    for (const auto &error : errors) {
        if (error.error() == QSslError::HostNameMismatch) {
            qCWarning(shared_peer_service_log)
                << "ignoring peer TLS host-name mismatch"
                << "peer=" << sessions_.value(socket).remote_peer_id
                << "address=" << socket->peerAddress().toString()
                << "port=" << socket->peerPort()
                << error.errorString();
            continue;
        }

        fatal_errors.append(error);
        qCWarning(shared_peer_service_log)
            << "peer TLS error"
            << "peer=" << sessions_.value(socket).remote_peer_id
            << "address=" << socket->peerAddress().toString()
            << "port=" << socket->peerPort()
            << error.errorString();
    }

    if (fatal_errors.isEmpty()) {
        socket->ignoreSslErrors(errors);
        return;
    }

    close_socket(socket, QStringLiteral("TLS verification failed"));
}

void peer_service::handle_disconnected(QSslSocket *socket)
{
    const auto session = sessions_.take(socket);
    if (session.outbound && !session.target_peer_id.isEmpty()) {
        pending_connections_.remove(session.target_peer_id);
    }
    if (!session.remote_peer_id.isEmpty()) {
        auto &runtime_state = peer_runtime_states_[session.remote_peer_id];
        if (runtime_state.last_ip.isEmpty()) {
            runtime_state.last_ip = socket->peerAddress().toString();
        }
        if (runtime_state.last_port == 0) {
            runtime_state.last_port = session.remote_listen_port == 0
                ? static_cast<quint16>(socket->peerPort())
                : session.remote_listen_port;
        }
    }

    qCInfo(shared_peer_service_log)
        << "peer socket disconnected"
        << "peer=" << session.remote_peer_id
        << "address=" << socket->peerAddress().toString()
        << "port=" << socket->peerPort();
    write_peer_status_snapshot();
    socket->deleteLater();
}

void peer_service::handle_peer_info(QSslSocket *socket, const shared::v1::PeerInfo &peer_info)
{
    auto session_it = sessions_.find(socket);
    if (session_it == sessions_.end()) {
        return;
    }

    if (!peer_info.hasIdentity() || !peer_info.identity().hasPeerId()
        || peer_info.identity().peerId().uuid().isEmpty()) {
        qCCritical(shared_peer_service_log) << "Received invalid peer-info identity";
        close_socket(socket, QStringLiteral("Invalid peer identity"));
        return;
    }

    const auto remote_peer_id = peer_info.identity().peerId().uuid();
    QString error_message{};
    if (!security_materials_.is_known_peer_identity(
            remote_peer_id,
            peer_info.identity().name(),
            core::security_materials::certificate_fingerprint_sha256(socket->peerCertificate()),
            error_message)) {
        qCCritical(shared_peer_service_log)
            << "Rejected peer certificate"
            << "peer_id=" << remote_peer_id
            << error_message;
        close_socket(socket, error_message);
        return;
    }

    session_it->remote_peer_id = remote_peer_id;
    session_it->remote_connection_id = peer_info.connectionId();
    session_it->remote_peer_list_version = peer_info.peerListVersion();
    session_it->remote_listen_port = static_cast<quint16>(peer_info.listenPort());
    session_it->peer_info_received = true;
    session_it->authenticated = true;
    note_peer_activity(socket);

    qCInfo(shared_peer_service_log)
        << "peer authenticated"
        << "peer_id=" << remote_peer_id
        << "name=" << peer_info.identity().name()
        << "listen_port=" << peer_info.listenPort()
        << "peer_list_version=" << peer_info.peerListVersion()
        << "outbound=" << session_it->outbound;

    if (!prune_duplicate_sessions(socket)) {
        return;
    }

    merge_observed_address(
        remote_peer_id,
        socket_address(*socket),
        static_cast<quint16>(peer_info.listenPort()),
        QStringLiteral("direct"),
        socket);
    merge_claimed_addresses(remote_peer_id, peer_info.knownAddresses(), socket);

    if (session_it->outbound) {
        pending_connections_.remove(session_it->target_peer_id);
    }

    write_peer_status_snapshot();
    send_local_peer_info(socket);
    send_known_address_hints(socket);

    if (current_peer_list_version_ >= peer_info.peerListVersion()) {
        send_current_peer_list(socket);
    }
}

void peer_service::handle_peer_list(QSslSocket *socket, const shared::v1::PeerList &peer_list)
{
    const auto update_result = security_materials_.store_peer_list_if_newer(peer_list);
    if (!update_result.success) {
        qCCritical(shared_peer_service_log) << "Rejected peer-list update" << update_result.error_message;
        close_socket(socket, update_result.error_message);
        return;
    }

    if (!update_result.updated) {
        qCInfo(shared_peer_service_log) << "Peer-list update did not change local state" << peer_list.version();
        return;
    }

    current_peer_list_bytes_ = serialize_peer_list(peer_list);
    current_peer_list_version_ = peer_list.version();
    qCInfo(shared_peer_service_log) << "Accepted newer peer list" << current_peer_list_version_;
    write_peer_status_snapshot();
    broadcast_peer_list(socket);
    attempt_connections();
}

void peer_service::handle_address_hint(QSslSocket *socket, const shared::v1::AddressHint &address_hint)
{
    if (!address_hint.hasPeerId() || address_hint.peerId().uuid().isEmpty()) {
        qCWarning(shared_peer_service_log) << "Ignoring address hint without peer id";
        return;
    }

    merge_claimed_addresses(address_hint.peerId().uuid(), address_hint.addresses(), socket);
}

void peer_service::maybe_connect_to_peer(
    const shared::v1::PeerListEntry &peer,
    const QList<shared::v1::PeerAddress> &addresses)
{
    const auto peer_id = peer.identity().peerId().uuid();
    if (has_session_for_peer(peer_id) || pending_connections_.contains(peer_id)) {
        return;
    }

    for (const auto &address : addresses) {
        if (address.ip().isEmpty() || address.port() == 0) {
            continue;
        }

        auto *socket = new QSslSocket{this};
        QString error_message{};
        if (!configure_client_socket(*socket, error_message)) {
            qCCritical(shared_peer_service_log) << "Failed to configure outbound peer socket" << error_message;
            socket->deleteLater();
            return;
        }

        attach_socket(socket, true);
        sessions_[socket].target_peer_id = peer_id;
        pending_connections_.insert(peer_id);
        connect(socket, &QSslSocket::connected, this, [this, socket, peer_id]() {
            qCInfo(shared_peer_service_log)
                << "tcp connection established to peer"
                << "peer_id=" << peer_id
                << "address=" << socket->peerAddress().toString()
                << "port=" << socket->peerPort();
            socket->setPeerVerifyName(QString{});
            socket->startClientEncryption();
        });

        qCInfo(shared_peer_service_log)
            << "connecting to peer"
            << "peer_id=" << peer_id
            << "ip=" << address.ip()
            << "port=" << address.port()
            << "source=" << address.source();
        socket->connectToHost(address.ip(), static_cast<quint16>(address.port()));
        return;
    }
}

bool peer_service::has_session_for_peer(const QString &peer_id) const
{
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.value().remote_peer_id == peer_id && it.value().authenticated) {
            return true;
        }
    }

    return false;
}

bool peer_service::should_keep_session(
    const session_state &existing_session,
    const session_state &candidate_session,
    const QString &remote_peer_id) const
{
    const auto local_owns_outbound = configuration_.peer_id < remote_peer_id;
    const auto preferred_outbound = local_owns_outbound;

    if (existing_session.outbound != candidate_session.outbound) {
        return candidate_session.outbound == preferred_outbound;
    }

    return candidate_session.local_connection_id < existing_session.local_connection_id;
}

bool peer_service::prune_duplicate_sessions(QSslSocket *socket)
{
    auto candidate_it = sessions_.find(socket);
    if (candidate_it == sessions_.end() || candidate_it->remote_peer_id.isEmpty()) {
        return true;
    }

    const auto remote_peer_id = candidate_it->remote_peer_id;
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.key() == socket || it.value().remote_peer_id != remote_peer_id || !it.value().authenticated) {
            continue;
        }

        if (should_keep_session(it.value(), candidate_it.value(), remote_peer_id)) {
            qCInfo(shared_peer_service_log) << "dropping duplicate peer session in favor of new connection" << remote_peer_id;
            close_socket(it.key(), QStringLiteral("Duplicate session lost ownership"));
            continue;
        }

        qCInfo(shared_peer_service_log) << "dropping duplicate peer session in favor of existing connection" << remote_peer_id;
        close_socket(socket, QStringLiteral("Duplicate session lost ownership"));
        return false;
    }

    return true;
}

void peer_service::merge_observed_address(
    const QString &peer_id,
    const QString &ip,
    quint16 port,
    const QString &source,
    QSslSocket *exclude_socket)
{
    if (peer_id.isEmpty() || ip.isEmpty() || port == 0) {
        return;
    }

    shared::v1::PeerAddress address{};
    address.setIp(ip);
    address.setPort(port);
    address.setSource(source);
    address.setObservedTimeMs(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch());

    bool changed{};
    address_hint_repository_.merge_address(peer_id, address, changed);
    if (!changed) {
        return;
    }

    shared::v1::PeerId hinted_peer_id{};
    hinted_peer_id.setUuid(peer_id);

    shared::v1::AddressHint address_hint{};
    address_hint.setPeerId(hinted_peer_id);
    address_hint.setAddresses({address});
    write_peer_status_snapshot();
    broadcast_address_hint(address_hint, exclude_socket);
}

void peer_service::merge_claimed_addresses(
    const QString &peer_id,
    const QList<shared::v1::PeerAddress> &addresses,
    QSslSocket *exclude_socket)
{
    bool changed{};
    address_hint_repository_.merge_addresses(peer_id, addresses, changed);
    if (!changed || addresses.isEmpty()) {
        return;
    }

    shared::v1::PeerId hinted_peer_id{};
    hinted_peer_id.setUuid(peer_id);

    shared::v1::AddressHint address_hint{};
    address_hint.setPeerId(hinted_peer_id);
    address_hint.setAddresses(addresses);
    write_peer_status_snapshot();
    broadcast_address_hint(address_hint, exclude_socket);
    attempt_connections();
}

}
