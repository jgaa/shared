#include "shared/desktop/core/address_hint_repository.h"
#include "shared/desktop/core/app_paths.h"
#include "shared/desktop/core/configuration_repository.h"
#include "shared/desktop/core/envelope_io.h"
#include "shared/desktop/core/logging_controller.h"
#include "shared/desktop/core/local_peer_addresses.h"
#include "shared/desktop/core/pending_enrollment_repository.h"
#include "shared/desktop/core/security_materials.h"
#include "shared/desktop/core/transfer_crypto.h"

#include "shared.qpb.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QLoggingCategory>
#include <QtCore/QTemporaryDir>
#include <QtTest/QTest>

namespace {

Q_LOGGING_CATEGORY(sharedcore_tests_log, "shared.desktop.tests")

QString safekeeping_vault_db_path()
{
    return QString::fromLocal8Bit(qgetenv("SAFEKEEPING_DATA_DIR"))
        + QStringLiteral("/shared-desktop/vault.db");
}

class environment_guard {
public:
    explicit environment_guard(QTemporaryDir &temporary_dir)
    {
        base_path_ = temporary_dir.path();
        set_env("XDG_CONFIG_HOME", "config", previous_config_home_);
        set_env("XDG_DATA_HOME", "data", previous_data_home_);
        set_env("XDG_CACHE_HOME", "cache", previous_cache_home_);
        set_env("XDG_RUNTIME_DIR", "runtime", previous_runtime_dir_);
        set_env("SAFEKEEPING_DATA_DIR", "safekeeping-data", previous_safekeeping_data_dir_);
        set_env("SAFEKEEPING_TEST_FAKE_VAULT_DIR", "safekeeping-fake-vault", previous_safekeeping_fake_vault_dir_);
        previous_safekeeping_disable_system_vault_ = qgetenv("SAFEKEEPING_DISABLE_SYSTEM_VAULT");
        qunsetenv("SAFEKEEPING_DISABLE_SYSTEM_VAULT");

        ensure_dir(QString::fromLocal8Bit(qgetenv("XDG_CONFIG_HOME")));
        ensure_dir(QString::fromLocal8Bit(qgetenv("XDG_DATA_HOME")));
        ensure_dir(QString::fromLocal8Bit(qgetenv("XDG_CACHE_HOME")));
        ensure_dir(QString::fromLocal8Bit(qgetenv("XDG_RUNTIME_DIR")));
        ensure_dir(QString::fromLocal8Bit(qgetenv("SAFEKEEPING_DATA_DIR")));
        ensure_dir(QString::fromLocal8Bit(qgetenv("SAFEKEEPING_TEST_FAKE_VAULT_DIR")));
        QFile::setPermissions(
            QString::fromLocal8Bit(qgetenv("XDG_RUNTIME_DIR")),
            QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    }

    ~environment_guard()
    {
        restore_env("XDG_CONFIG_HOME", previous_config_home_);
        restore_env("XDG_DATA_HOME", previous_data_home_);
        restore_env("XDG_CACHE_HOME", previous_cache_home_);
        restore_env("XDG_RUNTIME_DIR", previous_runtime_dir_);
        restore_env("SAFEKEEPING_DATA_DIR", previous_safekeeping_data_dir_);
        restore_env("SAFEKEEPING_TEST_FAKE_VAULT_DIR", previous_safekeeping_fake_vault_dir_);
        restore_env("SAFEKEEPING_DISABLE_SYSTEM_VAULT", previous_safekeeping_disable_system_vault_);
    }

private:
    static void restore_env(const char *name, const QByteArray &value)
    {
        if (value.isNull()) {
            qunsetenv(name);
            return;
        }

        qputenv(name, value);
    }

    void set_env(const char *name, const char *suffix, QByteArray &previous_value)
    {
        previous_value = qgetenv(name);
        const auto path = base_path_.isEmpty()
            ? QString{}
            : base_path_ + QStringLiteral("/") + QString::fromLatin1(suffix);
        qputenv(name, path.toUtf8());
    }

    static void ensure_dir(const QString &path)
    {
        if (!QDir{}.mkpath(path)) {
            qCCritical(sharedcore_tests_log) << "Failed to create test directory" << path;
            throw std::runtime_error(QStringLiteral("Failed to create test directory: %1").arg(path).toStdString());
        }
    }

    QString base_path_{};
    QByteArray previous_config_home_{};
    QByteArray previous_data_home_{};
    QByteArray previous_cache_home_{};
    QByteArray previous_runtime_dir_{};
    QByteArray previous_safekeeping_data_dir_{};
    QByteArray previous_safekeeping_fake_vault_dir_{};
    QByteArray previous_safekeeping_disable_system_vault_{};
};

class sharedcore_tests final : public QObject {
    Q_OBJECT

private slots:
    void envelope_io_round_trip();
    void configuration_repository_round_trip();
    void pending_enrollment_repository_round_trip();
    void address_hint_repository_round_trip();
    void local_peer_addresses_filters_loopback_and_container_interfaces();
    void enrollment_fingerprint_normalization();
    void logging_controller_levels();
    void security_materials_bootstrap_flow();
    void security_materials_reset_local_agent_state();
    void security_materials_remove_peer_from_signed_list();
    void transfer_crypto_wrap_unwrap_round_trip();
};

void sharedcore_tests::envelope_io_round_trip()
{
    shared::v1::PeerId peer_id{};
    peer_id.setUuid(QStringLiteral("01234567-89ab-7def-8123-456789abcdef"));

    shared::v1::PeerIdentity identity{};
    identity.setPeerId(peer_id);
    identity.setName(QStringLiteral("test-device"));
    identity.setPlatform(shared::v1::PlatformGadget::Platform::PLATFORM_LINUX);

    shared::v1::EnrollmentRequest request{};
    request.setRequestedIdentity(identity);
    request.setCertificateRequest(QByteArrayLiteral("csr-der"));
    request.setVerificationCode(QStringLiteral("deadbeef"));
    request.setX25519PublicKey(QByteArray(32, '\x42'));

    shared::v1::Envelope envelope{};
    envelope.setProtocolVersion(1);
    envelope.setMessageId(QStringLiteral("abc"));
    envelope.setRequestId(42);
    envelope.setEnrollmentRequest(request);

    auto framed_message = shared::desktop::core::envelope_io::serialize(envelope);
    QVERIFY(framed_message.size() > 4);

    shared::v1::Envelope decoded{};
    QString error_message{};
    QVERIFY(shared::desktop::core::envelope_io::try_read_message(framed_message, decoded, error_message));
    QVERIFY2(error_message.isEmpty(), qPrintable(error_message));
    QVERIFY(decoded.hasEnrollmentRequest());
    QVERIFY(decoded.hasRequestId());
    QCOMPARE(decoded.requestId(), static_cast<quint32>(42));
    QCOMPARE(decoded.enrollmentRequest().verificationCode(), QStringLiteral("deadbeef"));
    QCOMPARE(decoded.enrollmentRequest().x25519PublicKey(), QByteArray(32, '\x42'));
    QVERIFY(framed_message.isEmpty());

    shared::v1::PeerId destination_peer_id{};
    destination_peer_id.setUuid(QStringLiteral("89abcdef-0123-7def-8123-456789abcdef"));

    shared::v1::WhoHas who_has{};
    who_has.setDestinationPeerId(destination_peer_id);

    shared::v1::Envelope who_has_envelope{};
    who_has_envelope.setProtocolVersion(1);
    who_has_envelope.setMessageId(QStringLiteral("def"));
    who_has_envelope.setRequestId(7);
    who_has_envelope.setWhoHas(who_has);

    auto who_has_message = shared::desktop::core::envelope_io::serialize(who_has_envelope);
    shared::v1::Envelope decoded_who_has{};
    QVERIFY(shared::desktop::core::envelope_io::try_read_message(who_has_message, decoded_who_has, error_message));
    QVERIFY2(error_message.isEmpty(), qPrintable(error_message));
    QVERIFY(decoded_who_has.hasWhoHas());
    QVERIFY(decoded_who_has.hasRequestId());
    QCOMPARE(decoded_who_has.requestId(), static_cast<quint32>(7));
    QCOMPARE(decoded_who_has.whoHas().destinationPeerId().uuid(), destination_peer_id.uuid());
}

void sharedcore_tests::configuration_repository_round_trip()
{
    QTemporaryDir temporary_dir{};
    QVERIFY(temporary_dir.isValid());
    environment_guard guard{temporary_dir};

    shared::desktop::core::configuration_repository repository{};
    const auto loaded_before = repository.load();
    QVERIFY(!loaded_before.initialized);

    shared::desktop::core::agent_configuration configuration{};
    configuration.initialized = true;
    configuration.role = shared::desktop::core::agent_role::peer;
    configuration.peer_id = QStringLiteral("peer-id");
    configuration.name = QStringLiteral("peer-name");
    configuration.enrollment_host = QStringLiteral("127.0.0.2");
    configuration.enrollment_port = 49999;
    configuration.peer_host = QStringLiteral("127.0.0.3");
    configuration.peer_port = 49998;
    configuration.trusted_agent.host = QStringLiteral("127.0.0.1");
    configuration.trusted_agent.port = 47123;
    configuration.trusted_agent.peer_port = 47124;
    configuration.trusted_agent.pinned_server_fingerprint = QStringLiteral("abcd");

    repository.save(configuration);

    const auto loaded_after = repository.load();
    QVERIFY(loaded_after.initialized);
    QCOMPARE(loaded_after.role, shared::desktop::core::agent_role::peer);
    QCOMPARE(loaded_after.peer_id, QStringLiteral("peer-id"));
    QCOMPARE(loaded_after.name, QStringLiteral("peer-name"));
    QCOMPARE(loaded_after.enrollment_host, QStringLiteral("127.0.0.2"));
    QCOMPARE(loaded_after.enrollment_port, static_cast<quint16>(49999));
    QCOMPARE(loaded_after.peer_host, QStringLiteral("127.0.0.3"));
    QCOMPARE(loaded_after.peer_port, static_cast<quint16>(49998));
    QCOMPARE(loaded_after.trusted_agent.host, QStringLiteral("127.0.0.1"));
    QCOMPARE(loaded_after.trusted_agent.port, static_cast<quint16>(47123));
    QCOMPARE(loaded_after.trusted_agent.peer_port, static_cast<quint16>(47124));
    QCOMPARE(loaded_after.trusted_agent.pinned_server_fingerprint, QStringLiteral("abcd"));
}

void sharedcore_tests::pending_enrollment_repository_round_trip()
{
    QTemporaryDir temporary_dir{};
    QVERIFY(temporary_dir.isValid());
    environment_guard guard{temporary_dir};

    shared::desktop::core::app_paths app_paths{};
    QVERIFY(app_paths.ensure_directories());

    shared::desktop::core::pending_enrollment_repository repository{app_paths};
    shared::desktop::core::pending_enrollment_request request{};
    request.request_id = QStringLiteral("request-1");
    request.peer_id = QStringLiteral("peer-1");
    request.name = QStringLiteral("test");
    request.verification_code = QStringLiteral("cafebabe");
    request.certificate_request = QByteArrayLiteral("csr");
    request.x25519_public_key = QByteArray(32, '\x11');
    request.created_time_ms = 12345;

    repository.save_request(request);

    const auto loaded_request = repository.load_request(QStringLiteral("request-1"));
    QVERIFY(loaded_request.has_value());
    QCOMPARE(loaded_request->peer_id, QStringLiteral("peer-1"));
    QCOMPARE(loaded_request->verification_code, QStringLiteral("cafebabe"));

    repository.save_decision(QStringLiteral("request-1"), true, QStringLiteral("approved"));
    const auto loaded_decision = repository.load_decision(QStringLiteral("request-1"));
    QVERIFY(loaded_decision.has_value());
    QVERIFY(loaded_decision->decided);
    QVERIFY(loaded_decision->approved);
    QCOMPARE(loaded_decision->message, QStringLiteral("approved"));

    repository.remove_request(QStringLiteral("request-1"));
    QVERIFY(!repository.load_request(QStringLiteral("request-1")).has_value());
    QVERIFY(!repository.load_decision(QStringLiteral("request-1")).has_value());

    shared::desktop::core::pending_enrollment_request stale_request{};
    stale_request.request_id = QStringLiteral("request-2");
    stale_request.peer_id = QStringLiteral("peer-2");
    stale_request.name = QStringLiteral("stale");
    stale_request.verification_code = QStringLiteral("deadbeef");
    stale_request.certificate_request = QByteArrayLiteral("csr-2");
    stale_request.x25519_public_key = QByteArray(32, '\x22');
    stale_request.created_time_ms = 67890;

    repository.save_request(stale_request);
    repository.save_decision(QStringLiteral("request-2"), false, QStringLiteral("stale"));
    repository.remove_all_requests();
    QVERIFY(repository.load_requests().isEmpty());
    QVERIFY(!repository.load_decision(QStringLiteral("request-2")).has_value());
}

void sharedcore_tests::address_hint_repository_round_trip()
{
    QTemporaryDir temporary_dir{};
    QVERIFY(temporary_dir.isValid());
    environment_guard guard{temporary_dir};

    shared::desktop::core::app_paths app_paths{};
    QVERIFY(app_paths.ensure_directories());

    shared::desktop::core::address_hint_repository repository{app_paths};
    shared::v1::PeerAddress first{};
    first.setIp(QStringLiteral("10.0.0.10"));
    first.setPort(47124);
    first.setSource(QStringLiteral("gossip"));
    first.setObservedTimeMs(1000);

    bool changed{};
    repository.merge_address(QStringLiteral("peer-1"), first, changed);
    QVERIFY(changed);

    changed = false;
    repository.merge_address(QStringLiteral("peer-1"), first, changed);
    QVERIFY(!changed);

    shared::v1::PeerAddress updated = first;
    updated.setObservedTimeMs(2000);
    repository.merge_address(QStringLiteral("peer-1"), updated, changed);
    QVERIFY(changed);

    const auto loaded = repository.load_for_peer(QStringLiteral("peer-1"));
    QCOMPARE(loaded.size(), 1);
    QCOMPARE(loaded.first().ip(), QStringLiteral("10.0.0.10"));
    QCOMPARE(loaded.first().port(), static_cast<quint32>(47124));
    QCOMPARE(loaded.first().observedTimeMs(), static_cast<quint64>(2000));

    shared::desktop::core::address_hint_repository restarted_repository{app_paths};
    const auto restarted_loaded = restarted_repository.load_for_peer(QStringLiteral("peer-1"));
    QCOMPARE(restarted_loaded.size(), 1);
    QCOMPARE(restarted_loaded.first().ip(), QStringLiteral("10.0.0.10"));
    QCOMPARE(restarted_loaded.first().port(), static_cast<quint32>(47124));
    QCOMPARE(restarted_loaded.first().observedTimeMs(), static_cast<quint64>(2000));

    shared::v1::PeerAddress manual{};
    manual.setIp(QStringLiteral("198.51.100.10"));
    manual.setPort(47124);
    manual.setSource(QStringLiteral("manual"));
    manual.setObservedTimeMs(3000);
    repository.merge_address(QStringLiteral("peer-1"), manual, changed);
    QVERIFY(changed);

    shared::v1::PeerAddress local{};
    local.setIp(QStringLiteral("192.168.1.10"));
    local.setPort(47124);
    local.setSource(QStringLiteral("local"));
    local.setObservedTimeMs(0);
    repository.replace_source_addresses(QStringLiteral("peer-1"), QStringLiteral("local"), {local}, changed);
    QVERIFY(changed);

    changed = false;
    repository.replace_source_addresses(QStringLiteral("peer-1"), QStringLiteral("local"), {local}, changed);
    QVERIFY(!changed);

    shared::v1::PeerAddress updated_local = local;
    updated_local.setIp(QStringLiteral("10.0.0.20"));
    repository.replace_source_addresses(
        QStringLiteral("peer-1"),
        QStringLiteral("local"),
        {updated_local},
        changed);
    QVERIFY(changed);

    const auto with_local = repository.load_for_peer(QStringLiteral("peer-1"));
    QCOMPARE(with_local.size(), 3);
    QCOMPARE(with_local.at(0).ip(), QStringLiteral("10.0.0.10"));
    QCOMPARE(with_local.at(1).ip(), QStringLiteral("198.51.100.10"));
    QCOMPARE(with_local.at(2).ip(), QStringLiteral("10.0.0.20"));
    QCOMPARE(with_local.at(2).source(), QStringLiteral("local"));
}

void sharedcore_tests::local_peer_addresses_filters_loopback_and_container_interfaces()
{
    QList<shared::desktop::core::local_interface_address> candidates{
        {
            QStringLiteral("wlan0"),
            QNetworkInterface::IsUp | QNetworkInterface::IsRunning,
            QHostAddress{QStringLiteral("192.168.1.20")},
        },
        {
            QStringLiteral("eth0"),
            QNetworkInterface::IsUp | QNetworkInterface::IsRunning,
            QHostAddress{QStringLiteral("fd00::20")},
        },
        {
            QStringLiteral("lo"),
            QNetworkInterface::IsUp | QNetworkInterface::IsRunning | QNetworkInterface::IsLoopBack,
            QHostAddress{QStringLiteral("127.0.0.1")},
        },
        {
            QStringLiteral("docker0"),
            QNetworkInterface::IsUp | QNetworkInterface::IsRunning,
            QHostAddress{QStringLiteral("172.17.0.1")},
        },
        {
            QStringLiteral("veth7c1d"),
            QNetworkInterface::IsUp | QNetworkInterface::IsRunning,
            QHostAddress{QStringLiteral("10.244.0.1")},
        },
        {
            QStringLiteral("eth0"),
            QNetworkInterface::IsUp | QNetworkInterface::IsRunning,
            QHostAddress{QStringLiteral("fe80::1234")},
        },
        {
            QStringLiteral("eth0"),
            QNetworkInterface::IsUp | QNetworkInterface::IsRunning,
            QHostAddress{QStringLiteral("169.254.10.2")},
        },
        {
            QStringLiteral("wlan0"),
            QNetworkInterface::IsUp | QNetworkInterface::IsRunning,
            QHostAddress{QStringLiteral("192.168.1.20")},
        },
    };

    const auto addresses = shared::desktop::core::local_peer_addresses_for_candidates(47124, candidates);
    QCOMPARE(addresses.size(), 2);
    QCOMPARE(addresses.at(0).ip(), QStringLiteral("192.168.1.20"));
    QCOMPARE(addresses.at(0).port(), static_cast<quint32>(47124));
    QCOMPARE(addresses.at(0).source(), QStringLiteral("local"));
    QCOMPARE(addresses.at(0).observedTimeMs(), static_cast<quint64>(0));
    QCOMPARE(addresses.at(1).ip(), QStringLiteral("fd00::20"));
    QCOMPARE(addresses.at(1).port(), static_cast<quint32>(47124));
    QCOMPARE(addresses.at(1).source(), QStringLiteral("local"));
    QCOMPARE(addresses.at(1).observedTimeMs(), static_cast<quint64>(0));
}

void sharedcore_tests::enrollment_fingerprint_normalization()
{
    QCOMPARE(
        shared::desktop::core::security_materials::normalize_enrollment_fingerprint(QStringLiteral("abcd-1234")),
        QStringLiteral("abcd1234"));
    QCOMPARE(
        shared::desktop::core::security_materials::normalize_enrollment_fingerprint(QStringLiteral("ABCD1234")),
        QStringLiteral("abcd1234"));
    QCOMPARE(
        shared::desktop::core::security_materials::format_enrollment_fingerprint(QStringLiteral("abcd1234")),
        QStringLiteral("abcd-1234"));
    QVERIFY(
        shared::desktop::core::security_materials::normalize_enrollment_fingerprint(QStringLiteral("abc-1234")).isEmpty());
    QVERIFY(
        shared::desktop::core::security_materials::normalize_enrollment_fingerprint(QStringLiteral("abcd-123z")).isEmpty());
}

void sharedcore_tests::logging_controller_levels()
{
    QCOMPARE(
        shared::desktop::core::logging_controller::parse_log_level_name(QStringLiteral("trace")).value(),
        shared::desktop::core::logging_controller::trace_level);
    QCOMPARE(
        shared::desktop::core::logging_controller::parse_log_level_name(QStringLiteral("warning")).value(),
        shared::desktop::core::logging_controller::warn_level);
    QCOMPARE(
        shared::desktop::core::logging_controller::parse_log_level_name(QStringLiteral("off")).value(),
        shared::desktop::core::logging_controller::disabled_level);
    QVERIFY(
        !shared::desktop::core::logging_controller::parse_log_level_name(QStringLiteral("verbose")).has_value());
}

void sharedcore_tests::security_materials_bootstrap_flow()
{
    QTemporaryDir temporary_dir{};
    QVERIFY(temporary_dir.isValid());
    environment_guard guard{temporary_dir};

    shared::desktop::core::app_paths app_paths{};
    QVERIFY(app_paths.ensure_directories());

    shared::desktop::core::security_materials security_materials{app_paths};

    const auto trusted_agent_result = security_materials.initialize_local_trusted_agent(
        QStringLiteral("trusted-box"),
        47123);
    QVERIFY2(trusted_agent_result.success, qPrintable(trusted_agent_result.error_message));
    QVERIFY(!trusted_agent_result.peer_id.isEmpty());
    QCOMPARE(trusted_agent_result.enrollment_fingerprint.size(), 9);
    QCOMPARE(trusted_agent_result.enrollment_fingerprint.at(4), QLatin1Char('-'));

    QVERIFY(QFile::exists(safekeeping_vault_db_path()));
    QString vault_error{};
    QVERIFY(!security_materials.current_ca_certificate_pem(vault_error).isEmpty());
    QVERIFY2(vault_error.isEmpty(), qPrintable(vault_error));
    QVERIFY(!security_materials.current_server_certificate_pem(vault_error).isEmpty());
    QVERIFY2(vault_error.isEmpty(), qPrintable(vault_error));
    QVERIFY(!security_materials.current_peer_certificate_pem(vault_error).isEmpty());
    QVERIFY2(vault_error.isEmpty(), qPrintable(vault_error));

    const auto enrollment = security_materials.prepare_enrollment_request(QStringLiteral("joining-box"));
    QVERIFY2(enrollment.success, qPrintable(enrollment.error_message));
    QVERIFY(!enrollment.peer_id.isEmpty());
    QCOMPARE(enrollment.verification_code.size(), 8);
    QVERIFY(enrollment.request.hasRequestedIdentity());
    QCOMPARE(enrollment.request.requestedIdentity().name(), QStringLiteral("joining-box"));
    QCOMPARE(enrollment.request.x25519PublicKey().size(), 32);
    QVERIFY(!enrollment.request.certificateRequest().isEmpty());

    shared::desktop::core::agent_configuration configuration{};
    configuration.initialized = true;
    configuration.role = shared::desktop::core::agent_role::local_trusted_agent;
    configuration.peer_id = trusted_agent_result.peer_id;
    configuration.name = QStringLiteral("trusted-box");
    configuration.enrollment_port = 47123;
    configuration.peer_port = 47124;

    shared::desktop::core::pending_enrollment_request request{};
    request.request_id = QStringLiteral("request-1");
    request.peer_id = enrollment.peer_id;
    request.name = QStringLiteral("joining-box");
    request.verification_code = enrollment.verification_code;
    request.certificate_request = enrollment.request.certificateRequest();
    request.x25519_public_key = enrollment.request.x25519PublicKey();
    request.created_time_ms = 12345;

    QString approval_error{};
    const auto decision = security_materials.build_approved_decision(configuration, request, approval_error);
    QVERIFY2(approval_error.isEmpty(), qPrintable(approval_error));
    QVERIFY(decision.approved());
    QVERIFY(!decision.signedCertificate().isEmpty());
    QVERIFY(decision.hasPeerList());
    QVERIFY(decision.hasTrustedAgentCaCertificate());

    QString peer_list_error{};
    QVERIFY(security_materials.validate_peer_list(decision.peerList(), peer_list_error));
    QVERIFY2(peer_list_error.isEmpty(), qPrintable(peer_list_error));

    const auto current_peer_list = security_materials.current_peer_list(peer_list_error);
    QVERIFY2(peer_list_error.isEmpty(), qPrintable(peer_list_error));
    QCOMPARE(current_peer_list.version(), static_cast<quint32>(2));
    QCOMPARE(current_peer_list.peers().size(), 2);

    const auto update_result = security_materials.store_peer_list_if_newer(decision.peerList());
    QVERIFY2(update_result.success, qPrintable(update_result.error_message));
    QVERIFY(!update_result.updated);

    QString known_peer_error{};
    QVERIFY(security_materials.is_known_peer_identity(
        enrollment.peer_id,
        QStringLiteral("joining-box"),
        decision.peerList().peers().last().certificateFingerprintSha256(),
        known_peer_error));
    QVERIFY2(known_peer_error.isEmpty(), qPrintable(known_peer_error));

    auto duplicate_name_request = request;
    duplicate_name_request.request_id = QStringLiteral("request-2");
    duplicate_name_request.peer_id = QStringLiteral("duplicate-peer-id");
    QString duplicate_name_error{};
    const auto duplicate_name_decision =
        security_materials.build_approved_decision(configuration, duplicate_name_request, duplicate_name_error);
    QVERIFY(!duplicate_name_decision.approved());
    QCOMPARE(duplicate_name_error, QStringLiteral("Peer list contains duplicate peer names"));
}

void sharedcore_tests::security_materials_reset_local_agent_state()
{
    QTemporaryDir temporary_dir{};
    QVERIFY(temporary_dir.isValid());
    environment_guard guard{temporary_dir};

    shared::desktop::core::app_paths app_paths{};
    QVERIFY(app_paths.ensure_directories());

    shared::desktop::core::security_materials security_materials{app_paths};
    shared::desktop::core::pending_enrollment_repository pending_repository{app_paths};

    const auto trusted_agent_result = security_materials.initialize_local_trusted_agent(
        QStringLiteral("trusted-box"),
        47123);
    QVERIFY2(trusted_agent_result.success, qPrintable(trusted_agent_result.error_message));

    const auto enrollment = security_materials.prepare_enrollment_request(QStringLiteral("joining-box"));
    QVERIFY2(enrollment.success, qPrintable(enrollment.error_message));

    pending_repository.save_request({
        .request_id = QStringLiteral("request-1"),
        .peer_id = enrollment.peer_id,
        .name = QStringLiteral("joining-box"),
        .verification_code = enrollment.verification_code,
        .certificate_request = enrollment.request.certificateRequest(),
        .x25519_public_key = enrollment.request.x25519PublicKey(),
        .created_time_ms = 12345,
    });
    pending_repository.save_decision(QStringLiteral("request-1"), true, QStringLiteral("Approved"));

    QCOMPARE(pending_repository.load_requests().size(), 1);

    const auto reset_result = security_materials.reset_local_agent_state();
    QVERIFY2(reset_result.success, qPrintable(reset_result.error_message));

    QString post_reset_error{};
    QVERIFY(security_materials.current_ca_certificate_pem(post_reset_error).isEmpty());
    QVERIFY(security_materials.current_peer_private_key_pem(post_reset_error).isEmpty());
    QVERIFY(!QFile::exists(app_paths.address_hints_path()));
    QVERIFY(!QFile::exists(app_paths.peer_status_path()));
    QVERIFY(!QFile::exists(safekeeping_vault_db_path()));
    QCOMPARE(pending_repository.load_requests().size(), 0);
    QVERIFY(QDir{app_paths.pending_enrollments_dir()}.entryList(QDir::NoDotAndDotDot | QDir::AllEntries).isEmpty());
}

void sharedcore_tests::security_materials_remove_peer_from_signed_list()
{
    QTemporaryDir temporary_dir{};
    QVERIFY(temporary_dir.isValid());
    environment_guard guard{temporary_dir};

    shared::desktop::core::app_paths app_paths{};
    QVERIFY(app_paths.ensure_directories());

    shared::desktop::core::security_materials security_materials{app_paths};

    const auto trusted_agent_result = security_materials.initialize_local_trusted_agent(
        QStringLiteral("trusted-box"),
        47123);
    QVERIFY2(trusted_agent_result.success, qPrintable(trusted_agent_result.error_message));

    shared::desktop::core::agent_configuration configuration{};
    configuration.initialized = true;
    configuration.role = shared::desktop::core::agent_role::local_trusted_agent;
    configuration.peer_id = trusted_agent_result.peer_id;
    configuration.name = QStringLiteral("trusted-box");
    configuration.enrollment_port = 47123;
    configuration.peer_port = 47124;

    const auto enrollment = security_materials.prepare_enrollment_request(QStringLiteral("joining-box"));
    QVERIFY2(enrollment.success, qPrintable(enrollment.error_message));

    shared::desktop::core::pending_enrollment_request request{};
    request.request_id = QStringLiteral("request-1");
    request.peer_id = enrollment.peer_id;
    request.name = QStringLiteral("joining-box");
    request.verification_code = enrollment.verification_code;
    request.certificate_request = enrollment.request.certificateRequest();
    request.x25519_public_key = enrollment.request.x25519PublicKey();
    request.created_time_ms = 12345;

    QString approval_error{};
    const auto decision = security_materials.build_approved_decision(configuration, request, approval_error);
    QVERIFY2(approval_error.isEmpty(), qPrintable(approval_error));
    QVERIFY(decision.approved());

    const auto removal_result = security_materials.remove_peer_from_current_peer_list(configuration, enrollment.peer_id);
    QVERIFY2(removal_result.success, qPrintable(removal_result.error_message));

    QString peer_list_error{};
    const auto current_peer_list = security_materials.current_peer_list(peer_list_error);
    QVERIFY2(peer_list_error.isEmpty(), qPrintable(peer_list_error));
    QCOMPARE(current_peer_list.version(), static_cast<quint32>(3));
    QCOMPARE(current_peer_list.peers().size(), 1);
    QCOMPARE(current_peer_list.peers().first().identity().peerId().uuid(), trusted_agent_result.peer_id);

    QString known_peer_error{};
    QVERIFY(!security_materials.is_known_peer_identity(
        enrollment.peer_id,
        QStringLiteral("joining-box"),
        decision.peerList().peers().last().certificateFingerprintSha256(),
        known_peer_error));
    QCOMPARE(known_peer_error, QStringLiteral("Peer is not present in the signed peer list"));
}

void sharedcore_tests::transfer_crypto_wrap_unwrap_round_trip()
{
    QTemporaryDir sender_dir{};
    QVERIFY(sender_dir.isValid());
    QTemporaryDir recipient_dir{};
    QVERIFY(recipient_dir.isValid());

    QByteArray sender_public_key{};
    QByteArray recipient_public_key{};
    QByteArray wrapped_payload_key{};
    QByteArray payload_key{};

    {
        environment_guard guard{recipient_dir};
        shared::desktop::core::app_paths app_paths{};
        QVERIFY(app_paths.ensure_directories());

        shared::desktop::core::security_materials security_materials{app_paths};
        const auto enrollment = security_materials.prepare_enrollment_request(QStringLiteral("recipient-box"));
        QVERIFY2(enrollment.success, qPrintable(enrollment.error_message));
        recipient_public_key = enrollment.request.x25519PublicKey();
        QCOMPARE(recipient_public_key.size(), 32);
    }

    {
        environment_guard guard{sender_dir};
        shared::desktop::core::app_paths app_paths{};
        QVERIFY(app_paths.ensure_directories());

        shared::desktop::core::security_materials security_materials{app_paths};
        const auto enrollment = security_materials.prepare_enrollment_request(QStringLiteral("sender-box"));
        QVERIFY2(enrollment.success, qPrintable(enrollment.error_message));
        sender_public_key = enrollment.request.x25519PublicKey();
        QCOMPARE(sender_public_key.size(), 32);

        QString random_error{};
        const auto sender_private_key_pem = security_materials.current_x25519_private_key_pem(random_error);
        QVERIFY2(random_error.isEmpty(), qPrintable(random_error));
        QVERIFY(!sender_private_key_pem.isEmpty());

        payload_key = shared::desktop::core::transfer_crypto::random_bytes(
            shared::desktop::core::transfer_crypto::payload_key_size,
            random_error);
        QVERIFY2(random_error.isEmpty(), qPrintable(random_error));
        QCOMPARE(payload_key.size(), shared::desktop::core::transfer_crypto::payload_key_size);

        QString wrap_error{};
        wrapped_payload_key = shared::desktop::core::transfer_crypto::wrap_payload_key_for_recipient(
            sender_private_key_pem,
            recipient_public_key,
            payload_key,
            wrap_error);
        QVERIFY2(wrap_error.isEmpty(), qPrintable(wrap_error));
        QVERIFY(!wrapped_payload_key.isEmpty());
    }

    {
        environment_guard guard{recipient_dir};
        shared::desktop::core::app_paths app_paths{};
        QVERIFY(app_paths.ensure_directories());
        shared::desktop::core::security_materials security_materials{app_paths};
        const auto restore_result = security_materials.ensure_runtime_materials();
        QVERIFY2(restore_result.success, qPrintable(restore_result.error_message));
        QString recipient_key_error{};
        const auto recipient_private_key_pem = security_materials.current_x25519_private_key_pem(recipient_key_error);
        QVERIFY2(recipient_key_error.isEmpty(), qPrintable(recipient_key_error));
        QVERIFY(!recipient_private_key_pem.isEmpty());

        QString unwrap_error{};
        const auto unwrapped_payload_key =
            shared::desktop::core::transfer_crypto::unwrap_payload_key_from_sender(
                recipient_private_key_pem,
                sender_public_key,
                wrapped_payload_key,
                unwrap_error);
        QVERIFY2(unwrap_error.isEmpty(), qPrintable(unwrap_error));
        QCOMPARE(unwrapped_payload_key, payload_key);
    }
}

}

QTEST_MAIN(sharedcore_tests)

#include "sharedcore_tests.moc"
