#include "shared/desktop/core/address_hint_repository.h"
#include "shared/desktop/core/app_paths.h"
#include "shared/desktop/core/configuration_repository.h"
#include "shared/desktop/core/envelope_io.h"
#include "shared/desktop/core/logging_controller.h"
#include "shared/desktop/core/pending_enrollment_repository.h"
#include "shared/desktop/core/security_materials.h"

#include "shared.qpb.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QLoggingCategory>
#include <QtCore/QTemporaryDir>
#include <QtTest/QTest>

namespace {

Q_LOGGING_CATEGORY(sharedcore_tests_log, "shared.desktop.tests")

class environment_guard {
public:
    explicit environment_guard(QTemporaryDir &temporary_dir)
    {
        base_path_ = temporary_dir.path();
        set_env("XDG_CONFIG_HOME", "config", previous_config_home_);
        set_env("XDG_DATA_HOME", "data", previous_data_home_);
        set_env("XDG_CACHE_HOME", "cache", previous_cache_home_);
        set_env("XDG_RUNTIME_DIR", "runtime", previous_runtime_dir_);

        ensure_dir(QString::fromLocal8Bit(qgetenv("XDG_CONFIG_HOME")));
        ensure_dir(QString::fromLocal8Bit(qgetenv("XDG_DATA_HOME")));
        ensure_dir(QString::fromLocal8Bit(qgetenv("XDG_CACHE_HOME")));
        ensure_dir(QString::fromLocal8Bit(qgetenv("XDG_RUNTIME_DIR")));
    }

    ~environment_guard()
    {
        restore_env("XDG_CONFIG_HOME", previous_config_home_);
        restore_env("XDG_DATA_HOME", previous_data_home_);
        restore_env("XDG_CACHE_HOME", previous_cache_home_);
        restore_env("XDG_RUNTIME_DIR", previous_runtime_dir_);
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
};

class sharedcore_tests final : public QObject {
    Q_OBJECT

private slots:
    void envelope_io_round_trip();
    void configuration_repository_round_trip();
    void pending_enrollment_repository_round_trip();
    void address_hint_repository_round_trip();
    void enrollment_fingerprint_normalization();
    void logging_controller_levels();
    void security_materials_bootstrap_flow();
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
    envelope.setEnrollmentRequest(request);

    auto framed_message = shared::desktop::core::envelope_io::serialize(envelope);
    QVERIFY(framed_message.size() > 4);

    shared::v1::Envelope decoded{};
    QString error_message{};
    QVERIFY(shared::desktop::core::envelope_io::try_read_message(framed_message, decoded, error_message));
    QVERIFY2(error_message.isEmpty(), qPrintable(error_message));
    QVERIFY(decoded.hasEnrollmentRequest());
    QCOMPARE(decoded.enrollmentRequest().verificationCode(), QStringLiteral("deadbeef"));
    QCOMPARE(decoded.enrollmentRequest().x25519PublicKey(), QByteArray(32, '\x42'));
    QVERIFY(framed_message.isEmpty());
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

    QVERIFY(QFile::exists(app_paths.ca_key_path()));
    QVERIFY(QFile::exists(app_paths.ca_certificate_path()));
    QVERIFY(QFile::exists(app_paths.server_key_path()));
    QVERIFY(QFile::exists(app_paths.server_certificate_path()));
    QVERIFY(QFile::exists(app_paths.peer_list_path()));

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

}

QTEST_MAIN(sharedcore_tests)

#include "sharedcore_tests.moc"
