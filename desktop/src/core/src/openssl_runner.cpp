#include "shared/desktop/core/openssl_runner.h"

#include <QtCore/QLoggingCategory>
#include <QtCore/QProcess>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_openssl_runner_log, "shared.desktop.core.openssl_runner")

openssl_runner::result openssl_runner::run(
    const QStringList &arguments,
    const QString &working_directory,
    const QByteArray &standard_input) const
{
    QProcess process{};
    process.setProgram(QStringLiteral("openssl"));
    process.setArguments(arguments);

    if (!working_directory.isEmpty()) {
        process.setWorkingDirectory(working_directory);
    }

    process.start();
    if (!process.waitForStarted()) {
        qCCritical(shared_openssl_runner_log) << "Failed to start openssl" << arguments << process.errorString();
        return {
            .success = false,
            .error_message = QStringLiteral("Failed to start openssl"),
        };
    }

    if (!standard_input.isEmpty()) {
        if (process.write(standard_input) != standard_input.size()) {
            qCCritical(shared_openssl_runner_log) << "Failed to write stdin to openssl" << arguments << process.errorString();
            process.kill();
            process.waitForFinished();
            return {
                .success = false,
                .error_message = QStringLiteral("Failed to write input to openssl"),
            };
        }
    }
    process.closeWriteChannel();

    if (!process.waitForFinished()) {
        process.kill();
        process.waitForFinished();
        qCCritical(shared_openssl_runner_log) << "openssl did not finish in time" << arguments;
        return {
            .success = false,
            .error_message = QStringLiteral("openssl did not finish in time"),
        };
    }

    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        qCCritical(shared_openssl_runner_log) << "openssl failed" << arguments
            << process.exitStatus() << process.exitCode()
            << QString::fromUtf8(process.readAllStandardError()).trimmed();
        return {
            .success = false,
            .standard_output = process.readAllStandardOutput(),
            .error_message = QString::fromUtf8(process.readAllStandardError()).trimmed(),
        };
    }

    return {
        .success = true,
        .standard_output = process.readAllStandardOutput(),
    };
}

}
