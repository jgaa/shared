#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QStringList>

namespace shared::desktop::core {

class openssl_runner {
public:
    struct result {
        bool success{};
        QByteArray standard_output{};
        QString error_message{};
    };

    [[nodiscard]] result run(
        const QStringList &arguments,
        const QString &working_directory = {},
        const QByteArray &standard_input = {}) const;
};

}
