#pragma once

#include "shared.qpb.h"

#include <QtCore/QByteArray>

namespace shared::desktop::core {

class envelope_io {
public:
    [[nodiscard]] static QByteArray serialize(const shared::v1::Envelope &envelope);
    [[nodiscard]] static bool try_read_message(QByteArray &buffer, shared::v1::Envelope &envelope, QString &error_message);
};

}
