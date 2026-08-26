#pragma once

#include "shared.qpb.h"

#include <QtCore/QByteArray>

namespace shared::desktop::core {

class envelope_io {
public:
    // Keep a complete, untrusted protobuf frame small enough to parse safely.
    static constexpr quint32 maximum_payload_size{8 * 1024 * 1024};
    static constexpr qsizetype maximum_frame_size{static_cast<qsizetype>(maximum_payload_size) + 4};

    [[nodiscard]] static QByteArray serialize(const shared::v1::Envelope &envelope);
    [[nodiscard]] static bool try_read_message(
        QByteArray &buffer,
        shared::v1::Envelope &envelope,
        QString &error_message,
        quint32 maximum_payload = maximum_payload_size);
};

}
