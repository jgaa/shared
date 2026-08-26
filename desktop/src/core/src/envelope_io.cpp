#include "shared/desktop/core/envelope_io.h"

#include <QtCore/QDataStream>
#include <QtCore/QIODeviceBase>
#include <QtProtobuf/QProtobufSerializer>

namespace shared::desktop::core {

QByteArray envelope_io::serialize(const shared::v1::Envelope &envelope)
{
    QProtobufSerializer serializer{};
    const auto payload = envelope.serialize(&serializer);

    QByteArray framed_message{};
    framed_message.reserve(static_cast<int>(payload.size() + 4));

    QDataStream stream{&framed_message, QIODeviceBase::WriteOnly};
    stream.setByteOrder(QDataStream::BigEndian);
    stream << static_cast<quint32>(payload.size());
    framed_message.append(payload);

    return framed_message;
}

bool envelope_io::try_read_message(
    QByteArray &buffer,
    shared::v1::Envelope &envelope,
    QString &error_message,
    quint32 maximum_payload)
{
    if (buffer.size() < 4) {
        return false;
    }

    QDataStream stream{buffer.left(4)};
    stream.setByteOrder(QDataStream::BigEndian);

    quint32 payload_size{};
    stream >> payload_size;

    if (payload_size > maximum_payload) {
        error_message = QStringLiteral("Envelope payload exceeds the maximum allowed size");
        return false;
    }

    const auto framed_size = static_cast<qsizetype>(payload_size) + 4;
    if (buffer.size() < framed_size) {
        return false;
    }

    const auto payload = buffer.sliced(4, static_cast<qsizetype>(payload_size));
    buffer.remove(0, framed_size);

    QProtobufSerializer serializer{};
    if (!envelope.deserialize(&serializer, payload)) {
        error_message = QStringLiteral("Failed to deserialize protobuf envelope");
        return false;
    }

    return true;
}

}
