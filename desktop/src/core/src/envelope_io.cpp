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
    QString &error_message)
{
    if (buffer.size() < 4) {
        return false;
    }

    QDataStream stream{buffer.left(4)};
    stream.setByteOrder(QDataStream::BigEndian);

    quint32 payload_size{};
    stream >> payload_size;

    if (buffer.size() < static_cast<int>(payload_size + 4)) {
        return false;
    }

    const auto payload = buffer.sliced(4, payload_size);
    buffer.remove(0, static_cast<int>(payload_size + 4));

    QProtobufSerializer serializer{};
    if (!envelope.deserialize(&serializer, payload)) {
        error_message = QStringLiteral("Failed to deserialize protobuf envelope");
        return false;
    }

    return true;
}

}
