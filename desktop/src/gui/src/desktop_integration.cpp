#include "desktop_integration.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QEventLoop>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QRandomGenerator>
#include <QtCore/QSaveFile>
#include <QtCore/QStandardPaths>
#include <QtCore/QUrl>
#include <QtCore/QVariantMap>
#include <QtCore/QXmlStreamWriter>
#include <QtWidgets/QFileDialog>

#if defined(Q_OS_LINUX)
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusObjectPath>
#endif

namespace shared::desktop::gui::desktop_integration {

#if defined(Q_OS_LINUX)
#if SHARED_FLATPAK_BUILD
class portal_response_waiter final : public QObject {
    Q_OBJECT

public:
    struct result_state {
        bool completed{false};
        bool background_allowed{false};
        bool autostart_enabled{false};
        QString error_message{};
    };

    result_state *result{nullptr};
    QEventLoop *loop{nullptr};

public slots:
    void handle_response(uint response, const QVariantMap &payload)
    {
        if (result == nullptr || loop == nullptr) {
            return;
        }

        result->completed = true;
        if (response != 0) {
            result->error_message = response == 1
                ? QStringLiteral("Automatic start was denied")
                : QStringLiteral("Automatic start request failed");
            loop->quit();
            return;
        }

        result->background_allowed = payload.value(QStringLiteral("background")).toBool();
        result->autostart_enabled = payload.value(QStringLiteral("autostart")).toBool();
        loop->quit();
    }
};

#endif

struct file_chooser_portal_result {
    bool requested{false};
    bool accepted{false};
    QStringList uris{};
    QString error_message{};
};

class file_chooser_portal_waiter final : public QObject {
    Q_OBJECT

public:
    file_chooser_portal_result *result{nullptr};
    QEventLoop *loop{nullptr};

public slots:
    void handle_response(uint response, const QVariantMap &payload)
    {
        if (result == nullptr || loop == nullptr) {
            return;
        }

        result->requested = true;
        result->accepted = response == 0;
        if (result->accepted) {
            result->uris = payload.value(QStringLiteral("uris")).toStringList();
        } else if (response != 1) {
            result->error_message = QStringLiteral("File chooser portal request failed");
        }
        loop->quit();
    }
};

#endif

namespace {
#if defined(Q_OS_LINUX) && !SHARED_FLATPAK_BUILD
QString local_autostart_entry_path()
{
    return QDir{
        QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)
    }.filePath(QStringLiteral("autostart/eu.lastviking.shared.desktop"));
}

QString escape_desktop_exec_argument(QString value)
{
    value.replace(QStringLiteral("\\"), QStringLiteral("\\\\"));
    value.replace(QStringLiteral("\""), QStringLiteral("\\\""));
    value.replace(QStringLiteral("$"), QStringLiteral("\\$"));
    value.replace(QStringLiteral("`"), QStringLiteral("\\`"));
    return QStringLiteral("\"%1\"").arg(value);
}

QString local_autostart_icon_path()
{
    return QDir{
        QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
    }.filePath(QStringLiteral("shared/icons/eu.lastviking.shared.svg"));
}

bool ensure_local_autostart_icon(QString &error_message)
{
    const auto icon_path = local_autostart_icon_path();
    const QFileInfo icon_info{icon_path};
    const auto icon_directory = icon_info.dir();
    if (!icon_directory.exists() && !QDir{}.mkpath(icon_directory.absolutePath())) {
        error_message = QStringLiteral("Failed to create icon directory: %1")
                            .arg(icon_directory.absolutePath());
        return false;
    }

    QFile source_icon{QStringLiteral(":/shared/icons/shared-icon.svg")};
    if (!source_icon.open(QIODevice::ReadOnly)) {
        error_message = QStringLiteral("Failed to open bundled application icon");
        return false;
    }

    const auto icon_contents = source_icon.readAll();
    source_icon.close();
    if (icon_contents.isEmpty()) {
        error_message = QStringLiteral("Bundled application icon is empty");
        return false;
    }

    QFile existing_icon{icon_path};
    if (existing_icon.exists()) {
        if (!existing_icon.open(QIODevice::ReadOnly)) {
            error_message = QStringLiteral("Failed to read existing application icon: %1").arg(icon_path);
            return false;
        }
        const auto existing_contents = existing_icon.readAll();
        existing_icon.close();
        if (existing_contents == icon_contents) {
            return true;
        }
    }

    QFile icon_file{icon_path};
    if (!icon_file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        error_message = QStringLiteral("Failed to write application icon: %1").arg(icon_path);
        return false;
    }
    if (icon_file.write(icon_contents) < 0) {
        error_message = QStringLiteral("Failed to write application icon: %1").arg(icon_path);
        return false;
    }
    icon_file.close();

    if (!QFile::setPermissions(
            icon_path,
            QFileDevice::ReadOwner
                | QFileDevice::WriteOwner
                | QFileDevice::ReadGroup
                | QFileDevice::ReadOther)) {
        error_message = QStringLiteral("Failed to update application icon permissions: %1").arg(icon_path);
        return false;
    }

    return true;
}

QString local_autostart_entry_contents()
{
    const auto executable_path = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
    const auto executable_with_flag = QStringLiteral("%1 --autostart")
                                          .arg(escape_desktop_exec_argument(executable_path));
    return QStringLiteral(
               "[Desktop Entry]\n"
               "Type=Application\n"
               "Version=1.0\n"
               "Name=Shared\n"
               "Comment=Secure peer-to-peer clipboard and file transfer\n"
               "Exec=%1\n"
                "Icon=%2\n"
               "Categories=Network;FileTransfer;Qt;\n"
               "Hidden=false\n"
               "StartupNotify=true\n"
               "Terminal=false\n"
               "X-GNOME-Autostart-enabled=true\n")
        .arg(executable_with_flag, local_autostart_icon_path());
}

bool set_local_autostart_enabled(bool enabled, QString &error_message)
{
    const auto entry_path = local_autostart_entry_path();
    const QFileInfo entry_info{entry_path};

    if (!enabled) {
        if (!entry_info.exists()) {
            return true;
        }

        if (QFile::remove(entry_path)) {
            return true;
        }

        error_message = QStringLiteral("Failed to remove autostart entry: %1").arg(entry_path);
        return false;
    }

    if (!ensure_local_autostart_icon(error_message)) {
        return false;
    }

    const auto parent_directory = entry_info.dir();
    if (!parent_directory.exists() && !QDir{}.mkpath(parent_directory.absolutePath())) {
        error_message = QStringLiteral("Failed to create autostart directory: %1")
                            .arg(parent_directory.absolutePath());
        return false;
    }

    QFile entry_file{entry_path};
    if (!entry_file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        error_message = QStringLiteral("Failed to write autostart entry: %1").arg(entry_path);
        return false;
    }

    if (entry_file.write(local_autostart_entry_contents().toUtf8()) < 0) {
        error_message = QStringLiteral("Failed to write autostart entry: %1").arg(entry_path);
        return false;
    }

    entry_file.close();
    if (!QFile::setPermissions(
            entry_path,
            QFileDevice::ReadOwner
                | QFileDevice::WriteOwner
                | QFileDevice::ReadGroup
                | QFileDevice::ReadOther)) {
        error_message = QStringLiteral("Failed to update autostart entry permissions: %1").arg(entry_path);
        return false;
    }

    return true;
}
#endif

#if SHARED_FLATPAK_BUILD
portal_response_waiter::result_state request_flatpak_background_autostart(bool enabled)
{
    portal_response_waiter::result_state result{};

    QDBusInterface background_portal{
        QStringLiteral("org.freedesktop.portal.Desktop"),
        QStringLiteral("/org/freedesktop/portal/desktop"),
        QStringLiteral("org.freedesktop.portal.Background"),
        QDBusConnection::sessionBus()};
    if (!background_portal.isValid()) {
        result.error_message = QStringLiteral("Background portal is not available");
        return result;
    }

    QVariantMap options{};
    options.insert(
        QStringLiteral("handle_token"),
        QStringLiteral("shared_%1").arg(QString::number(QRandomGenerator::global()->generate64(), 16)));
    options.insert(
        QStringLiteral("reason"),
        QStringLiteral("Start Shared automatically when you log in"));
    options.insert(QStringLiteral("autostart"), enabled);

    const auto request_message = background_portal.call(
        QStringLiteral("RequestBackground"),
        QStringLiteral(""),
        options);
    if (request_message.type() == QDBusMessage::ErrorMessage) {
        result.error_message = request_message.errorMessage();
        return result;
    }

    if (request_message.arguments().isEmpty()
        || !request_message.arguments().constFirst().canConvert<QDBusObjectPath>()) {
        result.error_message = QStringLiteral("Background portal returned an invalid request handle");
        return result;
    }

    const auto request_path = request_message.arguments().constFirst().value<QDBusObjectPath>().path();
    QEventLoop loop{};
    portal_response_waiter waiter{};
    waiter.result = &result;
    waiter.loop = &loop;
    const auto connected = QDBusConnection::sessionBus().connect(
        QStringLiteral("org.freedesktop.portal.Desktop"),
        request_path,
        QStringLiteral("org.freedesktop.portal.Request"),
        QStringLiteral("Response"),
        &waiter,
        SLOT(handle_response(uint,QVariantMap)));
    if (!connected) {
        result.error_message = QStringLiteral("Failed to subscribe to background portal response");
        return result;
    }

    loop.exec();
    if (!result.completed) {
        result.error_message = QStringLiteral("Background portal request did not complete");
        return result;
    }

    if (enabled && !result.autostart_enabled) {
        result.error_message = QStringLiteral("Automatic start was not enabled");
    } else if (!enabled && result.autostart_enabled) {
        result.error_message = QStringLiteral("Automatic start is still enabled");
    }

    return result;
}
#endif

#if defined(Q_OS_LINUX)
file_chooser_portal_result select_files_with_portal()
{
    file_chooser_portal_result result{};
    QDBusInterface file_chooser_portal{
        QStringLiteral("org.freedesktop.portal.Desktop"),
        QStringLiteral("/org/freedesktop/portal/desktop"),
        QStringLiteral("org.freedesktop.portal.FileChooser"),
        QDBusConnection::sessionBus()};
    if (!file_chooser_portal.isValid()) {
        return result;
    }

    QVariantMap options{};
    options.insert(
        QStringLiteral("handle_token"),
        QStringLiteral("shared_%1").arg(QString::number(QRandomGenerator::global()->generate64(), 16)));
    options.insert(QStringLiteral("multiple"), true);

    const auto request_message = file_chooser_portal.call(
        QStringLiteral("OpenFile"),
        QStringLiteral(""),
        QStringLiteral("Select Files to Send"),
        options);
    if (request_message.type() == QDBusMessage::ErrorMessage) {
        result.error_message = request_message.errorMessage();
        return result;
    }

    if (request_message.arguments().isEmpty()
        || !request_message.arguments().constFirst().canConvert<QDBusObjectPath>()) {
        result.error_message = QStringLiteral("File chooser portal returned an invalid request handle");
        return result;
    }

    const auto request_path = request_message.arguments().constFirst().value<QDBusObjectPath>().path();
    QEventLoop loop{};
    file_chooser_portal_waiter waiter{};
    waiter.result = &result;
    waiter.loop = &loop;
    const auto connected = QDBusConnection::sessionBus().connect(
        QStringLiteral("org.freedesktop.portal.Desktop"),
        request_path,
        QStringLiteral("org.freedesktop.portal.Request"),
        QStringLiteral("Response"),
        &waiter,
        SLOT(handle_response(uint,QVariantMap)));
    if (!connected) {
        result.error_message = QStringLiteral("Failed to subscribe to file chooser portal response");
        return result;
    }

    loop.exec();
    if (!result.requested) {
        result.error_message = QStringLiteral("File chooser portal request did not complete");
    }
    return result;
}

#endif

#if defined(Q_OS_MACOS)
QString local_autostart_entry_path()
{
    return QDir{QDir::homePath()}.filePath(
        QStringLiteral("Library/LaunchAgents/eu.lastviking.shared.plist"));
}

bool set_local_autostart_enabled(bool enabled, QString &error_message)
{
    const auto path = local_autostart_entry_path();
    if (!enabled) {
        if (!QFileInfo::exists(path) || QFile::remove(path)) {
            return true;
        }
        error_message = QStringLiteral("Failed to remove login startup registration: %1").arg(path);
        return false;
    }

    if (!QDir{}.mkpath(QFileInfo{path}.absolutePath())) {
        error_message = QStringLiteral("Failed to create LaunchAgents directory");
        return false;
    }
    QSaveFile file{path};
    if (!file.open(QIODevice::WriteOnly)) {
        error_message = file.errorString();
        return false;
    }
    QXmlStreamWriter xml{&file};
    xml.setAutoFormatting(true);
    xml.writeStartDocument();
    xml.writeDTD(QStringLiteral("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"));
    xml.writeStartElement(QStringLiteral("plist"));
    xml.writeAttribute(QStringLiteral("version"), QStringLiteral("1.0"));
    xml.writeStartElement(QStringLiteral("dict"));
    xml.writeTextElement(QStringLiteral("key"), QStringLiteral("Label"));
    xml.writeTextElement(QStringLiteral("string"), QStringLiteral("eu.lastviking.shared"));
    xml.writeTextElement(QStringLiteral("key"), QStringLiteral("ProgramArguments"));
    xml.writeStartElement(QStringLiteral("array"));
    xml.writeTextElement(QStringLiteral("string"), QCoreApplication::applicationFilePath());
    xml.writeTextElement(QStringLiteral("string"), QStringLiteral("--autostart"));
    xml.writeEndElement();
    xml.writeTextElement(QStringLiteral("key"), QStringLiteral("RunAtLoad"));
    xml.writeEmptyElement(QStringLiteral("true"));
    xml.writeTextElement(QStringLiteral("key"), QStringLiteral("LimitLoadToSessionType"));
    xml.writeTextElement(QStringLiteral("string"), QStringLiteral("Aqua"));
    xml.writeEndElement();
    xml.writeEndElement();
    xml.writeEndDocument();
    if (xml.hasError() || !file.commit()) {
        error_message = QStringLiteral("Failed to write login startup registration: %1").arg(path);
        return false;
    }
    return true;
}
#endif

}

bool autostart_registered()
{
#if SHARED_FLATPAK_BUILD
    return true; // The portal owns the registration; use the saved preference.
#elif defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    return QFileInfo::exists(local_autostart_entry_path());
#else
    return false;
#endif
}

bool set_autostart_enabled(bool enabled, QString &error_message)
{
    error_message.clear();
#if SHARED_FLATPAK_BUILD
    error_message = request_flatpak_background_autostart(enabled).error_message;
    return error_message.isEmpty();
#elif defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    return set_local_autostart_enabled(enabled, error_message);
#else
    Q_UNUSED(enabled);
    error_message = QStringLiteral("Automatic start is not supported on this platform yet");
    return false;
#endif
}

QStringList select_files(const QString &initial_directory, QString &error_message)
{
    error_message.clear();
#if defined(Q_OS_LINUX)
    const auto result = select_files_with_portal();
    if (result.requested) {
        error_message = result.error_message;
        return result.accepted ? result.uris : QStringList{};
    }
#endif
    const auto selected = QFileDialog::getOpenFileUrls(
        nullptr, QStringLiteral("Select Files to Send"),
        QUrl::fromLocalFile(initial_directory));
    QStringList urls{};
    for (const auto &url : selected) {
        urls.append(url.toString());
    }
    return urls;
}

}

#if defined(Q_OS_LINUX)
#include "desktop_integration.moc"
#endif
