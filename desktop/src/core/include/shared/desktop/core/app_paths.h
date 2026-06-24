#pragma once

#include <QtCore/QString>

namespace shared::desktop::core {

class app_paths {
public:
    [[nodiscard]] QString config_dir() const;
    [[nodiscard]] QString data_dir() const;
    [[nodiscard]] QString cache_dir() const;
    [[nodiscard]] QString runtime_dir() const;
    [[nodiscard]] QString socket_path() const;
    [[nodiscard]] QString credentials_dir() const;
    [[nodiscard]] QString trusted_agent_dir() const;
    [[nodiscard]] QString pending_enrollments_dir() const;
    [[nodiscard]] QString peer_list_path() const;
    [[nodiscard]] QString ca_key_path() const;
    [[nodiscard]] QString ca_certificate_path() const;
    [[nodiscard]] QString ca_serial_path() const;
    [[nodiscard]] QString server_key_path() const;
    [[nodiscard]] QString server_certificate_path() const;
    [[nodiscard]] QString server_certificate_der_path() const;
    [[nodiscard]] QString pinned_trusted_agent_ca_certificate_path() const;
    [[nodiscard]] QString peer_key_path() const;
    [[nodiscard]] QString peer_certificate_path() const;
    [[nodiscard]] QString peer_certificate_der_path() const;
    [[nodiscard]] QString peer_csr_der_path() const;
    [[nodiscard]] QString x25519_private_key_path() const;

    [[nodiscard]] bool ensure_directories() const;
};

}
