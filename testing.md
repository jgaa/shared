# Testing

Single-host manual test for one trusted agent and one joining client:

```sh
rm /tmp/shared*.log
# Terminal 1: trusted-agent daemon
export XDG_CONFIG_HOME=/tmp/shared-a-config
export XDG_DATA_HOME=/tmp/shared-a-data
export XDG_CACHE_HOME=/tmp/shared-a-cache
export XDG_RUNTIME_DIR=/tmp/shared-a-run
export SHARED_PEERSERVICE_IP=127.0.0.1
export SHARED_PEERSERVICE_PORT=47124
rm -rf "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR" /tmp/shared-a-daemon.log /tmp/shared-a-gui.log
mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR"
QT_QPA_PLATFORM=xcb /var/local/build/shared_desktop-Desktop-Debug/bin/shareddaemon \
  --log-to-console trace \
  --log-level trace \
  --log-file /tmp/shared-a-daemon.log &

# Terminal 2: trusted-agent GUI
export XDG_CONFIG_HOME=/tmp/shared-a-config
export XDG_DATA_HOME=/tmp/shared-a-data
export XDG_CACHE_HOME=/tmp/shared-a-cache
export XDG_RUNTIME_DIR=/tmp/shared-a-run
export SHARED_PEERSERVICE_IP=127.0.0.1
export SHARED_PEERSERVICE_PORT=47124
QT_QPA_PLATFORM=xcb /var/local/build/shared_desktop-Desktop-Debug/bin/sharedgui \
  --log-to-console trace \
  --log-level trace \
  --log-file /tmp/shared-a-gui.log &

# Terminal 3: joining-client daemon
export XDG_CONFIG_HOME=/tmp/shared-b-config
export XDG_DATA_HOME=/tmp/shared-b-data
export XDG_CACHE_HOME=/tmp/shared-b-cache
export XDG_RUNTIME_DIR=/tmp/shared-b-run
export SHARED_PEERSERVICE_IP=127.0.0.1
export SHARED_PEERSERVICE_PORT=47125
rm -rf "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR" /tmp/shared-b-daemon.log /tmp/shared-b-gui.log
mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR"
QT_QPA_PLATFORM=xcb /var/local/build/shared_desktop-Desktop-Debug/bin/shareddaemon \
  --log-to-console trace \
  --log-level trace \
  --log-file /tmp/shared-b-daemon.log &

# Terminal 4: joining-client GUI
export XDG_CONFIG_HOME=/tmp/shared-b-config
export XDG_DATA_HOME=/tmp/shared-b-data
export XDG_CACHE_HOME=/tmp/shared-b-cache
export XDG_RUNTIME_DIR=/tmp/shared-b-run
export SHARED_PEERSERVICE_IP=127.0.0.1
export SHARED_PEERSERVICE_PORT=47125
QT_QPA_PLATFORM=xcb /var/local/build/shared_desktop-Desktop-Debug/bin/sharedgui \
  --log-to-console trace \
  --log-level trace \
  --log-file /tmp/shared-b-gui.log &

```

Trusted agent setup:

1. Start Terminal 1 and Terminal 2.
2. In the GUI, open `Initialize Local`.
3. Enter a device name.
4. Keep `TCP Port` at `47123` unless you need a different port.
5. Press `Initialize Trusted Agent`.
6. Confirm the GUI leaves first-run setup and shows `Enrollment fingerprint`.
7. Confirm Terminal 1 logs `trusted-agent enrollment server listening on port 47123`.
8. Confirm Terminal 1 also logs the peer service listening on `127.0.0.1 47124`.

Joining client:

1. Leave the trusted agent running in Terminal 1 and Terminal 2.
2. Start Terminal 3 and Terminal 4 for the joining client.
3. In the trusted-agent GUI, copy the `Enrollment fingerprint`.
   Format: `hhhh-hhhh`.
4. In the joining client GUI, stay on `Join Existing`.
5. Enter a device name.
6. Enter the trusted agent host or IP.
   For same-machine testing, use `127.0.0.1`.
7. Set `TCP Port` to the trusted agent enrollment port.
   Default: `47123`.
8. Paste the trusted agent `Enrollment fingerprint`.
   The client should accept either `hhhh-hhhh` or `hhhhhhhh`.
9. Press `Start Enrollment`.
10. In the trusted-agent GUI, look for a new entry under `Pending Enrollments`.
11. Verify the `Verification code` shown on the trusted-agent GUI matches the code shown on the joining client device.
12. Press `Approve` on the trusted-agent GUI.
13. Confirm the joining client GUI leaves first-run setup and shows `Joined trusted agent 127.0.0.1:47123` or the host and port you used.
14. Open `File/Settings` in the joining client GUI and confirm `Trusted Agent -> Peer TCP Port` is `47124`.
15. Confirm the joining-client daemon logs the peer service listening on `127.0.0.1 47125`.
16. Confirm the log files capture the activity without unexpected TLS or OpenSSL errors:
    `/tmp/shared-a-daemon.log`
    `/tmp/shared-a-gui.log`
    `/tmp/shared-b-daemon.log`
    `/tmp/shared-b-gui.log`

Failure checks:

1. If the join button appears to do nothing, look at the `Last error` panel near the top of the GUI.
2. If no port is listening, confirm `/tmp/shared-a-daemon.log` contains `trusted-agent enrollment server listening on port ...`.
3. If Qt reports Wayland plugin failures, rerun with `QT_QPA_PLATFORM=xcb`.
4. If `XDG_RUNTIME_DIR` permission warnings appear, run `chmod 700` on the runtime directory before starting the program.
