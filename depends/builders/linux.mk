build_linux_SHA256SUM = sha256sum
build_linux_DOWNLOAD = curl --silent --show-error --location --fail --connect-timeout $(DOWNLOAD_CONNECT_TIMEOUT) --retry $(DOWNLOAD_RETRIES) -o
