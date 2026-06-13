# curl-gmssl

本仓库基于 curl 8.20.0，增加了 GmSSL SSL/TLS 后端。该后端通过 curl 的 vtls
接口调用 GmSSL TLS API，可用于测试 TLS 1.2、TLS 1.3 以及国密相关 cipher suite。

## 编译 GmSSL

先准备一个启用了 TLS、AES、SHA2 和 P-256 的 GmSSL：

```sh
git clone https://github.com/GmSSL/GmSSL.git
cd GmSSL

cmake -S . -B build-tls \
  -DENABLE_TLS=ON \
  -DENABLE_AES=ON \
  -DENABLE_SHA2=ON \
  -DENABLE_SHA1=ON \
  -DENABLE_SECP256R1=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build-tls
```

编译完成后，GmSSL 库通常位于 `build-tls/bin/`，头文件位于 `include/`。

## 编译 curl-gmssl

在本仓库根目录中配置并编译：

```sh
cmake -S . -B build-gmssl \
  -DCURL_USE_GMSSL=ON \
  -DCURL_USE_OPENSSL=OFF \
  -DCURL_USE_MBEDTLS=OFF \
  -DGMSSL_LIBRARY=/path/to/GmSSL/build-tls/bin/libgmssl.dylib \
  -DGMSSL_INCLUDE_DIR=/path/to/GmSSL/include \
  -DCURL_USE_LIBPSL=OFF \
  -DCURL_ZSTD=OFF \
  -DCURL_USE_LIBSSH2=OFF \
  -DCURL_DISABLE_LDAP=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_CURL_EXE=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build-gmssl
```

Linux 上的 `GMSSL_LIBRARY` 通常是 `libgmssl.so`，macOS 上通常是
`libgmssl.dylib`。

## 检查是否使用 GmSSL 后端

```sh
./build-gmssl/src/curl -V
```

输出中应包含类似内容：

```text
libcurl/8.20.0 GmSSL/GmSSL 3.1.3 Dev
```

其中 `GmSSL/GmSSL 3.1.3 Dev` 表示当前 curl 使用的是 GmSSL TLS 后端以及对应
GmSSL 版本。

也可以在连接时使用 `-v` 查看握手结果：

```sh
./build-gmssl/src/curl -v https://127.0.0.1:19454/
```

成功时会看到类似：

```text
GmSSL: TLSv1.3 Handshake complete, cipher is TLS_AES_128_GCM_SHA256
```

## 指定协议版本

使用 TLS 1.3：

```sh
./build-gmssl/src/curl \
  --tlsv1.3 \
  --cacert rootcacert.pem \
  https://127.0.0.1:19454/
```

使用 TLS 1.2：

```sh
./build-gmssl/src/curl \
  --tlsv1.2 \
  --cacert rootcacert.pem \
  https://127.0.0.1:19443/
```

## 指定密码套件

TLS 1.3 使用 `--tls13-ciphers`：

```sh
./build-gmssl/src/curl \
  --tlsv1.3 \
  --tls13-ciphers TLS_AES_128_GCM_SHA256 \
  --cacert rootcacert.pem \
  https://127.0.0.1:19454/
```

TLS 1.2 使用 `--ciphers`：

```sh
./build-gmssl/src/curl \
  --tlsv1.2 \
  --ciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 \
  --cacert rootcacert.pem \
  https://127.0.0.1:19443/
```

当前 GmSSL 后端支持的主要 cipher suite 包括：

```text
TLS_SM4_GCM_SM3
TLS_AES_128_GCM_SHA256
TLS_ECDHE_SM4_GCM_SM3
TLS_ECDHE_SM4_CBC_SM3
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
```

当前不支持 AES-256、CCM 和 ChaCha20-Poly1305 cipher suite。如果显式指定的
cipher suite 全部不被 GmSSL 后端支持，curl 会返回 cipher 配置错误，而不会回退到
默认 cipher suite。

