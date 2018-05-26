cmake_minimum_required(VERSION 3.10)
project(GCrypto)

set(CMAKE_CXX_STANDARD 11)

# Add Qt
find_package(Qt5Core REQUIRED)

# Add OpenSSL
set(SSL_DIR /usr/local/ssl)
include_directories(${SSL_DIR}/include)
find_library(OPENSSL_LIBS
        NAMES lcrypto lssl
        HINTS ${SSL_DIR}/lib)

# Compile
set(SOURCE_FILES main.cpp GCipher/base_cipher.cpp GCipher/base_cipher.h GCipher/symmetric_cipher.cpp GCipher/symmetric_cipher.h GCipher/block_cipher.cpp GCipher/block_cipher.h GCipher/g_aes.cpp GCipher/g_aes.h GCipher/cipher_mode.cpp GCipher/cipher_mode.h GCipher/ecb_mode.cpp GCipher/ecb_mode.h)
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

# Linking
target_link_libraries(${PROJECT_NAME} Qt5::Core)
target_link_libraries(${PROJECT_NAME} ${SSL_DIR})