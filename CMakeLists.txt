cmake_minimum_required(VERSION 3.10)
project(GCrypto)

set(CMAKE_CXX_STANDARD 11)
include_directories(${PROJECT_SOURCE_DIR})


# Add Qt
find_package(Qt5Core REQUIRED)

# Add OpenSSL
set(SSL_DIR /usr/local/ssl)
include_directories(${SSL_DIR}/include)
find_library(OPENSSL_LIBS
        NAMES lcrypto lssl
        HINTS ${SSL_DIR}/lib)

# GError
set (GErrorPath Core/GError)
set (GErrorFiles ${GErrorPath}/errors.cpp ${GErrorPath}/errors.h)

# GCipher
set (GCipherPath GCipher)

set (GCipherBaseFiles ${GCipherPath}/base_cipher.cpp ${GCipherPath}/base_cipher.h)

set (GSymmetricPath ${GCipherPath}/Symmetric)
set (GSymmetricFiles ${GSymmetricPath}/symmetric_cipher.cpp ${GSymmetricPath}/symmetric_cipher.h)

set (GBlockPath ${GSymmetricPath}/Block)
set (GBlockFiles ${GBlockPath}/block_cipher.cpp ${GBlockPath}/block_cipher.h)

set (CiphersPath ${GBlockPath}/Ciphers)
set (CiphersFiles ${CiphersPath}/aes.cpp ${CiphersPath}/aes.h)

set (ModesPath ${GBlockPath}/Modes)
set (ModesBaseFiles ${ModesPath}/cipher_mode.cpp ${ModesPath}/cipher_mode.cpp)
set (ModesFiles ${ModesBaseFiles} ${ModesPath}/ecb.h ${ModesPath}/ecb.cpp ${ModesPath}/cbc.h ${ModesPath}/cbc.cpp)

set (GCipherFiles ${GCipherBaseFiles} ${GSymmetricFiles} ${GBlockFiles} ${CiphersFiles} ${ModesFiles} ${} ${} ${})

# Source
set(SourceFiles main.cpp )
add_executable(${PROJECT_NAME} ${SourceFiles} ${GCipherFiles} ${GErrorFiles} ${} ${})
# ---

# Linking
target_link_libraries(${PROJECT_NAME} Qt5::Core)
target_link_libraries(${PROJECT_NAME} ${SSL_DIR})