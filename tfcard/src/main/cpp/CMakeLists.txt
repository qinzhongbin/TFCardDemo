# For more information about using CMake with Android Studio, read the documentation: https://d.android.com/studio/projects/add-native-code.html
project("TFcard")
cmake_minimum_required(VERSION 3.10.2)

# 定义变量（依赖库目录）
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs)

# 依赖库
link_directories(${LIB_DIR}/${ANDROID_ABI})
# 头文件
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
# 源文件
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SRC_DIR)

# 编译库
add_library(QTF SHARED ${SRC_DIR})

# 链接
target_link_libraries(QTF
        skf
        ssl
        curl
        crypto
        SdCryptoStor
        qtf3302
        log)
