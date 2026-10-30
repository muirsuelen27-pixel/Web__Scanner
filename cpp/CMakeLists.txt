cmake_minimum_required(VERSION 3.24)

project(WebScannerDesktop VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 6.6 REQUIRED COMPONENTS Core Gui Widgets Svg LinguistTools)

qt_add_executable(web_scanner
    src/main.cpp
    src/core/BackendClient.cpp
    src/core/LanguageManager.cpp
    src/core/ThemeManager.cpp
    src/models/ScannerModels.cpp
    src/widgets/MetricCard.cpp
    src/widgets/AnimatedButton.cpp
    src/widgets/Sidebar.cpp
    src/widgets/Toast.cpp
    src/ui/Pages.cpp
    src/ui/MainWindow.cpp
    include/core/BackendClient.h
    include/core/LanguageManager.h
    include/core/ThemeManager.h
    include/models/ScannerModels.h
    include/widgets/MetricCard.h
    include/widgets/AnimatedButton.h
    include/widgets/Sidebar.h
    include/widgets/Toast.h
    include/ui/Pages.h
    include/ui/MainWindow.h
    resources/webscanner.qrc
)

target_include_directories(web_scanner PRIVATE include "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(web_scanner PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Svg)
target_compile_definitions(web_scanner PRIVATE
    QT_NO_CAST_FROM_ASCII
    QT_NO_CAST_TO_ASCII
)

configure_file(cmake/BuildConfig.h.in generated/BuildConfig.h @ONLY)

set(TRANSLATION_FILES
    i18n/webscanner_en.ts
    i18n/webscanner_es.ts
    i18n/webscanner_fr.ts
)
qt_add_translations(web_scanner
    TS_FILES ${TRANSLATION_FILES}
    RESOURCE_PREFIX "/i18n"
)
add_custom_target(update-translations
    COMMAND $<TARGET_FILE:Qt6::lupdate>
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        -ts ${TRANSLATION_FILES}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Updating Qt Linguist source catalogs"
)

include(CTest)
option(WEB_SCANNER_BUILD_TESTS "Build Qt model and UI tests" OFF)
if(BUILD_TESTING AND WEB_SCANNER_BUILD_TESTS)
    find_package(Qt6 6.6 REQUIRED COMPONENTS Test)
    qt_add_executable(web_scanner_tests
        tests/ScannerModelsTest.cpp
        src/models/ScannerModels.cpp
        include/models/ScannerModels.h
    )
    target_include_directories(web_scanner_tests PRIVATE include)
    target_link_libraries(web_scanner_tests PRIVATE Qt6::Core Qt6::Test)
    add_test(NAME scanner-models COMMAND web_scanner_tests)
endif()

install(TARGETS web_scanner RUNTIME DESTINATION bin)
