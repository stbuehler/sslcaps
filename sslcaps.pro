# #####################################################################
# Automatically generated by qmake (2.01a) Sun Dec 4 13:12:39 2011
# #####################################################################
TEMPLATE = app
TARGET = 
DEPENDPATH += . \
    src
INCLUDEPATH += .

QT -= gui
QT += network

unix {
	CONFIG += link_pkgconfig
	PKGCONFIG += gnutls
}

# Input
SOURCES += src/sslcaps.cpp \
    src/tls_record.cpp \
    src/stream.cpp \
    src/tls_simple_stream.cpp
HEADERS += \
    src/tls_record.h \
    src/tls_record_enums.h \
    src/stream.h \
    src/tls_simple_stream.h
