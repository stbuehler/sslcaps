#ifndef SSLCAPS_TLS_RECORD_ENUMS_H
#define SSLCAPS_TLS_RECORD_ENUMS_H

#include <QtGlobal>
#include <QMetaType>

namespace SSLCaps {
	namespace TLS {

		class ContentType {
		public:
			enum Enum {
				CHANGE_CIPHER_SPEC = 20,
				ALERT = 21,
				HANDSHAKE = 22,
				APPLICATION_DATA = 23
			};
		public:
			ContentType() : m_value(0) { }
			ContentType(Enum value) : m_value(value) { }
			ContentType(quint8 value) : m_value(value) { }

			Enum value() const { return (Enum) m_value; }
			operator Enum() const { return (Enum) m_value; }
			void setValue(Enum value) { m_value = value; }

		private:
			quint8 m_value;
		};

		class AlertLevel {
		public:
			enum Enum {
				WARNING = 1,
				FATAL = 2
			};
		public:
			AlertLevel() : m_value(0) { }
			AlertLevel(Enum value) : m_value(value) { }
			AlertLevel(quint8 value) : m_value(value) { }

			Enum value() const { return (Enum) m_value; }
			operator Enum() const { return (Enum) m_value; }
			void setValue(Enum value) { m_value = value; }

		private:
			quint8 m_value;
		};

		class AlertDescription {
		public:
			enum Enum {
				CLOSE_NOTIFY = 0,
				UNEXPECTED_MESSAGE = 10,
				BAD_RECORD_MAC = 20,
				DECRYPTION_FAILED_RESERVED = 21,
				RECORD_OVERFLOW = 22,
				DECOMPRESSION_FAILURE = 30,
				HANDSHAKE_FAILURE = 40,
				NO_CERTIFICATE_RESERVED = 41,
				BAD_CERTIFICATE = 42,
				UNSUPPORTED_CERTIFICATE = 43,
				CERTIFICATE_REVOKED = 44,
				CERTIFICATE_EXPIRED = 45,
				CERTIFICATE_UNKNOWN = 46,
				ILLEGAL_PARAMETER = 47,
				UNKNOWN_CA = 48,
				ACCESS_DENIED = 49,
				DECODE_ERROR = 50,
				DECRYPT_ERROR = 51,
				EXPORT_RESTRICTION_RESERVED = 60,
				PROTOCOL_VERSION = 70,
				INSUFFICIENT_SECURITY = 71,
				INTERNAL_ERROR = 80,
				USER_CANCELED = 90,
				NO_RENEGOTIATION = 100,
				UNSUPPORTED_EXTENSION = 110,
				CERTIFICATE_UNOBTAINABLE = 111,
				UNRECOGNIZED_NAME = 112,
				BAD_CERTIFICATE_STATUS_RESPONSE = 113,
				BAD_CERTIFICATE_HASH_VALUE = 114,
				UNKNOWN_PSK_IDENTITY = 115
			};
		public:
			AlertDescription() : m_value(255) { }
			AlertDescription(Enum value) : m_value(value) { }
			AlertDescription(quint8 value) : m_value(value) { }

			Enum value() const { return (Enum) m_value; }
			operator Enum() const { return (Enum) m_value; }
			void setValue(Enum value) { m_value = value; }

		private:
			quint8 m_value;
		};

		class CompressionMethod {
		public:
			enum Enum {
				COMP_NULL = 0,
				DEFLATE = 1,
				LZS = 64
			};
		public:
			CompressionMethod() : m_value(0) { }
			CompressionMethod(Enum value) : m_value(value) { }
			CompressionMethod(quint8 value) : m_value(value) { }

			Enum value() const { return (Enum) m_value; }
			operator Enum() const { return (Enum) m_value; }
			void setValue(Enum value) { m_value = value; }

		private:
			quint8 m_value;
		};

		class HandshakeType {
		public:
			enum Enum {
				HELLO_REQUEST = 0,
				CLIENT_HELLO = 1,
				SERVER_HELLO = 2,
				HELLO_VERIFY_REQUEST = 3,
				NEW_SESSION_TICKET = 4,
				CERTIFICATE = 11,
				SERVER_KEY_EXCHANGE = 12,
				CERTIFICATE_REQUEST = 13,
				SERVER_HELLO_DONE = 14,
				CERTIFICATE_VERIFY = 15,
				CLIENT_KEY_EXCHANGE = 16,
				FINISHED = 20,
				CERTIFICATE_URL = 21,
				CERTIFICATE_STATUS = 22,
				SUPPLEMENTAL_DATA = 23
			};
		public:
			HandshakeType() : m_value(255) { }
			HandshakeType(Enum value) : m_value(value) { }
			HandshakeType(quint8 value) : m_value(value) { }

			Enum value() const { return (Enum) m_value; }
			operator Enum() const { return (Enum) m_value; }
			void setValue(Enum value) { m_value = value; }

		private:
			quint8 m_value;
		};

		class ECNamedCurve {
		public:
			enum Enum {
				SECT163K1 = 1,
				SECT163R1 = 2,
				SECT163R2 = 3,
				SECT193R1 = 4,
				SECT193R2 = 5,
				SECT233K1 = 6,
				SECT233R1 = 7,
				SECT239K1 = 8,
				SECT283K1 = 9,
				SECT283R1 = 10,
				SECT409K1 = 11,
				SECT409R1 = 12,
				SECT571K1 = 13,
				SECT571R1 = 14,
				SECP160K1 = 15,
				SECP160R1 = 16,
				SECP160R2 = 17,
				SECP192K1 = 18,
				SECP192R1 = 19,
				SECP224K1 = 20,
				SECP224R1 = 21,
				SECP256K1 = 22,
				SECP256R1 = 23,
				SECP384R1 = 24,
				SECP512R1 = 25,
				ARBITRARY_EXPLICIT_PRIME_CURVES = 65281,
				ARBITRARY_EXPLICIT_CHAR2_CURVES = 65282
			};
		public:
			ECNamedCurve() : m_value(0) { }
			ECNamedCurve(Enum value) : m_value(value) { }
			ECNamedCurve(quint16 value) : m_value(value) { }

			Enum value() const { return (Enum) m_value; }
			operator Enum() const { return (Enum) m_value; }
			void setValue(Enum value) { m_value = value; }

		private:
			quint16 m_value;
		};

		class ECPointFormat {
		public:
			enum Enum {
				UNCOMPRESSED = 0,
				ANSIX962_COMPRESSED_PRIME = 1,
				ANSIX962_COMPRESSED_CHAR2 = 2
			};
		public:
			ECPointFormat() : m_value(0) { }
			ECPointFormat(Enum value) : m_value(value) { }
			ECPointFormat(quint8 value) : m_value(value) { }

			Enum value() const { return (Enum) m_value; }
			operator Enum() const { return (Enum) m_value; }
			void setValue(Enum value) { m_value = value; }

		private:
			quint8 m_value;
		};

		class ECCurveType {
		public:
			enum Enum {
				EXPLICIT_PRIME = 1,
				EXPLICIT_CHAR2 = 2,
				NAMED_CURVE = 3
			};
		public:
			ECCurveType() : m_value(0) { }
			ECCurveType(Enum value) : m_value(value) { }
			ECCurveType(quint8 value) : m_value(value) { }

			Enum value() const { return (Enum) m_value; }
			operator Enum() const { return (Enum) m_value; }
			void setValue(Enum value) { m_value = value; }

		private:
			quint8 m_value;
		};

	}
}

Q_DECLARE_METATYPE(SSLCaps::TLS::ContentType)
Q_DECLARE_METATYPE(SSLCaps::TLS::AlertLevel)
Q_DECLARE_METATYPE(SSLCaps::TLS::AlertDescription)
Q_DECLARE_METATYPE(SSLCaps::TLS::HandshakeType)
Q_DECLARE_METATYPE(SSLCaps::TLS::ECNamedCurve)
Q_DECLARE_METATYPE(SSLCaps::TLS::ECPointFormat)
Q_DECLARE_METATYPE(SSLCaps::TLS::ECCurveType)


#endif // SSLCAPS_TLS_RECORD_ENUMS_H
