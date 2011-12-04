#ifndef SSLCAPS_TLS_RECORD_H
#define SSLCAPS_TLS_RECORD_H

#include "tls_record_enums.h"

#include <QtGlobal>
#include <QByteArray>
#include <QMetaType>
#include <QVector>

namespace SSLCaps {
	namespace TLS {
		class ProtocolVersion {
		public:
			ProtocolVersion() : m_valid(false), m_major(0), m_minor(0) { }
			ProtocolVersion(quint8 major, quint8 minor) : m_valid(true), m_major(major), m_minor(minor) { }

			bool valid() const { return m_valid; }

			quint8 major() const { return m_major; }
			quint8 minor() const { return m_minor; }
			void set(quint8 major, quint8 minor) { m_valid = true; m_major = major; m_minor = minor; }
			void clear() { m_valid = false; m_major = m_minor = 0; }

			static const ProtocolVersion SSL3_0, TLS1_0, TLS1_1, TLS1_2;

		private:
			bool m_valid;
			quint8 m_major, m_minor;
		};

		class CipherSuite {
		public:
			struct raw {
				quint8 suite[2];
				quint8 first() const { return suite[0]; }
				quint8 second() const { return suite[1]; }
				raw() { suite[0] = suite[1] = 0; }
				raw(quint8 first, quint8 second) { suite[0] = first; suite[1] = second; }
			};

			CipherSuite() : m_valid(0) { }
			CipherSuite(quint8 first, quint8 second) : m_valid(true), m_raw(first, second) { }

			bool valid() const { return m_valid; }
			raw value() const { return m_raw; }
			quint8 first() const { return m_raw.suite[0]; }
			quint8 second() const { return m_raw.suite[1]; }
			void set(raw r) { m_valid = true; m_raw = r; }
			void set(quint8 first, quint8 second) { m_valid = true; m_raw.suite[0] = first; m_raw.suite[1] = second; }
			void clear() { m_valid = false; m_raw.suite[0] = m_raw.suite[1] = 0; }

		private:
			bool m_valid;
			raw m_raw;
		};

		class Alert {
		public:
			Alert() { }
			Alert(AlertLevel level, AlertDescription description) : level(level), description(description) { }

			AlertLevel level;
			AlertDescription description;

			QByteArray serialize() const;
		};

		class Handshake_Generic {
		public:
			virtual ~Handshake_Generic() { }
			virtual HandshakeType type() const = 0;
			virtual QByteArray serialize() const = 0;
		};

		class Handshake_Hello_Request : public Handshake_Generic {
		public:
			virtual ~Handshake_Hello_Request();
			HandshakeType type() const;
			QByteArray serialize() const;
		};

		class Handshake_Client_Hello : public Handshake_Generic {
		public:
			virtual ~Handshake_Client_Hello();
			HandshakeType type() const;
			QByteArray serialize() const;

			struct Random {
				quint32 gmt_unix_time;
				quint8 random_bytes[28];
			};

			ProtocolVersion client_version;
			Random random;
			QByteArray session_id;
			QVector<CipherSuite> cipher_suites;
			QVector<CompressionMethod> compression_methods;
			// TODO: Extensions
		};

		class Handshake_Server_Hello : public Handshake_Generic {
		public:
			virtual ~Handshake_Server_Hello();
			HandshakeType type() const;
			QByteArray serialize() const;
			// TODO
		};

		class Handshake_Certificate : public Handshake_Generic {
		public:
			virtual ~Handshake_Certificate();
			HandshakeType type() const;
			QByteArray serialize() const;
			// TODO
		};

		class Handshake_Server_Key_Exchange : public Handshake_Generic {
		public:
			virtual ~Handshake_Server_Key_Exchange();
			HandshakeType type() const;
			QByteArray serialize() const;
			// TODO
		};

		class Handshake_Certificate_Request : public Handshake_Generic {
		public:
			virtual ~Handshake_Certificate_Request();
			HandshakeType type() const;
			QByteArray serialize() const;
			// TODO
		};

		class Handshake_Server_Hello_Done : public Handshake_Generic {
		public:
			virtual ~Handshake_Server_Hello_Done();
			HandshakeType type() const;
			QByteArray serialize() const;
			// TODO
		};

		class Handshake_Certificate_Verify : public Handshake_Generic {
		public:
			virtual ~Handshake_Certificate_Verify();
			HandshakeType type() const;
			QByteArray serialize() const;
			// TODO
		};

		class Handshake_Client_Key_Exchange : public Handshake_Generic {
		public:
			virtual ~Handshake_Client_Key_Exchange();
			HandshakeType type() const;
			QByteArray serialize() const;
			// TODO
		};

		class Handshake_Finished : public Handshake_Generic {
		public:
			virtual ~Handshake_Finished();
			HandshakeType type() const;
			QByteArray serialize() const;
			// TODO
		};

		class Handshake {
		public:
			Handshake() { }

			HandshakeType msg_type;
			QByteArray body;

			QByteArray serialize() const;
		};

		class Record {
		public:
			static const int MAX_FRAGMENT_SIZE = (1 << 14);

			ContentType type;
			ProtocolVersion version;
			QByteArray fragment;

			QByteArray serialize() const;
		};
	}
}

Q_DECLARE_METATYPE(SSLCaps::TLS::Alert)
Q_DECLARE_METATYPE(SSLCaps::TLS::Record)

#endif // SSLCAPS_TLS_RECORD_H
