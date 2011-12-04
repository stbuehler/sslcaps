#include "tls_record.h"
namespace SSLCaps {
	namespace TLS {

		const ProtocolVersion ProtocolVersion::SSL3_0(3, 0);
		const ProtocolVersion ProtocolVersion::TLS1_0(3, 1);
		const ProtocolVersion ProtocolVersion::TLS1_1(3, 2);
		const ProtocolVersion ProtocolVersion::TLS1_2(3, 3);

		Handshake_Hello_Request::~Handshake_Hello_Request() {
		}
		HandshakeType Handshake_Hello_Request::type() const {
			return HandshakeType::HELLO_REQUEST;
		}
		QByteArray Handshake_Hello_Request::serialize() const {
			return QByteArray();
		}

		Handshake_Client_Hello::~Handshake_Client_Hello() {
		}
		HandshakeType Handshake_Client_Hello::type() const {
			return HandshakeType::CLIENT_HELLO;
		}
		QByteArray Handshake_Client_Hello::serialize() const {
			return QByteArray();
		}

		Handshake_Server_Hello::~Handshake_Server_Hello() {
		}
		HandshakeType Handshake_Server_Hello::type() const {
			return HandshakeType::SERVER_HELLO;
		}
		QByteArray Handshake_Server_Hello::serialize() const {
			return QByteArray();
		}

		Handshake_Certificate::~Handshake_Certificate() {
		}
		HandshakeType Handshake_Certificate::type() const {
			return HandshakeType::CERTIFICATE;
		}
		QByteArray Handshake_Certificate::serialize() const {
			return QByteArray();
		}

		Handshake_Server_Key_Exchange::~Handshake_Server_Key_Exchange() {
		}
		HandshakeType Handshake_Server_Key_Exchange::type() const {
			return HandshakeType::SERVER_KEY_EXCHANGE;
		}
		QByteArray Handshake_Server_Key_Exchange::serialize() const {
			return QByteArray();
		}

		Handshake_Certificate_Request::~Handshake_Certificate_Request() {
		}
		HandshakeType Handshake_Certificate_Request::type() const {
			return HandshakeType::CERTIFICATE_REQUEST;
		}
		QByteArray Handshake_Certificate_Request::serialize() const {
			return QByteArray();
		}

		Handshake_Server_Hello_Done::~Handshake_Server_Hello_Done() {
		}
		HandshakeType Handshake_Server_Hello_Done::type() const {
			return HandshakeType::SERVER_HELLO_DONE;
		}
		QByteArray Handshake_Server_Hello_Done::serialize() const {
			return QByteArray();
		}

		Handshake_Certificate_Verify::~Handshake_Certificate_Verify() {
		}
		HandshakeType Handshake_Certificate_Verify::type() const {
			return HandshakeType::CERTIFICATE_VERIFY;
		}
		QByteArray Handshake_Certificate_Verify::serialize() const {
			return QByteArray();
		}

		Handshake_Client_Key_Exchange::~Handshake_Client_Key_Exchange() {
		}
		HandshakeType Handshake_Client_Key_Exchange::type() const {
			return HandshakeType::CLIENT_KEY_EXCHANGE;
		}
		QByteArray Handshake_Client_Key_Exchange::serialize() const {
			return QByteArray();
		}

		Handshake_Finished::~Handshake_Finished() {
		}
		HandshakeType Handshake_Finished::type() const {
			return HandshakeType::FINISHED;
		}
		QByteArray Handshake_Finished::serialize() const {
			return QByteArray();
		}

		QByteArray Alert::serialize() const {
			QByteArray data;
			data.reserve(2);
			data.append(level).append(description);
			return data;
		}

		QByteArray Handshake::serialize() const {
			if (body.length() >= (1 << 24)) qFatal("SSLCaps::TLS::Handshake::serialize: Handshake body too large");
			QByteArray data;
			data.reserve(4 + body.length());
			data.append(msg_type).append(body.length() >> 16).append(body.length() >> 8).append(body.length());
			data += body;
			return data;
		}

		QByteArray Record::serialize() const {
			/* TODO: implement fragmentation, split data if necessary */
			if (fragment.length() > MAX_FRAGMENT_SIZE) qFatal("SSLCaps::TLS::Record::serialize: Record fragment too large");
			QByteArray data;
			data.reserve(5 + fragment.length());
			data.append(type.value()).append(version.major()).append(version.minor()).append(fragment.length() >> 8).append(fragment.length());
			data += fragment;
			return data;
		}
	}
}
