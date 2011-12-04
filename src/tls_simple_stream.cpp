#include "tls_simple_stream.h"

namespace SSLCaps {
	namespace TLS {
		SimpleStream::SimpleStream(QTcpSocket *socket, QObject *parent)
			: QObject(parent), m_socket(socket) {
			m_socket->setParent(this);
		}

		void SimpleStream::send(const Record &record) {
			m_socket->write(record.serialize());
		}

		void SimpleStream::send(const Handshake &handshake) {
			Record r;
			r.version = ProtocolVersion::TLS1_0;
			r.type = ContentType::HANDSHAKE;
			r.fragment = handshake.serialize();
			send(r);
		}

		void SimpleStream::send(const Handshake_Generic &handshake) {
			Handshake h;
			h.msg_type = handshake.type();
			h.body = handshake.serialize();
			send(h);
		}
	}
}
