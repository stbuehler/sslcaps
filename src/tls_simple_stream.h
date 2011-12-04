#ifndef SSLCAPS_TLS_SIMPLE_STREAM_H
#define SSLCAPS_TLS_SIMPLE_STREAM_H

#include "tls_record.h"

#include <QObject>
#include <QTcpSocket>

namespace SSLCaps {
	namespace TLS {
		class SimpleStream : public QObject {
			Q_OBJECT
		public:
			SimpleStream(QTcpSocket *socket, QObject *parent = 0);

			void send(const Record &record);
			void send(const Handshake &handshake);
			void send(const Handshake_Generic &handshake);

		signals:
			void recvRecord(Record record);

		private:
			QTcpSocket *m_socket;
		};

	}
}

#endif // SSLCAPS_TLS_SIMPLE_STREAM_H
