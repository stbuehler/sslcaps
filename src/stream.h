#ifndef SSLCAPS_STREAM_H
#define SSLCAPS_STREAM_H

#include <QObject>
#include <QByteArray>
#include <QList>

namespace SSLCaps {

	class ByteStream : QObject {
		Q_OBJECT
	public:
		ByteStream() : m_length(0), m_eof(false) { }

		void push(const QByteArray &data);
		void push_eof();

		bool eof() { return m_eof; }
		QByteArray peek(int amount);
		QByteArray pop(int amount);

	signals:
		void newData(int amount); /* amount == 0: end of stream */

	private:
		int m_length;
		bool m_eof;
		QList<QByteArray> m_buffers;
	};


}

#endif // SSLCAPS_STREAM_H
