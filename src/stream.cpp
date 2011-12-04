#include "stream.h"

#include <limits>

namespace SSLCaps {
	void ByteStream::push(const QByteArray &data) {
		if (0 == data.length()) return;

		if (std::numeric_limits<int>::max() - m_length < data.length()) {
			qFatal("SSLCaps::ByteStream::push: buffer overflow");
		}
		m_length += data.length();
		m_buffers.push_back(data);
	}

	void ByteStream::push_eof() {
		if (m_eof) return;

		m_eof = true;
		emit newData(0);
	}

	QByteArray ByteStream::peek(int amount) {
		if (amount <= 0) qFatal("SSLCaps::ByteStream::peek called with amount < 0");
		if (m_buffers.empty()) return QByteArray();

		if (amount == m_buffers.first().length()) return m_buffers.first();

		QByteArray result;

		foreach (const QByteArray &b, m_buffers) {
			if (amount < b.length()) {
				result.append(b.left(amount));
				return result;
			}

			result.append(b);
			amount -= b.length();
			if (0 == amount) return result;
		}

		return result;
	}

	QByteArray ByteStream::pop(int amount) {
		if (amount <= 0) qFatal("SSLCaps::ByteStream::pop called with amount < 0");
		if (m_buffers.empty()) return QByteArray();

		QByteArray result;

		if (amount == m_buffers.first().length()) {
			result = m_buffers.first();
			m_buffers.pop_front();
			return result;
		}

		while (!m_buffers.empty()) {
			const QByteArray &b(m_buffers.first());

			if (amount < b.length()) {
				result.append(b.left(amount));
				QByteArray slice = b.right(b.length() - amount);
				m_buffers.pop_front();
				m_buffers.push_front(slice);
				m_length -= amount;
				return result;
			}

			result.append(b);
			amount -= b.length();
			m_length -= b.length();
			m_buffers.pop_front();

			if (0 == amount) return result;
		}

		return result;
	}
}
