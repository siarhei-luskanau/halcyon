/*
 * halcyon-core
 * Copyright (C) 2018 Tigase, Inc. (office@tigase.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. Look for COPYING file in the top folder.
 * If not, see http://www.gnu.org/licenses/.
 */
package tigase.halcyon.core.connector.socket

import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.NSLock
import platform.Security.*
import platform.darwin.ByteVar
import tigase.halcyon.core.logger.LoggerFactory

@OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
class SSLEngine(connector: SocketConnector, domain: String) {

	private val log = LoggerFactory.logger("tigase.halcyon.core.connector.socket.SSLEngine")

	enum class HandshakeResult { complete,
		incomplete,
		failed;
	}

	enum class State { handshaking,
		active,
		closed
	}

	enum class SSLStatus { ok,
		want_read,
		want_write,
		fail;

		companion object {

			private val log = LoggerFactory.logger("tigase.halcyon.core.connector.socket.SSLEngine")
		}
	}

	private val connector: SocketConnector = connector
	private val domain = domain
	private var state: State = State.handshaking


//	private val socketWriterDispatchQueue = dispatch_queue_create("socketWriter", null);

	private var awaitingEncryption: MutableList<ByteArray> = mutableListOf()
	private val awaitingEncryptionLock = NSLock();

}