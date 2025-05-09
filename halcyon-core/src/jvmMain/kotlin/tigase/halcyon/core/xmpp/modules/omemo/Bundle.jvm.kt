package tigase.halcyon.core.xmpp.modules.omemo

import org.signal.libsignal.protocol.ecc.Curve

actual fun Bundle.getRandomPreKeyBundle(): PreKeyBundle {
    val preKey = this.preKeys.random()
    return PreKeyBundle(
        this.deviceId,
        this.deviceId,
        preKey.preKeyId,
        Curve.decodePoint(preKey.preKeyPublic, 0),
        this.signedPreKeyId,
        Curve.decodePoint(this.signedPreKeyPublic, 0),
        this.signedPreKeySignature,
        IdentityKey(this.identityKey, 0)
    )
}

actual typealias PreKeyBundle = org.signal.libsignal.protocol.state.PreKeyBundle

actual typealias SignalProtocolAddress = org.signal.libsignal.protocol.SignalProtocolAddress

actual typealias ECPublicKey = org.signal.libsignal.protocol.ecc.ECPublicKey
actual typealias ECKeyPair = org.signal.libsignal.protocol.ecc.ECKeyPair
actual typealias IdentityKey = org.signal.libsignal.protocol.IdentityKey


actual typealias IdentityKeyPair = org.signal.libsignal.protocol.IdentityKeyPair
actual typealias SignedPreKeyRecord = org.signal.libsignal.protocol.state.SignedPreKeyRecord
actual typealias PreKeyRecord = org.signal.libsignal.protocol.state.PreKeyRecord
actual class SessionBuilder actual constructor(
    store: SignalProtocolStore,
    address: SignalProtocolAddress
) : org.signal.libsignal.protocol.SessionBuilder(store, address) {

}

actual typealias SessionCipher = org.signal.libsignal.protocol.SessionCipher

actual typealias UntrustedIdentityException = org.signal.libsignal.protocol.UntrustedIdentityException
actual typealias InvalidKeyException = org.signal.libsignal.protocol.InvalidKeyException;

actual typealias SignalProtocolStore = org.signal.libsignal.protocol.state.SignalProtocolStore

actual typealias InvalidKeyIdException = org.signal.libsignal.protocol.InvalidKeyIdException
actual typealias PreKeyStore = org.signal.libsignal.protocol.state.PreKeyStore

actual typealias SignedPreKeyStore = org.signal.libsignal.protocol.state.SignedPreKeyStore

actual typealias SessionRecord = org.signal.libsignal.protocol.state.SessionRecord

actual typealias SessionStore = org.signal.libsignal.protocol.state.SessionStore

actual typealias IdentityKeyStore = org.signal.libsignal.protocol.state.IdentityKeyStore

actual typealias IdentityKeyStoreDirection = org.signal.libsignal.protocol.state.IdentityKeyStore.Direction;