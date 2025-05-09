package tigase.halcyon.core.xmpp.modules.omemo

actual class KeyHelper {
    actual companion object {
        actual fun generateIdentityKeyPair(): IdentityKeyPair = org.signal.libsignal.protocol.util.KeyHelper.generateIdentityKeyPair()
        actual fun generateRegistrationId(extendedRange: Boolean): Int = org.signal.libsignal.protocol.util.KeyHelper.generateRegistrationId(extendedRange)
        actual fun generatePreKeys(start: Int, count: Int): List<PreKeyRecord> = org.signal.libsignal.protocol.util.KeyHelper.generatePreKeys(start, count)
        actual fun generateSignedPreKey(identityKeyPair: IdentityKeyPair, signedPreKeyId: Int): SignedPreKeyRecord = org.signal.libsignal.protocol.util.KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId)
    }
}
