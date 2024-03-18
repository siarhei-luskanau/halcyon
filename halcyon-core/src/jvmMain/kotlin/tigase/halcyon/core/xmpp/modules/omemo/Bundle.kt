package tigase.halcyon.core.xmpp.modules.omemo

import org.whispersystems.libsignal.IdentityKey
import org.whispersystems.libsignal.ecc.Curve
import org.whispersystems.libsignal.state.PreKeyBundle
import tigase.halcyon.core.exceptions.HalcyonException
import tigase.halcyon.core.fromBase64
import tigase.halcyon.core.xml.Element
import tigase.halcyon.core.xmpp.BareJID

/**
 * Pre-key data.
 */
data class PreKey(val preKeyId: Int, val preKeyPublic: ByteArray)

/**
 * Key bundle data.
 */
data class Bundle(
    val jid: BareJID,
    val deviceId: Int,
    val signedPreKeyId: Int,
    val signedPreKeyPublic: ByteArray,
    val signedPreKeySignature: ByteArray,
    val identityKey: ByteArray,
    val preKeys: List<PreKey>
)

/**
 * Converts `<bundle>` element to [Bundle].
 * @param jid JabberID of bundle owner.
 * @param deviceId device id of bundle publisher.
 */
fun Element.toBundleOf(jid: BareJID, deviceId: Int): Bundle {
    if (this.name != "bundle" || this.xmlns != OMEMOModule.XMLNS) throw HalcyonException("Not a bundle element.")
    val signedPreKeyId = this.getFirstChild("signedPreKeyPublic")?.attributes?.get("signedPreKeyId")
        ?: throw HalcyonException("Incomplete bundle: signedPreKeyId not found")
    val signedPreKeyPublic = this.getFirstChild("signedPreKeyPublic")?.value
        ?: throw HalcyonException("Incomplete bundle: signedPreKeyPublic not found")
    val signedPreKeySignature = this.getFirstChild("signedPreKeySignature")?.value
        ?: throw HalcyonException("Incomplete bundle: signedPreKeySignature not found")
    val identityKey = this.getFirstChild("identityKey")?.value
        ?: throw HalcyonException("Incomplete bundle: identityKey not found")

    val prekeys = this.getFirstChild("prekeys")
        ?.getChildren("preKeyPublic")
        ?.map {
            PreKey(
                it.attributes["preKeyId"]?.toInt() ?: throw HalcyonException("Invalid preKeyPublic"),
                it.value?.fromBase64() ?: throw HalcyonException("Invalid preKeyPublic")
            )
        } ?: emptyList()
    return Bundle(
        jid = jid,
        deviceId = deviceId,
        signedPreKeyId = signedPreKeyId.toInt(),
        signedPreKeyPublic = signedPreKeyPublic.fromBase64(),
        signedPreKeySignature = signedPreKeySignature.fromBase64(),
        identityKey = identityKey.fromBase64(),
        preKeys = prekeys
    )
}

fun Bundle.getRandomPreKeyBundle(): PreKeyBundle {
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