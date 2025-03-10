//Generated by the protocol buffer compiler. DO NOT EDIT!
// source: okapi/transport/v1/transport.proto

package trinsic.okapi.transport.v1;

@kotlin.jvm.JvmSynthetic
public inline fun signRequest(block: trinsic.okapi.transport.v1.SignRequestKt.Dsl.() -> kotlin.Unit): trinsic.okapi.transport.v1.Transport.SignRequest =
  trinsic.okapi.transport.v1.SignRequestKt.Dsl._create(trinsic.okapi.transport.v1.Transport.SignRequest.newBuilder()).apply { block() }._build()
public object SignRequestKt {
  @kotlin.OptIn(com.google.protobuf.kotlin.OnlyForUseByGeneratedProtoCode::class)
  @com.google.protobuf.kotlin.ProtoDslMarker
  public class Dsl private constructor(
    private val _builder: trinsic.okapi.transport.v1.Transport.SignRequest.Builder
  ) {
    public companion object {
      @kotlin.jvm.JvmSynthetic
      @kotlin.PublishedApi
      internal fun _create(builder: trinsic.okapi.transport.v1.Transport.SignRequest.Builder): Dsl = Dsl(builder)
    }

    @kotlin.jvm.JvmSynthetic
    @kotlin.PublishedApi
    internal fun _build(): trinsic.okapi.transport.v1.Transport.SignRequest = _builder.build()

    /**
     * <code>bytes payload = 1;</code>
     */
    public var payload: com.google.protobuf.ByteString
      @JvmName("getPayload")
      get() = _builder.getPayload()
      @JvmName("setPayload")
      set(value) {
        _builder.setPayload(value)
      }
    /**
     * <code>bytes payload = 1;</code>
     */
    public fun clearPayload() {
      _builder.clearPayload()
    }

    /**
     * <code>.okapi.keys.v1.JsonWebKey key = 2;</code>
     */
    public var key: trinsic.okapi.keys.v1.Keys.JsonWebKey
      @JvmName("getKey")
      get() = _builder.getKey()
      @JvmName("setKey")
      set(value) {
        _builder.setKey(value)
      }
    /**
     * <code>.okapi.keys.v1.JsonWebKey key = 2;</code>
     */
    public fun clearKey() {
      _builder.clearKey()
    }
    /**
     * <code>.okapi.keys.v1.JsonWebKey key = 2;</code>
     * @return Whether the key field is set.
     */
    public fun hasKey(): kotlin.Boolean {
      return _builder.hasKey()
    }

    /**
     * <code>.pbmse.v1.SignedMessage append_to = 3;</code>
     */
    public var appendTo: trinsic.okapi.pbmse.v1.Pbmse.SignedMessage
      @JvmName("getAppendTo")
      get() = _builder.getAppendTo()
      @JvmName("setAppendTo")
      set(value) {
        _builder.setAppendTo(value)
      }
    /**
     * <code>.pbmse.v1.SignedMessage append_to = 3;</code>
     */
    public fun clearAppendTo() {
      _builder.clearAppendTo()
    }
    /**
     * <code>.pbmse.v1.SignedMessage append_to = 3;</code>
     * @return Whether the appendTo field is set.
     */
    public fun hasAppendTo(): kotlin.Boolean {
      return _builder.hasAppendTo()
    }
  }
}
@kotlin.jvm.JvmSynthetic
public inline fun trinsic.okapi.transport.v1.Transport.SignRequest.copy(block: trinsic.okapi.transport.v1.SignRequestKt.Dsl.() -> kotlin.Unit): trinsic.okapi.transport.v1.Transport.SignRequest =
  trinsic.okapi.transport.v1.SignRequestKt.Dsl._create(this.toBuilder()).apply { block() }._build()
