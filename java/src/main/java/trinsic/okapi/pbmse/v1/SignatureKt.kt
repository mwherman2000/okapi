//Generated by the protocol buffer compiler. DO NOT EDIT!
// source: pbmse/v1/pbmse.proto

package trinsic.okapi.pbmse.v1;

@kotlin.jvm.JvmSynthetic
public inline fun signature(block: trinsic.okapi.pbmse.v1.SignatureKt.Dsl.() -> kotlin.Unit): trinsic.okapi.pbmse.v1.Pbmse.Signature =
  trinsic.okapi.pbmse.v1.SignatureKt.Dsl._create(trinsic.okapi.pbmse.v1.Pbmse.Signature.newBuilder()).apply { block() }._build()
public object SignatureKt {
  @kotlin.OptIn(com.google.protobuf.kotlin.OnlyForUseByGeneratedProtoCode::class)
  @com.google.protobuf.kotlin.ProtoDslMarker
  public class Dsl private constructor(
    private val _builder: trinsic.okapi.pbmse.v1.Pbmse.Signature.Builder
  ) {
    public companion object {
      @kotlin.jvm.JvmSynthetic
      @kotlin.PublishedApi
      internal fun _create(builder: trinsic.okapi.pbmse.v1.Pbmse.Signature.Builder): Dsl = Dsl(builder)
    }

    @kotlin.jvm.JvmSynthetic
    @kotlin.PublishedApi
    internal fun _build(): trinsic.okapi.pbmse.v1.Pbmse.Signature = _builder.build()

    /**
     * <code>bytes header = 1;</code>
     */
    public var header: com.google.protobuf.ByteString
      @JvmName("getHeader")
      get() = _builder.getHeader()
      @JvmName("setHeader")
      set(value) {
        _builder.setHeader(value)
      }
    /**
     * <code>bytes header = 1;</code>
     */
    public fun clearHeader() {
      _builder.clearHeader()
    }

    /**
     * <code>bytes signature = 3;</code>
     */
    public var signature: com.google.protobuf.ByteString
      @JvmName("getSignature")
      get() = _builder.getSignature()
      @JvmName("setSignature")
      set(value) {
        _builder.setSignature(value)
      }
    /**
     * <code>bytes signature = 3;</code>
     */
    public fun clearSignature() {
      _builder.clearSignature()
    }
  }
}
@kotlin.jvm.JvmSynthetic
public inline fun trinsic.okapi.pbmse.v1.Pbmse.Signature.copy(block: trinsic.okapi.pbmse.v1.SignatureKt.Dsl.() -> kotlin.Unit): trinsic.okapi.pbmse.v1.Pbmse.Signature =
  trinsic.okapi.pbmse.v1.SignatureKt.Dsl._create(this.toBuilder()).apply { block() }._build()
