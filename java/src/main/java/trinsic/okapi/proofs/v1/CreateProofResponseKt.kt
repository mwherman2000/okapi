//Generated by the protocol buffer compiler. DO NOT EDIT!
// source: okapi/proofs/v1/proofs.proto

package trinsic.okapi.proofs.v1;

@kotlin.jvm.JvmSynthetic
public inline fun createProofResponse(block: trinsic.okapi.proofs.v1.CreateProofResponseKt.Dsl.() -> kotlin.Unit): trinsic.okapi.proofs.v1.Proofs.CreateProofResponse =
  trinsic.okapi.proofs.v1.CreateProofResponseKt.Dsl._create(trinsic.okapi.proofs.v1.Proofs.CreateProofResponse.newBuilder()).apply { block() }._build()
public object CreateProofResponseKt {
  @kotlin.OptIn(com.google.protobuf.kotlin.OnlyForUseByGeneratedProtoCode::class)
  @com.google.protobuf.kotlin.ProtoDslMarker
  public class Dsl private constructor(
    private val _builder: trinsic.okapi.proofs.v1.Proofs.CreateProofResponse.Builder
  ) {
    public companion object {
      @kotlin.jvm.JvmSynthetic
      @kotlin.PublishedApi
      internal fun _create(builder: trinsic.okapi.proofs.v1.Proofs.CreateProofResponse.Builder): Dsl = Dsl(builder)
    }

    @kotlin.jvm.JvmSynthetic
    @kotlin.PublishedApi
    internal fun _build(): trinsic.okapi.proofs.v1.Proofs.CreateProofResponse = _builder.build()

    /**
     * <code>.google.protobuf.Struct signed_document = 1;</code>
     */
    public var signedDocument: com.google.protobuf.Struct
      @JvmName("getSignedDocument")
      get() = _builder.getSignedDocument()
      @JvmName("setSignedDocument")
      set(value) {
        _builder.setSignedDocument(value)
      }
    /**
     * <code>.google.protobuf.Struct signed_document = 1;</code>
     */
    public fun clearSignedDocument() {
      _builder.clearSignedDocument()
    }
    /**
     * <code>.google.protobuf.Struct signed_document = 1;</code>
     * @return Whether the signedDocument field is set.
     */
    public fun hasSignedDocument(): kotlin.Boolean {
      return _builder.hasSignedDocument()
    }
  }
}
@kotlin.jvm.JvmSynthetic
public inline fun trinsic.okapi.proofs.v1.Proofs.CreateProofResponse.copy(block: trinsic.okapi.proofs.v1.CreateProofResponseKt.Dsl.() -> kotlin.Unit): trinsic.okapi.proofs.v1.Proofs.CreateProofResponse =
  trinsic.okapi.proofs.v1.CreateProofResponseKt.Dsl._create(this.toBuilder()).apply { block() }._build()
