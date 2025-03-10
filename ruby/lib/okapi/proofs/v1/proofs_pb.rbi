# Code generated by protoc-gen-rbi. DO NOT EDIT.
# source: okapi/proofs/v1/proofs.proto
# typed: strict

module Okapi; end
module Okapi::Proofs; end
module Okapi::Proofs::V1; end

class Okapi::Proofs::V1::CreateProofRequest
  include Google::Protobuf
  include Google::Protobuf::MessageExts
  extend Google::Protobuf::MessageExts::ClassMethods

  sig { params(str: String).returns(Okapi::Proofs::V1::CreateProofRequest) }
  def self.decode(str)
  end

  sig { params(msg: Okapi::Proofs::V1::CreateProofRequest).returns(String) }
  def self.encode(msg)
  end

  sig { params(str: String, kw: T.untyped).returns(Okapi::Proofs::V1::CreateProofRequest) }
  def self.decode_json(str, **kw)
  end

  sig { params(msg: Okapi::Proofs::V1::CreateProofRequest, kw: T.untyped).returns(String) }
  def self.encode_json(msg, **kw)
  end

  sig { returns(Google::Protobuf::Descriptor) }
  def self.descriptor
  end

  sig do
    params(
      document: T.nilable(Google::Protobuf::Struct),
      key: T.nilable(Okapi::Keys::V1::JsonWebKey),
      suite: T.nilable(T.any(Symbol, String, Integer))
    ).void
  end
  def initialize(
    document: nil,
    key: nil,
    suite: :LD_SUITE_UNSPECIFIED
  )
  end

  sig { returns(T.nilable(Google::Protobuf::Struct)) }
  def document
  end

  sig { params(value: T.nilable(Google::Protobuf::Struct)).void }
  def document=(value)
  end

  sig { void }
  def clear_document
  end

  sig { returns(T.nilable(Okapi::Keys::V1::JsonWebKey)) }
  def key
  end

  sig { params(value: T.nilable(Okapi::Keys::V1::JsonWebKey)).void }
  def key=(value)
  end

  sig { void }
  def clear_key
  end

  sig { returns(Symbol) }
  def suite
  end

  sig { params(value: T.any(Symbol, String, Integer)).void }
  def suite=(value)
  end

  sig { void }
  def clear_suite
  end

  sig { params(field: String).returns(T.untyped) }
  def [](field)
  end

  sig { params(field: String, value: T.untyped).void }
  def []=(field, value)
  end

  sig { returns(T::Hash[Symbol, T.untyped]) }
  def to_h
  end
end

class Okapi::Proofs::V1::CreateProofResponse
  include Google::Protobuf
  include Google::Protobuf::MessageExts
  extend Google::Protobuf::MessageExts::ClassMethods

  sig { params(str: String).returns(Okapi::Proofs::V1::CreateProofResponse) }
  def self.decode(str)
  end

  sig { params(msg: Okapi::Proofs::V1::CreateProofResponse).returns(String) }
  def self.encode(msg)
  end

  sig { params(str: String, kw: T.untyped).returns(Okapi::Proofs::V1::CreateProofResponse) }
  def self.decode_json(str, **kw)
  end

  sig { params(msg: Okapi::Proofs::V1::CreateProofResponse, kw: T.untyped).returns(String) }
  def self.encode_json(msg, **kw)
  end

  sig { returns(Google::Protobuf::Descriptor) }
  def self.descriptor
  end

  sig do
    params(
      signed_document: T.nilable(Google::Protobuf::Struct)
    ).void
  end
  def initialize(
    signed_document: nil
  )
  end

  sig { returns(T.nilable(Google::Protobuf::Struct)) }
  def signed_document
  end

  sig { params(value: T.nilable(Google::Protobuf::Struct)).void }
  def signed_document=(value)
  end

  sig { void }
  def clear_signed_document
  end

  sig { params(field: String).returns(T.untyped) }
  def [](field)
  end

  sig { params(field: String, value: T.untyped).void }
  def []=(field, value)
  end

  sig { returns(T::Hash[Symbol, T.untyped]) }
  def to_h
  end
end

class Okapi::Proofs::V1::VerifyProofRequest
  include Google::Protobuf
  include Google::Protobuf::MessageExts
  extend Google::Protobuf::MessageExts::ClassMethods

  sig { params(str: String).returns(Okapi::Proofs::V1::VerifyProofRequest) }
  def self.decode(str)
  end

  sig { params(msg: Okapi::Proofs::V1::VerifyProofRequest).returns(String) }
  def self.encode(msg)
  end

  sig { params(str: String, kw: T.untyped).returns(Okapi::Proofs::V1::VerifyProofRequest) }
  def self.decode_json(str, **kw)
  end

  sig { params(msg: Okapi::Proofs::V1::VerifyProofRequest, kw: T.untyped).returns(String) }
  def self.encode_json(msg, **kw)
  end

  sig { returns(Google::Protobuf::Descriptor) }
  def self.descriptor
  end

  sig { params(field: String).returns(T.untyped) }
  def [](field)
  end

  sig { params(field: String, value: T.untyped).void }
  def []=(field, value)
  end

  sig { returns(T::Hash[Symbol, T.untyped]) }
  def to_h
  end
end

class Okapi::Proofs::V1::VerifyProofResponse
  include Google::Protobuf
  include Google::Protobuf::MessageExts
  extend Google::Protobuf::MessageExts::ClassMethods

  sig { params(str: String).returns(Okapi::Proofs::V1::VerifyProofResponse) }
  def self.decode(str)
  end

  sig { params(msg: Okapi::Proofs::V1::VerifyProofResponse).returns(String) }
  def self.encode(msg)
  end

  sig { params(str: String, kw: T.untyped).returns(Okapi::Proofs::V1::VerifyProofResponse) }
  def self.decode_json(str, **kw)
  end

  sig { params(msg: Okapi::Proofs::V1::VerifyProofResponse, kw: T.untyped).returns(String) }
  def self.encode_json(msg, **kw)
  end

  sig { returns(Google::Protobuf::Descriptor) }
  def self.descriptor
  end

  sig { params(field: String).returns(T.untyped) }
  def [](field)
  end

  sig { params(field: String, value: T.untyped).void }
  def []=(field, value)
  end

  sig { returns(T::Hash[Symbol, T.untyped]) }
  def to_h
  end
end

module Okapi::Proofs::V1::LdSuite
  self::LD_SUITE_UNSPECIFIED = T.let(0, Integer)
  self::LD_SUITE_JCSED25519SIGNATURE2020 = T.let(1, Integer)

  sig { params(value: Integer).returns(T.nilable(Symbol)) }
  def self.lookup(value)
  end

  sig { params(value: Symbol).returns(T.nilable(Integer)) }
  def self.resolve(value)
  end

  sig { returns(::Google::Protobuf::EnumDescriptor) }
  def self.descriptor
  end
end
