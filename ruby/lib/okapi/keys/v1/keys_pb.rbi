# Code generated by protoc-gen-rbi. DO NOT EDIT.
# source: okapi/keys/v1/keys.proto
# typed: strict

module Okapi; end
module Okapi::Keys; end
module Okapi::Keys::V1; end

class Okapi::Keys::V1::GenerateKeyRequest
  include Google::Protobuf
  include Google::Protobuf::MessageExts
  extend Google::Protobuf::MessageExts::ClassMethods

  sig { params(str: String).returns(Okapi::Keys::V1::GenerateKeyRequest) }
  def self.decode(str)
  end

  sig { params(msg: Okapi::Keys::V1::GenerateKeyRequest).returns(String) }
  def self.encode(msg)
  end

  sig { params(str: String, kw: T.untyped).returns(Okapi::Keys::V1::GenerateKeyRequest) }
  def self.decode_json(str, **kw)
  end

  sig { params(msg: Okapi::Keys::V1::GenerateKeyRequest, kw: T.untyped).returns(String) }
  def self.encode_json(msg, **kw)
  end

  sig { returns(Google::Protobuf::Descriptor) }
  def self.descriptor
  end

  sig do
    params(
      seed: T.nilable(String),
      key_type: T.nilable(T.any(Symbol, String, Integer))
    ).void
  end
  def initialize(
    seed: "",
    key_type: :KEY_TYPE_UNSPECIFIED
  )
  end

  sig { returns(String) }
  def seed
  end

  sig { params(value: String).void }
  def seed=(value)
  end

  sig { void }
  def clear_seed
  end

  sig { returns(Symbol) }
  def key_type
  end

  sig { params(value: T.any(Symbol, String, Integer)).void }
  def key_type=(value)
  end

  sig { void }
  def clear_key_type
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

class Okapi::Keys::V1::GenerateKeyResponse
  include Google::Protobuf
  include Google::Protobuf::MessageExts
  extend Google::Protobuf::MessageExts::ClassMethods

  sig { params(str: String).returns(Okapi::Keys::V1::GenerateKeyResponse) }
  def self.decode(str)
  end

  sig { params(msg: Okapi::Keys::V1::GenerateKeyResponse).returns(String) }
  def self.encode(msg)
  end

  sig { params(str: String, kw: T.untyped).returns(Okapi::Keys::V1::GenerateKeyResponse) }
  def self.decode_json(str, **kw)
  end

  sig { params(msg: Okapi::Keys::V1::GenerateKeyResponse, kw: T.untyped).returns(String) }
  def self.encode_json(msg, **kw)
  end

  sig { returns(Google::Protobuf::Descriptor) }
  def self.descriptor
  end

  sig do
    params(
      key: T.nilable(T::Array[T.nilable(Okapi::Keys::V1::JsonWebKey)]),
      did_document: T.nilable(Google::Protobuf::Struct)
    ).void
  end
  def initialize(
    key: [],
    did_document: nil
  )
  end

  sig { returns(T::Array[T.nilable(Okapi::Keys::V1::JsonWebKey)]) }
  def key
  end

  sig { params(value: Google::Protobuf::RepeatedField).void }
  def key=(value)
  end

  sig { void }
  def clear_key
  end

  sig { returns(T.nilable(Google::Protobuf::Struct)) }
  def did_document
  end

  sig { params(value: T.nilable(Google::Protobuf::Struct)).void }
  def did_document=(value)
  end

  sig { void }
  def clear_did_document
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

class Okapi::Keys::V1::ResolveRequest
  include Google::Protobuf
  include Google::Protobuf::MessageExts
  extend Google::Protobuf::MessageExts::ClassMethods

  sig { params(str: String).returns(Okapi::Keys::V1::ResolveRequest) }
  def self.decode(str)
  end

  sig { params(msg: Okapi::Keys::V1::ResolveRequest).returns(String) }
  def self.encode(msg)
  end

  sig { params(str: String, kw: T.untyped).returns(Okapi::Keys::V1::ResolveRequest) }
  def self.decode_json(str, **kw)
  end

  sig { params(msg: Okapi::Keys::V1::ResolveRequest, kw: T.untyped).returns(String) }
  def self.encode_json(msg, **kw)
  end

  sig { returns(Google::Protobuf::Descriptor) }
  def self.descriptor
  end

  sig do
    params(
      did: T.nilable(String)
    ).void
  end
  def initialize(
    did: ""
  )
  end

  sig { returns(String) }
  def did
  end

  sig { params(value: String).void }
  def did=(value)
  end

  sig { void }
  def clear_did
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

class Okapi::Keys::V1::ResolveResponse
  include Google::Protobuf
  include Google::Protobuf::MessageExts
  extend Google::Protobuf::MessageExts::ClassMethods

  sig { params(str: String).returns(Okapi::Keys::V1::ResolveResponse) }
  def self.decode(str)
  end

  sig { params(msg: Okapi::Keys::V1::ResolveResponse).returns(String) }
  def self.encode(msg)
  end

  sig { params(str: String, kw: T.untyped).returns(Okapi::Keys::V1::ResolveResponse) }
  def self.decode_json(str, **kw)
  end

  sig { params(msg: Okapi::Keys::V1::ResolveResponse, kw: T.untyped).returns(String) }
  def self.encode_json(msg, **kw)
  end

  sig { returns(Google::Protobuf::Descriptor) }
  def self.descriptor
  end

  sig do
    params(
      did_document: T.nilable(Google::Protobuf::Struct),
      keys: T.nilable(T::Array[T.nilable(Okapi::Keys::V1::JsonWebKey)])
    ).void
  end
  def initialize(
    did_document: nil,
    keys: []
  )
  end

  sig { returns(T.nilable(Google::Protobuf::Struct)) }
  def did_document
  end

  sig { params(value: T.nilable(Google::Protobuf::Struct)).void }
  def did_document=(value)
  end

  sig { void }
  def clear_did_document
  end

  sig { returns(T::Array[T.nilable(Okapi::Keys::V1::JsonWebKey)]) }
  def keys
  end

  sig { params(value: Google::Protobuf::RepeatedField).void }
  def keys=(value)
  end

  sig { void }
  def clear_keys
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

class Okapi::Keys::V1::JsonWebKey
  include Google::Protobuf
  include Google::Protobuf::MessageExts
  extend Google::Protobuf::MessageExts::ClassMethods

  sig { params(str: String).returns(Okapi::Keys::V1::JsonWebKey) }
  def self.decode(str)
  end

  sig { params(msg: Okapi::Keys::V1::JsonWebKey).returns(String) }
  def self.encode(msg)
  end

  sig { params(str: String, kw: T.untyped).returns(Okapi::Keys::V1::JsonWebKey) }
  def self.decode_json(str, **kw)
  end

  sig { params(msg: Okapi::Keys::V1::JsonWebKey, kw: T.untyped).returns(String) }
  def self.encode_json(msg, **kw)
  end

  sig { returns(Google::Protobuf::Descriptor) }
  def self.descriptor
  end

  sig do
    params(
      kid: T.nilable(String),
      x: T.nilable(String),
      y: T.nilable(String),
      d: T.nilable(String),
      crv: T.nilable(String),
      kty: T.nilable(String)
    ).void
  end
  def initialize(
    kid: "",
    x: "",
    y: "",
    d: "",
    crv: "",
    kty: ""
  )
  end

  sig { returns(String) }
  def kid
  end

  sig { params(value: String).void }
  def kid=(value)
  end

  sig { void }
  def clear_kid
  end

  sig { returns(String) }
  def x
  end

  sig { params(value: String).void }
  def x=(value)
  end

  sig { void }
  def clear_x
  end

  sig { returns(String) }
  def y
  end

  sig { params(value: String).void }
  def y=(value)
  end

  sig { void }
  def clear_y
  end

  sig { returns(String) }
  def d
  end

  sig { params(value: String).void }
  def d=(value)
  end

  sig { void }
  def clear_d
  end

  sig { returns(String) }
  def crv
  end

  sig { params(value: String).void }
  def crv=(value)
  end

  sig { void }
  def clear_crv
  end

  sig { returns(String) }
  def kty
  end

  sig { params(value: String).void }
  def kty=(value)
  end

  sig { void }
  def clear_kty
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

module Okapi::Keys::V1::KeyType
  self::KEY_TYPE_UNSPECIFIED = T.let(0, Integer)
  self::KEY_TYPE_ED25519 = T.let(1, Integer)
  self::KEY_TYPE_X25519 = T.let(2, Integer)
  self::KEY_TYPE_P256 = T.let(3, Integer)
  self::KEY_TYPE_BLS12381G1G2 = T.let(4, Integer)
  self::KEY_TYPE_SECP256K1 = T.let(5, Integer)

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
