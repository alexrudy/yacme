use std::ops::Add;

use ::ecdsa::PrimeCurve;
use digest::generic_array::ArrayLength;
use ecdsa::der::{MaxOverhead, MaxSize};
use ecdsa::hazmat::SignPrimitive;
use ecdsa::SignatureSize;
use elliptic_curve::{ops::Invert, subtle::CtOption, Scalar};
use elliptic_curve::{
    point::{AffinePoint, PointCompression},
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve, CurveArithmetic, FieldBytesSize, PublicKey,
};

impl<C> super::PublicKey for ::elliptic_curve::PublicKey<C>
where
    C: PointCompression + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn as_bytes(&self) -> Box<[u8]> {
        self.to_sec1_bytes()
    }
}

impl<C> super::KeyPair for ::elliptic_curve::SecretKey<C>
where
    C: Curve + PointCompression + CurveArithmetic + PrimeCurve,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
    <C as CurveArithmetic>::Scalar:
        ::ecdsa::hazmat::SignPrimitive<C> + Invert<Output = CtOption<Scalar<C>>>,
{
    type PublicKey = PublicKey<C>;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key()
    }
}

impl<C> super::KeyPair for ::ecdsa::SigningKey<C>
where
    C: Curve + PointCompression + CurveArithmetic + PrimeCurve,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
    <C as CurveArithmetic>::Scalar:
        ::ecdsa::hazmat::SignPrimitive<C> + Invert<Output = CtOption<Scalar<C>>>,
{
    type PublicKey = PublicKey<C>;

    fn public_key(&self) -> Self::PublicKey {
        self.verifying_key().into()
    }
}

impl super::CertificateKey<::ecdsa::Signature<p256::NistP256>, sha2::Sha256>
    for ::ecdsa::SigningKey<p256::NistP256>
{
    fn algorithm(&self) -> spki::AlgorithmIdentifierOwned {
        spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        }
    }
}

impl<C> super::Signature for ::ecdsa::Signature<C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    fn to_der(&self) -> der::Document {
        der::Document::encode_msg(&self.to_der()).unwrap()
    }
}
