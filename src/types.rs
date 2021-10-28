use crate::error::Result;
use crate::secp::{Commitment, PublicKey, RangeProof, SecretKey};
use crate::ser::{self, BinReader, Readable, Reader, Writeable, Writer};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

pub type RawBytes = Vec<u8>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RoutingInfo {
    // todo
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payload {
    pub routing_info: Option<RoutingInfo>,
    pub excess: SecretKey,
    pub rangeproof: Option<RangeProof>,
}

impl Readable for Payload {
	fn read<R: Reader>(reader: &mut R) -> Result<Payload> {
        let routing_info = if reader.read_u8()? == 0 { None } else { Some(RoutingInfo{}) };
        let excess = SecretKey::read(reader)?;
        let rangeproof = if reader.read_u8()? == 0 {
            None
        } else {
            Some(RangeProof::read(reader)?)
        };

        let payload = Payload {
            routing_info: routing_info,
            excess: excess,
            rangeproof: rangeproof
        };
        Ok(payload)
	}
}

impl Writeable for Payload {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<()> {
        match &self.routing_info {
            Some(_r) => writer.write_u8(1)?,
            None => writer.write_u8(0)?,
        };
        
        writer.write_fixed_bytes(&self.excess)?;

        match &self.rangeproof {
            Some(proof) => {
                writer.write_u8(1)?;
                proof.write(writer)?;
            },
            None => writer.write_u8(0)?,
        };

        Ok(())
	}
}

pub fn serialize_payload(payload: &Payload) -> Result<Vec<u8>> {
    ser::ser_vec(&payload)
}

pub fn deserialize_payload(bytes: &Vec<u8>) -> Result<Payload> {
	let mut cursor = Cursor::new(&bytes);
    let mut reader = BinReader::new(&mut cursor);
    Payload::read(&mut reader)
}

pub struct Onion {
    pub ephemeral_pubkey: PublicKey,
    pub commit: Commitment,
    pub enc_payloads: Vec<RawBytes>,
}

pub struct Hop {
    pub pubkey: PublicKey,
    pub payload: Payload,
}