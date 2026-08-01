use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use prost::Message;
use sha3::{Digest, Keccak256};
use tonic::Status;

#[allow(clippy::result_large_err)] // tonic::Status is the required gRPC error type.
pub fn recover_message_signer(message: &[u8], signature: &[u8]) -> Result<String, Status> {
    if signature.len() != 65 {
        return Err(Status::unauthenticated("signature must contain 65 bytes"));
    }
    let recovery_byte = match signature[64] {
        0 | 1 => signature[64],
        27 | 28 => signature[64] - 27,
        // SP1 6.2.2 and the pinned SDK call Alloy `Signature::as_bytes()`,
        // which already returns 27/28, and then add 27 again for
        // CreateArtifact. Preserve compatibility with those 54/55 bytes.
        54 | 55 => signature[64] - 54,
        _ => {
            return Err(Status::unauthenticated(
                "signature recovery identifier is invalid",
            ))
        }
    };
    let signature = Signature::try_from(&signature[..64])
        .map_err(|_| Status::unauthenticated("signature is invalid"))?;
    let recovery_id = RecoveryId::from_byte(recovery_byte)
        .ok_or_else(|| Status::unauthenticated("signature recovery identifier is invalid"))?;
    let digest = eip191_hash(message);
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|_| Status::unauthenticated("signature does not recover a signer"))?;
    let encoded = key.to_encoded_point(false);
    let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

#[allow(clippy::result_large_err)] // tonic::Status is the required gRPC error type.
pub fn recover_body_signer<M: Message>(body: &M, signature: &[u8]) -> Result<String, Status> {
    recover_message_signer(&body.encode_to_vec(), signature)
}

fn eip191_hash(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;
    use sha3::{Digest, Keccak256};

    use super::*;

    #[test]
    fn recovers_eip191_signer_with_ethereum_recovery_byte() {
        let key = SigningKey::from_slice(&[7_u8; 32]).unwrap();
        let message = b"create_artifact";
        let digest = eip191_hash(message);
        let (signature, recovery_id) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery_id.to_byte() + 27);
        let recovered = recover_message_signer(message, &bytes).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        assert_eq!(recovered, format!("0x{}", hex::encode(&hash[12..])));
    }

    #[test]
    fn recovers_sp1_6_2_2_double_offset_recovery_byte() {
        let key = SigningKey::from_slice(&[9_u8; 32]).unwrap();
        let message = b"create_artifact";
        let digest = eip191_hash(message);
        let (signature, recovery_id) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery_id.to_byte() + 54);
        let recovered = recover_message_signer(message, &bytes).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        assert_eq!(recovered, format!("0x{}", hex::encode(&hash[12..])));
    }
}
