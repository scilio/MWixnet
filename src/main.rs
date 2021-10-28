mod error;
mod onion;
mod secp;
mod ser;
mod types;

fn main() {
    let value : u64 = 1000;
    let blind = secp::insecure_rand_secret().unwrap(); 
    let commitment = secp::commit(value, &blind).unwrap();
    let secp = secp256k1zkp::Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);

    let session_key = secp::insecure_rand_secret().unwrap();
    let mut hops : Vec<types::Hop> = Vec::new();

    let mut keys : Vec<secp::SecretKey> = Vec::new();
    let mut latest_commit = commitment.clone();
    let mut latest_blind = blind.clone();
    for i in 0..5 {
        keys.push(secp::insecure_rand_secret().unwrap());

        let excess = secp::insecure_rand_secret().unwrap();

        latest_blind.add_assign(&secp, &excess).unwrap();
        latest_commit = secp::add_excess(&latest_commit, &excess).unwrap();
        let proof = if i == 4 {
            let n1 = secp::insecure_rand_secret().unwrap();
            let rp = secp.bullet_proof(value, latest_blind.clone(), n1.clone(), n1.clone(), None, None);
            Some(rp)
        } else {
            None
        };

        hops.push(types::Hop{
            pubkey: secp::to_public_key(&keys[i]).unwrap(),
            payload: types::Payload{
                routing_info: None,
                excess: excess,
                rangeproof: proof,
            }
        });
    }

    let mut onion_packet = onion::create_onion(&commitment, &session_key, &hops).unwrap();

    let mut payload = types::Payload{
        routing_info: None,
        excess: secp::insecure_rand_secret().unwrap(),
        rangeproof: None
    };
    for i in 0..5 {
        let peeled = onion::peel_layer(&onion_packet, &keys[i]).unwrap();
        payload = peeled.0;
        onion_packet = peeled.1;
    }

    // Calculate the final commitment and verify the rangeproof
    let final_commit = secp::commit(value, &latest_blind).unwrap();
    let proof = payload.rangeproof.unwrap();
    let _ = secp.verify_bullet_proof(final_commit, proof, None).unwrap();
}