use crate::onion;
use crate::secp::{self, Commitment, ComSignature, SecretKey};
use crate::ser;
use crate::types::Onion;

use jsonrpc_v2::{Data, Params};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub struct ServerConfig {
    pub key: SecretKey,
    pub addr: SocketAddr,
    pub is_first: bool,
}

pub struct Submission {
    pub excess: SecretKey,
    pub input_commit: Commitment,
    pub onion: Onion,
}

#[derive(Serialize, Deserialize)]
pub struct SwapReq {
    pub onion: Onion,
    #[serde(with = "ser::vec_serde")]
    pub msg: Vec<u8>,
	#[serde(with = "secp::comsig_serde")]
    pub comsig: ComSignature,
}

lazy_static! {
    static ref SERVER_STATE: Mutex<Vec<Submission>> = Mutex::new(Vec::new());
}

async fn swap(server_config: Data<ServerConfig>, Params(swap): Params<SwapReq>) -> Result<(), jsonrpc_v2::Error> {
    // milestone 2 - check that commitment is unspent

    // Verify commitment signature to ensure caller owns the output
    let _ = swap.comsig.verify(&swap.onion.commit, &swap.msg)?;

    let peeled = onion::peel_layer(&swap.onion, &(*server_config).key)?;
    SERVER_STATE.lock().unwrap().push(Submission{
        excess: peeled.0.excess,
        input_commit: swap.onion.commit,
        onion: peeled.1
    });
    Ok(())
}

/// Takes in entries, peels, then stores results. Re-sorts matrix and sends to next server
async fn derive_outputs(_server_config: Data<ServerConfig>, Params(_entries): Params<Vec<Onion>>) -> Result<(), jsonrpc_v2::Error> {
    // milestone 3 - peel onion layer, store and forward
    Ok(())
}

async fn derive_kernel(_server_config: Data<ServerConfig>, Params(_tx): Params<()>) -> Result<(), jsonrpc_v2::Error> {
    // milestone 3 - modify kernel excess then forward
    Ok(())
}

/// Spin up the JSON-RPC web server
pub async fn listen<F>(server_config: &ServerConfig, shutdown_signal: F) -> std::result::Result<(), Box<dyn std::error::Error>>
where
    F: core::future::Future<Output = ()>,
{
    let mut rpc = jsonrpc_v2::Server::new()
        .with_data(Data::new(server_config.clone()))
        .with_method("derive_outputs", derive_outputs)
        .with_method("derive_kernel", derive_kernel);

    if server_config.is_first {
        rpc = rpc.with_method("swap", swap);
    }

    let web_service = rpc.finish().into_hyper_web_service();
    let rpc_server = hyper::server::Server::bind(&server_config.addr);
    rpc_server
        .serve(web_service)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{onion, secp, server, types};
    use std::net::TcpListener;
    use std::time::Duration;
    use std::thread;

    use hyper::{Body, Client, Request, Response};
    use tokio::runtime;

    /// Spin up a temporary web service, query the API, then cleanup and return response
    fn make_request(server_key: secp::SecretKey, req: String) -> Result<Response<Body>, Box<dyn std::error::Error>> {
        let server_config = server::ServerConfig { 
            key: server_key,
            addr: TcpListener::bind("127.0.0.1:0")?.local_addr()?,
            is_first: true
        };

        let threaded_rt = runtime::Runtime::new()?;
        let (shutdown_sender, shutdown_receiver) = futures::channel::oneshot::channel();
        let uri = format!("http://{}", server_config.addr);

        // Spawn the server task
        threaded_rt.spawn(async move {
            server::listen(&server_config, async { shutdown_receiver.await.ok(); }).await.unwrap()
        });

        // Wait for listener
        thread::sleep(Duration::from_millis(500));

        let do_request = async move {
            let request = Request::post(uri)
                .body(Body::from(req))
                .unwrap();

            Client::new().request(request).await
        };

        let response = threaded_rt.block_on(do_request)?;
        shutdown_sender.send(()).ok();

        // Wait for shutdown
        thread::sleep(Duration::from_millis(500));
        threaded_rt.shutdown_background();

        Ok(response)
    }

    #[test]
    fn swap_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
        let server_key = secp::insecure_rand_secret()?;
        
        let secp = secp::Secp256k1::new();
        let value: u64 = 100;
        let blind = secp::insecure_rand_secret()?;
        let commitment = secp::commit(value, &blind)?;
        let session_key = secp::insecure_rand_secret()?;

        let hop = types::Hop {
            pubkey: secp::PublicKey::from_secret_key(&secp, &server_key)?,
            payload: types::Payload{
                excess: secp::insecure_rand_secret()?,
                rangeproof: None,
            }
        };
        let hops: Vec<types::Hop> = vec![hop];
        let onion_packet = onion::create_onion(&commitment, &session_key, &hops)?;
        let msg : Vec<u8> = vec![0u8, 1u8, 2u8, 3u8];
        let comsig = secp::ComSignature::sign(value, &blind, &msg)?;
        let swap = server::SwapReq{
            onion: onion_packet,
            msg: msg,
            comsig: comsig,
        };

        let req = format!("{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": {}}}", serde_json::json!(swap));
        println!("{}", req);
        let response = make_request(server_key, req)?;
        assert!(response.status().is_success());
        Ok(())
    }


    #[test]
    fn swap_bad_request() -> Result<(), Box<dyn std::error::Error>> {
        let params = "{ \"param\": \"Not a valid Swap request\" }";
        let req = format!("{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": {}}}", params);
        let response = make_request(secp::insecure_rand_secret()?, req)?;
        assert!(response.status().is_success());
        Ok(())
    }
}