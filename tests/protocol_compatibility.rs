use prost::Message;
use sp1_private_prover::proto::{artifact as local_artifact, network as local};
use sp1_sdk::network::proto::{artifact as exact_artifact, auction_types as exact};

fn same_message<A: Message, B: Message>(left: A, right: B) {
    assert_eq!(left.encode_to_vec(), right.encode_to_vec());
}

#[test]
fn request_and_response_field_tags_match_sp1_6_2_2() {
    same_message(
        local_artifact::CreateArtifactRequest {
            signature: vec![1, 2],
            artifact_type: 2,
        },
        exact_artifact::CreateArtifactRequest {
            signature: vec![1, 2],
            artifact_type: 2,
        },
    );
    same_message(
        local::CreateProgramRequestBody {
            nonce: 9,
            vk_hash: vec![1; 32],
            vk: vec![2, 3],
            program_uri: "sp1-private://artifact/a".into(),
        },
        exact::CreateProgramRequestBody {
            nonce: 9,
            vk_hash: vec![1; 32],
            vk: vec![2, 3],
            program_uri: "sp1-private://artifact/a".into(),
        },
    );
    same_message(
        local::RequestProofRequestBody {
            nonce: 1,
            vk_hash: vec![2; 32],
            version: "sp1-v6.1.0".into(),
            mode: 4,
            strategy: 1,
            stdin_uri: "sp1-private://artifact/b".into(),
            deadline: 3,
            cycle_limit: 4,
            gas_limit: 5,
            min_auction_period: 6,
            whitelist: vec![vec![7; 20]],
            domain: vec![8],
            auctioneer: vec![9; 20],
            executor: vec![10; 20],
            verifier: vec![11; 20],
            public_values_hash: Some(vec![12; 32]),
            base_fee: "13".into(),
            max_price_per_pgu: "14".into(),
            variant: 15,
            treasury: vec![16; 20],
            stdin_private: true,
        },
        exact::RequestProofRequestBody {
            nonce: 1,
            vk_hash: vec![2; 32],
            version: "sp1-v6.1.0".into(),
            mode: 4,
            strategy: 1,
            stdin_uri: "sp1-private://artifact/b".into(),
            deadline: 3,
            cycle_limit: 4,
            gas_limit: 5,
            min_auction_period: 6,
            whitelist: vec![vec![7; 20]],
            domain: vec![8],
            auctioneer: vec![9; 20],
            executor: vec![10; 20],
            verifier: vec![11; 20],
            public_values_hash: Some(vec![12; 32]),
            base_fee: "13".into(),
            max_price_per_pgu: "14".into(),
            variant: 15,
            treasury: vec![16; 20],
            stdin_private: true,
        },
    );
    same_message(
        local::GetProofRequestStatusResponse {
            fulfillment_status: 3,
            execution_status: 2,
            request_tx_hash: vec![1; 32],
            deadline: 4,
            fulfill_tx_hash: Some(vec![2; 32]),
            proof_uri: Some("http://localhost/proof".into()),
            public_values_hash: Some(vec![3; 32]),
            proof_public_uri: None,
        },
        exact::GetProofRequestStatusResponse {
            fulfillment_status: 3,
            execution_status: 2,
            request_tx_hash: vec![1; 32],
            deadline: 4,
            fulfill_tx_hash: Some(vec![2; 32]),
            proof_uri: Some("http://localhost/proof".into()),
            public_values_hash: Some(vec![3; 32]),
            proof_public_uri: None,
        },
    );
    same_message(
        local::GetProofRequestParamsResponse {
            domain: vec![1],
            auctioneer: vec![2; 20],
            executor: vec![3; 20],
            verifier: vec![4; 20],
            max_price_per_pgu: "5".into(),
            base_fee: "6".into(),
            treasury: vec![7; 20],
            tick_size: 8,
        },
        exact::GetProofRequestParamsResponse {
            domain: vec![1],
            auctioneer: vec![2; 20],
            executor: vec![3; 20],
            verifier: vec![4; 20],
            max_price_per_pgu: "5".into(),
            base_fee: "6".into(),
            treasury: vec![7; 20],
            tick_size: 8,
        },
    );
    same_message(
        local::GetNonceRequest {
            address: vec![1; 20],
        },
        exact::GetNonceRequest {
            address: vec![1; 20],
        },
    );
    same_message(
        local::GetProversByUptimeResponse {
            provers: vec![vec![1; 20]],
        },
        exact::GetProversByUptimeResponse {
            provers: vec![vec![1; 20]],
        },
    );
    same_message(
        local::CancelRequestRequestBody {
            nonce: 7,
            request_id: vec![8; 32],
        },
        exact::CancelRequestRequestBody {
            nonce: 7,
            request_id: vec![8; 32],
        },
    );
}

#[test]
fn grpc_method_paths_match_the_exact_sdk() {
    let generated = include_str!("../vendor/sp1/crates/sdk/src/network/proto/auction/network.rs");
    for path in [
        "/network.ProverNetwork/GetProgram",
        "/network.ProverNetwork/CreateProgram",
        "/network.ProverNetwork/GetProofRequestParams",
        "/network.ProverNetwork/GetNonce",
        "/network.ProverNetwork/GetProversByUptime",
        "/network.ProverNetwork/RequestProof",
        "/network.ProverNetwork/GetProofRequestStatus",
        "/network.ProverNetwork/CancelRequest",
    ] {
        assert!(generated.contains(path), "exact SP1 SDK lacks {path}");
    }
    let artifact = include_str!("../vendor/sp1/crates/sdk/src/network/proto/artifact.rs");
    assert!(artifact.contains("/artifact.ArtifactStore/CreateArtifact"));
}
