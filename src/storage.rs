use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use prost::Message;
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::proto::{
    artifact::ArtifactType,
    network::{Program, RequestProofRequestBody},
};

#[derive(Debug, Clone)]
pub struct Artifact {
    pub uri: String,
    pub kind: i32,
    pub path: PathBuf,
    pub expanded_size: u64,
    pub signer: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Running,
    Fulfilled,
    Failed,
    Canceled,
}

impl JobState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Fulfilled => "fulfilled",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "fulfilled" => Ok(Self::Fulfilled),
            "failed" => Ok(Self::Failed),
            "canceled" => Ok(Self::Canceled),
            _ => bail!("unknown job state {value}"),
        }
    }
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Fulfilled | Self::Failed | Self::Canceled)
    }
}

#[derive(Debug, Clone)]
pub struct Job {
    pub request_id: Vec<u8>,
    pub signer: String,
    pub request: RequestProofRequestBody,
    pub state: JobState,
    pub proof_path: Option<PathBuf>,
    pub proof_token_hash: Option<Vec<u8>>,
    pub proof_token: Option<String>,
    pub proof_token_expires_at: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct Storage {
    connection: Arc<Mutex<Connection>>,
    root: Arc<PathBuf>,
}

impl Storage {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("proofs"))?;
        fs::create_dir_all(root.join("tmp"))?;
        let connection = Connection::open(root.join("state.sqlite3"))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(SCHEMA)?;
        connection.execute(
            "UPDATE jobs SET state='queued', updated_at=?1 WHERE state='running'",
            [now()],
        )?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            root: Arc::new(root.to_path_buf()),
        })
    }

    pub fn create_upload(
        &self,
        signer: &str,
        kind: i32,
        expires_in: u64,
    ) -> Result<(String, String)> {
        let id = random_hex(24);
        let token = random_hex(32);
        let token_hash = Sha256::digest(token.as_bytes()).to_vec();
        let uri = format!("sp1-private://artifact/{id}");
        self.connection.lock().unwrap().execute(
            "INSERT INTO artifacts(uri,kind,signer,upload_token_hash,upload_expires_at,created_at) VALUES(?1,?2,?3,?4,?5,?6)",
            params![uri, kind, signer, token_hash, now() + expires_in, now()],
        )?;
        Ok((uri, token))
    }

    pub fn store_upload(
        &self,
        token: &str,
        compressed: &[u8],
        max_expanded: u64,
        max_elf: u64,
        retained_maximum: u64,
    ) -> Result<String> {
        let token_hash = Sha256::digest(token.as_bytes()).to_vec();
        let mut connection = self.connection.lock().unwrap();
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(String, i32, Option<u64>)> = tx.query_row(
            "SELECT uri,kind,upload_expires_at FROM artifacts WHERE upload_token_hash=?1 AND object_hash IS NULL",
            [&token_hash], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let (uri, kind, expires_at) = row.context("upload token is unknown or already used")?;
        if expires_at.unwrap_or_default() < now() {
            bail!("upload token expired");
        }
        let expanded = decompress_limited(compressed, max_expanded)?;
        let object = if kind == ArtifactType::Program as i32 {
            bincode::deserialize::<Vec<u8>>(&expanded).context("decode bincode program artifact")?
        } else {
            expanded
        };
        if kind == ArtifactType::Program as i32 && object.len() as u64 > max_elf {
            bail!("program ELF exceeds configured limit");
        }
        let artifact_bytes: u64 = tx.query_row(
            "SELECT coalesce(sum(expanded_size),0) FROM artifacts WHERE object_hash IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let proof_bytes: u64 = tx.query_row(
            "SELECT coalesce(sum(proof_size),0) FROM jobs WHERE proof_path IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        if artifact_bytes
            .saturating_add(proof_bytes)
            .saturating_add(object.len() as u64)
            > retained_maximum
        {
            bail!("retained artifact storage limit reached");
        }
        let object_hash = hex::encode(Sha256::digest(&object));
        let final_path = self.root.join("objects").join(&object_hash);
        if !final_path.exists() {
            atomic_write(&self.root.join("tmp"), &final_path, &object)?;
        }
        tx.execute(
            "UPDATE artifacts SET object_hash=?1,expanded_size=?2,upload_token_hash=NULL,upload_expires_at=NULL WHERE uri=?3",
            params![object_hash, object.len() as u64, uri],
        )?;
        tx.commit()?;
        Ok(uri)
    }

    pub fn artifact(&self, uri: &str) -> Result<Option<Artifact>> {
        let root = self.root.clone();
        self.connection.lock().unwrap().query_row(
            "SELECT uri,kind,object_hash,expanded_size,signer FROM artifacts WHERE uri=?1 AND object_hash IS NOT NULL",
            [uri], |row| {
                let hash: String = row.get(2)?;
                Ok(Artifact { uri: row.get(0)?, kind: row.get(1)?, path: root.join("objects").join(hash), expanded_size: row.get(3)?, signer: row.get(4)? })
            },
        ).optional().map_err(Into::into)
    }

    pub fn nonce(&self, signer: &str) -> Result<u64> {
        Ok(self
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT nonce FROM nonces WHERE signer=?1",
                [signer],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    pub fn consume_nonce(&self, signer: &str, supplied: u64) -> Result<()> {
        let mut connection = self.connection.lock().unwrap();
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: u64 = tx
            .query_row(
                "SELECT nonce FROM nonces WHERE signer=?1",
                [signer],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if current != supplied {
            bail!("nonce mismatch: expected {current}, received {supplied}");
        }
        tx.execute("INSERT INTO nonces(signer,nonce) VALUES(?1,?2) ON CONFLICT(signer) DO UPDATE SET nonce=excluded.nonce", params![signer, current + 1])?;
        tx.commit()?;
        Ok(())
    }

    pub fn program(&self, vk_hash: &[u8]) -> Result<Option<Program>> {
        self.connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT vk_hash,vk,program_uri,owner,created_at FROM programs WHERE vk_hash=?1",
                [vk_hash],
                |row| {
                    Ok(Program {
                        vk_hash: row.get(0)?,
                        vk: row.get(1)?,
                        program_uri: row.get(2)?,
                        name: None,
                        owner: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn insert_program(&self, program: &Program) -> Result<()> {
        self.connection.lock().unwrap().execute(
            "INSERT INTO programs(vk_hash,vk,program_uri,owner,created_at) VALUES(?1,?2,?3,?4,?5)",
            params![
                program.vk_hash,
                program.vk,
                program.program_uri,
                program.owner,
                program.created_at
            ],
        )?;
        Ok(())
    }

    pub fn queue_counts(&self, signer: &str) -> Result<(usize, usize, usize)> {
        let connection = self.connection.lock().unwrap();
        let global: usize = connection.query_row(
            "SELECT count(*) FROM jobs WHERE state='queued'",
            [],
            |row| row.get(0),
        )?;
        let queued: usize = connection.query_row(
            "SELECT count(*) FROM jobs WHERE state='queued' AND signer=?1",
            [signer],
            |row| row.get(0),
        )?;
        let active: usize = connection.query_row(
            "SELECT count(*) FROM jobs WHERE state='running' AND signer=?1",
            [signer],
            |row| row.get(0),
        )?;
        Ok((global, queued, active))
    }

    pub fn insert_job(
        &self,
        request_id: &[u8],
        signer: &str,
        request: &RequestProofRequestBody,
    ) -> Result<bool> {
        let encoded = request.encode_to_vec();
        let changed = self.connection.lock().unwrap().execute(
            "INSERT OR IGNORE INTO jobs(request_id,signer,request,state,created_at,updated_at) VALUES(?1,?2,?3,'queued',?4,?4)",
            params![request_id, signer, encoded, now()],
        )?;
        Ok(changed == 1)
    }

    pub fn next_job(&self) -> Result<Option<Job>> {
        let mut connection = self.connection.lock().unwrap();
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id: Option<Vec<u8>> = tx
            .query_row(
                "SELECT request_id FROM jobs WHERE state='queued' ORDER BY created_at LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(id) = id else {
            return Ok(None);
        };
        tx.execute(
            "UPDATE jobs SET state='running',updated_at=?1 WHERE request_id=?2",
            params![now(), id],
        )?;
        tx.commit()?;
        drop(connection);
        self.job(&id)
    }

    pub fn job(&self, request_id: &[u8]) -> Result<Option<Job>> {
        self.connection.lock().unwrap().query_row(
            "SELECT signer,request,state,proof_path,proof_token_hash,proof_token,proof_token_expires_at,error FROM jobs WHERE request_id=?1", [request_id],
            |row| {
                let bytes: Vec<u8> = row.get(1)?;
                let request = RequestProofRequestBody::decode(bytes.as_slice()).map_err(|e| rusqlite::Error::FromSqlConversionFailure(bytes.len(), rusqlite::types::Type::Blob, Box::new(e)))?;
                let state_text: String = row.get(2)?;
                let state = JobState::parse(&state_text).map_err(|e| rusqlite::Error::FromSqlConversionFailure(state_text.len(), rusqlite::types::Type::Text, e.into()))?;
                Ok(Job { request_id: request_id.to_vec(), signer: row.get(0)?, request, state, proof_path: row.get::<_, Option<String>>(3)?.map(PathBuf::from), proof_token_hash: row.get(4)?, proof_token: row.get(5)?, proof_token_expires_at: row.get(6)?, error: row.get(7)? })
            },
        ).optional().map_err(Into::into)
    }

    pub fn fulfill(
        &self,
        request_id: &[u8],
        proof: &[u8],
        token_lifetime: u64,
        retained_maximum: u64,
    ) -> Result<String> {
        let connection = self.connection.lock().unwrap();
        let artifact_bytes: u64 = connection.query_row(
            "SELECT coalesce(sum(expanded_size),0) FROM artifacts WHERE object_hash IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let proof_bytes: u64 = connection.query_row(
            "SELECT coalesce(sum(proof_size),0) FROM jobs WHERE proof_path IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        if artifact_bytes
            .saturating_add(proof_bytes)
            .saturating_add(proof.len() as u64)
            > retained_maximum
        {
            bail!("retained artifact storage limit reached");
        }
        let path = self.root.join("proofs").join(hex::encode(request_id));
        atomic_write(&self.root.join("tmp"), &path, proof)?;
        let token = random_hex(32);
        let token_hash = Sha256::digest(token.as_bytes()).to_vec();
        connection.execute(
            "UPDATE jobs SET state='fulfilled',proof_path=?1,proof_size=?2,proof_token_hash=?3,proof_token=?4,proof_token_expires_at=?5,updated_at=?6 WHERE request_id=?7 AND state='running'",
            params![path.to_string_lossy(), proof.len() as u64, token_hash, token, now() + token_lifetime, now(), request_id],
        )?;
        Ok(token)
    }

    pub fn fail(&self, request_id: &[u8], error: &str) -> Result<()> {
        self.connection.lock().unwrap().execute("UPDATE jobs SET state='failed',error=?1,updated_at=?2 WHERE request_id=?3 AND state='running'", params![error, now(), request_id])?;
        Ok(())
    }

    pub fn cancel(&self, request_id: &[u8], signer: &str) -> Result<bool> {
        Ok(self.connection.lock().unwrap().execute("UPDATE jobs SET state='canceled',updated_at=?1 WHERE request_id=?2 AND signer=?3 AND state IN ('queued','running')", params![now(), request_id, signer])? == 1)
    }

    pub fn proof(&self, request_id: &[u8], token: &str) -> Result<Option<Vec<u8>>> {
        let Some(job) = self.job(request_id)? else {
            return Ok(None);
        };
        if job.state != JobState::Fulfilled
            || job.proof_token_expires_at.unwrap_or_default() < now()
        {
            return Ok(None);
        }
        let expected = job
            .proof_token_hash
            .context("fulfilled job lacks proof token")?;
        let supplied = Sha256::digest(token.as_bytes());
        if subtle::ConstantTimeEq::ct_eq(expected.as_slice(), &supplied[..]).unwrap_u8() != 1 {
            return Ok(None);
        }
        Ok(Some(fs::read(
            job.proof_path.context("fulfilled job lacks proof path")?,
        )?))
    }

    pub fn cleanup(&self, upload_cutoff: u64, terminal_cutoff: u64) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "DELETE FROM artifacts WHERE object_hash IS NULL AND upload_expires_at < ?1",
            [upload_cutoff],
        )?;
        let mut statement = connection.prepare("SELECT proof_path FROM jobs WHERE state IN ('fulfilled','failed','canceled') AND updated_at < ?1 AND proof_path IS NOT NULL")?;
        let paths = statement
            .query_map([terminal_cutoff], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        connection.execute(
            "DELETE FROM jobs WHERE state IN ('fulfilled','failed','canceled') AND updated_at < ?1",
            [terminal_cutoff],
        )?;
        drop(connection);
        for path in paths {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

fn decompress_limited(compressed: &[u8], maximum: u64) -> Result<Vec<u8>> {
    let decoder = zstd::stream::read::Decoder::new(compressed)?;
    let mut output = Vec::new();
    std::io::copy(&mut decoder.take(maximum + 1), &mut output)?;
    if output.len() as u64 > maximum {
        bail!("expanded artifact exceeds configured limit");
    }
    Ok(output)
}

fn atomic_write(temp_dir: &Path, final_path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = temp_dir.join(format!("{}.tmp", random_hex(12)));
    let mut file = fs::File::create(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temp, final_path)?;
    fs::File::open(final_path.parent().context("file has no parent")?)?.sync_all()?;
    Ok(())
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn random_hex(bytes: usize) -> String {
    let mut data = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut data);
    hex::encode(data)
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS nonces(signer TEXT PRIMARY KEY, nonce INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts(uri TEXT PRIMARY KEY, kind INTEGER NOT NULL, signer TEXT NOT NULL, upload_token_hash BLOB UNIQUE, upload_expires_at INTEGER, object_hash TEXT, expanded_size INTEGER, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS programs(vk_hash BLOB PRIMARY KEY, vk BLOB NOT NULL, program_uri TEXT NOT NULL UNIQUE, owner BLOB NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(request_id BLOB PRIMARY KEY, signer TEXT NOT NULL, request BLOB NOT NULL, state TEXT NOT NULL, proof_path TEXT, proof_size INTEGER, proof_token_hash BLOB, proof_token TEXT, proof_token_expires_at INTEGER, error TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(state,created_at);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn upload_is_single_use_and_decompression_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let (_, token) = storage.create_upload("0x01", 2, 60).unwrap();
        let compressed = zstd::encode_all(&b"hello"[..], 3).unwrap();
        storage
            .store_upload(&token, &compressed, 5, 5, 100)
            .unwrap();
        assert!(storage
            .store_upload(&token, &compressed, 5, 5, 100)
            .is_err());
        assert!(decompress_limited(&compressed, 4).is_err());
    }
    #[test]
    fn program_upload_decodes_the_sdk_bincode_byte_slice() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let (uri, token) = storage
            .create_upload("0x01", ArtifactType::Program as i32, 60)
            .unwrap();
        let elf = b"\x7fELFprogram".to_vec();
        let serialized = bincode::serialize(&elf).unwrap();
        let compressed = zstd::encode_all(&serialized[..], 3).unwrap();

        storage
            .store_upload(&token, &compressed, 1024, elf.len() as u64, 1024)
            .unwrap();

        let artifact = storage.artifact(&uri).unwrap().unwrap();
        assert_eq!(artifact.expanded_size, elf.len() as u64);
        assert_eq!(fs::read(artifact.path).unwrap(), elf);
    }
    #[test]
    fn nonce_is_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        storage.consume_nonce("0x01", 0).unwrap();
        assert!(storage.consume_nonce("0x01", 0).is_err());
        assert_eq!(storage.nonce("0x01").unwrap(), 1);
    }

    #[test]
    fn interrupted_running_job_is_requeued_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let request = RequestProofRequestBody {
            deadline: now() + 60,
            ..Default::default()
        };
        {
            let storage = Storage::open(dir.path()).unwrap();
            storage.insert_job(&[9; 32], "0x01", &request).unwrap();
            assert_eq!(
                storage.next_job().unwrap().unwrap().state,
                JobState::Running
            );
        }
        let storage = Storage::open(dir.path()).unwrap();
        assert_eq!(
            storage.job(&[9; 32]).unwrap().unwrap().state,
            JobState::Queued
        );
    }
}
