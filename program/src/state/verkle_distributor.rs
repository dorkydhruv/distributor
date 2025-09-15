use pinocchio::pubkey::Pubkey;

#[repr(C)]
pub struct VerkleDistributor {
    /// Version of the airdrop
    pub version: [u8; 8],
    /// Compressed BN254 G1 root commitment (32 bytes)
    pub root: [u8; 32],
    /// [Mint] of the token to be distributed.
    pub mint: Pubkey,
    /// Token Address of the vault
    pub token_vault: Pubkey,
    /// Maximum number of tokens that can ever be claimed from this [VerkleDistributor].
    pub max_total_claim: [u8; 8],
    /// Maximum number of nodes in [VerkleDistributor].
    pub max_num_nodes: [u8; 8],
    /// Total amount of tokens that have been claimed.
    pub total_amount_claimed: [u8; 8],
    /// Number of nodes that have been claimed.
    pub num_nodes_claimed: [u8; 8],
    /// Lockup time start (Unix Timestamp)
    pub start_ts: [u8; 8],
    /// Lockup time end (Unix Timestamp)
    pub end_ts: [u8; 8],
    /// Clawback start (Unix Timestamp)
    pub clawback_start_ts: [u8; 8],
    /// Clawback receiver
    pub clawback_receiver: Pubkey,
    /// Admin wallet
    pub admin: Pubkey,
    /// Lagrange basis G1 points L_i(τ)·G1 (WIDTH=32)
    pub g1_lagrange: [[u8; 32]; 32],
    /// G2 generator
    pub g2_gen: [u8; 64],
    /// τ·G2
    pub g2_tau: [u8; 64],
    /// SRS version (for future upgrades)
    pub srs_version: u8,
    /// Whether or not the distributor has been clawed back
    pub clawed_back: u8,
    /// Bump seed.
    pub bump: u8,
}

impl VerkleDistributor {
    pub const SEED: &[u8] = b"VerkleDistributor";
    pub const LEN: usize = core::mem::size_of::<VerkleDistributor>();

    pub fn initialize(
        &mut self,
        version: u64,
        root: [u8; 32],
        mint: Pubkey,
        token_vault: Pubkey,
        max_total_claim: u64,
        max_num_nodes: u64,
        start_ts: i64,
        end_ts: i64,
        clawback_start_ts: i64,
        clawback_receiver: Pubkey,
        admin: Pubkey,
        bump: u8,
    ) {
        self.version = version.to_be_bytes();
    self.root.copy_from_slice(&root);
        self.mint = mint;
        self.token_vault = token_vault;
        self.max_total_claim = max_total_claim.to_be_bytes();
        self.max_num_nodes = max_num_nodes.to_be_bytes();
        self.start_ts = start_ts.to_be_bytes();
        self.end_ts = end_ts.to_be_bytes();
        self.clawback_start_ts = clawback_start_ts.to_be_bytes();
        self.clawback_receiver = clawback_receiver;
        self.admin = admin;
        self.clawed_back = 0;
        self.total_amount_claimed = [0; 8];
        self.num_nodes_claimed = [0; 8];
        self.bump = bump;
        self.srs_version = 0;
        // Caller must separately populate SRS fields after initialization.
        self.g1_lagrange = [[0u8;32];32];
        self.g2_gen = [0u8;64];
        self.g2_tau = [0u8;64];
    }

    pub unsafe fn unpack(data: &mut [u8]) -> &mut Self {
        assert_eq!(data.len(), Self::LEN);
        let unpacked: &mut Self = unsafe { &mut *(data.as_mut_ptr() as *mut Self) };
        unpacked
    }
}
