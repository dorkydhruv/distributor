use pinocchio::program_error::ProgramError;

#[derive(Clone, PartialEq)]
pub enum ErrorCode {
    InsufficientUnlockedTokens,
    StartTooFarInFuture,
    InvalidProof,
    ExceededMaxClaim,
    MaxNodesExceeded,
    Unauthorized,
    OwnerMismatch,
    ClawbackDuringVesting,
    ClawbackBeforeStart,
    ClawbackAlreadyClaimed,
    InsufficientClawbackDelay,
    SameClawbackReceiver,
    SameAdmin,
    ClaimExpired,
    ArithmeticError,
    StartTimestampAfterEnd,
    TimestampsNotInFuture,
    InvalidVersion,
}

impl From<ErrorCode> for ProgramError {
    fn from(e: ErrorCode) -> Self {
        Self::Custom(e as u32)
    }
}