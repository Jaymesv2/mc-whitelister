
use backoff::Error;

pub trait ClassifyRetryableError: Sized {
    fn classify(self) -> Error<Self> {
        Error::transient(self)
    }
}

impl ClassifyRetryableError for sqlx::Error {
    fn classify(self) -> Error<Self> {
        match self {
            // I'm going to assume that real database errors can't be retried
            // database errors are basically always bad
            // sqlx::Error::Database(e) => { }
            sqlx::Error::BeginFailed => Error::transient(self), // not much data is given so 
            sqlx::Error::PoolTimedOut => Error::transient(self), // timeouts should be retried
            sqlx::Error::Io(e) => {
                match e.classify() {
                    Error::Permanent(e2) => Error::Permanent(sqlx::Error::Io(e2)),
                    Error::Transient {
                        err,
                        retry_after,
                    } => Error::Transient {
                        err: sqlx::Error::Io(err),
                        retry_after
                    }
                }
            }
            _ => Error::permanent(self)
        }
    }
}


impl ClassifyRetryableError for std::io::Error {
    fn classify(self) -> Error<Self> {
        use std::io::ErrorKind;
        match self.kind() {
            ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset | ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable | ErrorKind::ConnectionAborted | ErrorKind::NotConnected | ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable | ErrorKind::NetworkDown | ErrorKind::BrokenPipe | ErrorKind::AlreadyExists | ErrorKind::TimedOut | ErrorKind::ResourceBusy | ErrorKind::ExecutableFileBusy | ErrorKind::Interrupted | ErrorKind::UnexpectedEof => 
            Error::transient(self),
            _ => Error::permanent(self)

        }
    }
}


impl ClassifyRetryableError for reqwest::Error {
    fn classify(self) -> Error<Self> {
        if self.is_timeout() || self.is_request() || self.is_connect() || self.is_body() || self.is_decode() || self.is_upgrade() {
            Error::transient(self)
        } else {
            Error::permanent(self)
        }
    }
}

// impl ClassifyRetryableError for tower_sessions::session::Error {
//     fn classify(self) -> Error<Self> {
//
//     }
// }



// fn hoist() -> {
//
// }



// impl<T,E> ClassifyError for  {}
//
// pub fn classify_sqlx_error(err: sqlx::Error) -> 
