//! Returns *nix signal enum value from passed string

use std::convert::TryFrom;

use nix::sys::signal::Signal as NixSignal;

/// POSIX Signal
#[derive(Debug)]
pub struct Signal(NixSignal);

#[derive(Debug, thiserror::Error)]
pub enum SignalError<T> {
    #[error("invalid signal: {0}")]
    InvalidSignal(T),
}

impl TryFrom<&str> for Signal {
    type Error = SignalError<String>;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        use NixSignal::*;

        Ok(Signal(match s.to_ascii_uppercase().as_str() {
            "1" | "HUP" | "SIGHUP" => SIGHUP,
            "2" | "INT" | "SIGINT" => SIGINT,
            "3" | "QUIT" | "SIGQUIT" => SIGQUIT,
            "4" | "ILL" | "SIGILL" => SIGILL,
            "5" | "BUS" | "SIGBUS" => SIGBUS,
            "6" | "ABRT" | "IOT" | "SIGABRT" | "SIGIOT" => SIGABRT,
            "7" | "TRAP" | "SIGTRAP" => SIGTRAP,
            "8" | "FPE" | "SIGFPE" => SIGFPE,
            "9" | "KILL" | "SIGKILL" => SIGKILL,
            "10" | "USR1" | "SIGUSR1" => SIGUSR1,
            "11" | "SEGV" | "SIGSEGV" => SIGSEGV,
            "12" | "USR2" | "SIGUSR2" => SIGUSR2,
            "13" | "PIPE" | "SIGPIPE" => SIGPIPE,
            "14" | "ALRM" | "SIGALRM" => SIGALRM,
            "15" | "TERM" | "SIGTERM" => SIGTERM,
            "16" | "STKFLT" | "SIGSTKFLT" => SIGSTKFLT,
            "17" | "CHLD" | "SIGCHLD" => SIGCHLD,
            "18" | "CONT" | "SIGCONT" => SIGCONT,
            "19" | "STOP" | "SIGSTOP" => SIGSTOP,
            "20" | "TSTP" | "SIGTSTP" => SIGTSTP,
            "21" | "TTIN" | "SIGTTIN" => SIGTTIN,
            "22" | "TTOU" | "SIGTTOU" => SIGTTOU,
            "23" | "URG" | "SIGURG" => SIGURG,
            "24" | "XCPU" | "SIGXCPU" => SIGXCPU,
            "25" | "XFSZ" | "SIGXFSZ" => SIGXFSZ,
            "26" | "VTALRM" | "SIGVTALRM" => SIGVTALRM,
            "27" | "PROF" | "SIGPROF" => SIGPROF,
            "28" | "WINCH" | "SIGWINCH" => SIGWINCH,
            "29" | "IO" | "SIGIO" => SIGIO,
            "30" | "PWR" | "SIGPWR" => SIGPWR,
            "31" | "SYS" | "SIGSYS" => SIGSYS,
            _ => return Err(SignalError::InvalidSignal(s.to_string())),
        }))
    }
}

impl TryFrom<i32> for Signal {
    type Error = SignalError<i32>;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        NixSignal::try_from(value)
            .map_err(|_| SignalError::InvalidSignal(value))
            .map(Signal)
    }
}

impl From<NixSignal> for Signal {
    fn from(s: NixSignal) -> Self {
        Signal(s)
    }
}

impl Signal {
    pub(crate) fn into_raw(self) -> NixSignal {
        self.0
    }
}
