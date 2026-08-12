use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, LocalFlags, OutputFlags, SetArg, Termios};
use std::os::fd::BorrowedFd;

#[must_use]
pub struct TerminalMode(Termios);

// Enable raw mode for the terminal and return the old state to be restored
pub fn term_set_raw_mode(
    term: BorrowedFd,
    handle_signals_by_terminal: bool,
) -> Result<TerminalMode, nix::Error> {
    let mut termios = tcgetattr(term)?;
    let old_state = termios.clone();

    cfmakeraw(&mut termios);

    // Raw input only: cfmakeraw also clears OPOST, and a guest whose console
    // has no tty layer to insert carriage returns (Nanos writes bare \n to
    // its PL011) then staircases across the screen. ONLCR expands the guest's
    // \n to \r\n on output; guests that already send \r\n are unaffected.
    termios.output_flags |= OutputFlags::OPOST | OutputFlags::ONLCR;

    if handle_signals_by_terminal {
        termios.local_flags |= LocalFlags::ISIG;
    }

    tcsetattr(term, SetArg::TCSANOW, &termios)?;
    Ok(TerminalMode(old_state))
}

pub fn term_restore_mode(term: BorrowedFd, restore: &TerminalMode) -> Result<(), nix::Error> {
    tcsetattr(term, SetArg::TCSANOW, &restore.0)
}
