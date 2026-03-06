use alloc::vec::Vec;
use core::fmt;

use crate::{
    Decoding, DuplexSpongeInterface, Encoding, NargDeserialize, StdHash, VerificationResult,
};

use super::interaction::InteractionPattern;
use super::player::PatternPlayer;

pub struct CheckedVerifierState<'a, H = StdHash>
where
    H: DuplexSpongeInterface,
{
    inner: crate::VerifierState<'a, H>,
    player: PatternPlayer,
}

impl<H> fmt::Debug for CheckedVerifierState<'_, H>
where
    H: DuplexSpongeInterface,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CheckedVerifierState<{}>", core::any::type_name::<H>())
    }
}

impl<'a, H> CheckedVerifierState<'a, H>
where
    H: DuplexSpongeInterface,
{
    pub const fn new(inner: crate::VerifierState<'a, H>, pattern: InteractionPattern) -> Self {
        Self {
            inner,
            player: PatternPlayer::new(pattern),
        }
    }

    pub fn public_message<T: Encoding<[H::U]> + 'static + ?Sized>(&mut self, message: &T) {
        self.player.expect_public_message::<T>();
        self.inner.public_message(message);
    }

    pub fn prover_message<T: Encoding<[H::U]> + NargDeserialize + 'static>(
        &mut self,
    ) -> VerificationResult<T> {
        self.player.expect_prover_message::<T>();
        self.inner.prover_message()
    }

    pub fn verifier_message<T: Decoding<[H::U]> + 'static>(&mut self) -> T {
        self.player.expect_verifier_message::<T>();
        self.inner.verifier_message()
    }

    pub fn public_messages<T: Encoding<[H::U]> + 'static>(&mut self, messages: &[T]) {
        self.player.expect_public_messages::<T>(messages.len());
        self.inner.public_messages(messages);
    }

    /// Absorbs an iterator of public messages.
    ///
    /// Unlike [`VerifierState::public_messages_iter`], this collects the iterator
    /// into a `Vec` to determine the count before checking against the pattern.
    pub fn public_messages_iter<J>(&mut self, messages: J)
    where
        J: IntoIterator,
        J::Item: Encoding<[H::U]> + 'static,
    {
        let collected: Vec<J::Item> = messages.into_iter().collect();
        self.player
            .expect_public_messages::<J::Item>(collected.len());
        self.inner.public_messages(&collected);
    }

    pub fn prover_messages<T: Encoding<[H::U]> + NargDeserialize + 'static, const N: usize>(
        &mut self,
    ) -> VerificationResult<[T; N]> {
        self.player.expect_prover_messages::<T>(N);
        self.inner.prover_messages()
    }

    pub fn prover_messages_vec<T: Encoding<[H::U]> + NargDeserialize + 'static>(
        &mut self,
        len: usize,
    ) -> VerificationResult<Vec<T>> {
        self.player.expect_prover_messages::<T>(len);
        self.inner.prover_messages_vec(len)
    }

    pub fn verifier_messages<T: Decoding<[H::U]> + 'static, const N: usize>(&mut self) -> [T; N] {
        self.player.expect_verifier_messages::<T>(N);
        core::array::from_fn(|_| self.inner.verifier_message())
    }

    pub fn verifier_messages_vec<T: Decoding<[H::U]> + 'static>(&mut self, len: usize) -> Vec<T> {
        self.player.expect_verifier_messages::<T>(len);
        (0..len).map(|_| self.inner.verifier_message()).collect()
    }

    pub fn check_eof(self) -> VerificationResult<()> {
        self.player.check_complete();
        self.inner.check_eof()
    }
}
