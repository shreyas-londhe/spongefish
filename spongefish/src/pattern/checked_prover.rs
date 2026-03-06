use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};

use crate::narg_prover::ReseedableRng;
use crate::{Decoding, DuplexSpongeInterface, Encoding, NargSerialize, ProverState, StdHash};

use super::interaction::InteractionPattern;
use super::player::PatternPlayer;

type StdRng = rand::rngs::StdRng;

pub struct CheckedProverState<H = StdHash, R = StdRng>
where
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    inner: ProverState<H, R>,
    player: PatternPlayer,
}

impl<H, R> CheckedProverState<H, R>
where
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    pub const fn new(inner: ProverState<H, R>, pattern: InteractionPattern) -> Self {
        Self {
            inner,
            player: PatternPlayer::new(pattern),
        }
    }

    pub const fn rng(&mut self) -> &mut ReseedableRng<R> {
        self.inner.rng()
    }

    pub const fn narg_string(&self) -> &[u8] {
        self.inner.narg_string()
    }

    pub fn public_message<T: Encoding<[H::U]> + 'static + ?Sized>(&mut self, message: &T) {
        self.player.expect_public_message::<T>();
        self.inner.public_message(message);
    }

    pub fn prover_message<T: Encoding<[H::U]> + NargSerialize + 'static + ?Sized>(
        &mut self,
        message: &T,
    ) {
        self.player.expect_prover_message::<T>();
        self.inner.prover_message(message);
    }

    pub fn verifier_message<T: Decoding<[H::U]> + 'static>(&mut self) -> T {
        self.player.expect_verifier_message::<T>();
        self.inner.verifier_message()
    }

    pub fn public_messages<T: Encoding<[H::U]> + 'static>(&mut self, messages: &[T]) {
        self.player.expect_public_messages::<T>(messages.len());
        self.inner.public_messages(messages);
    }

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

    pub fn prover_messages<T: Encoding<[H::U]> + NargSerialize + 'static>(
        &mut self,
        messages: &[T],
    ) {
        self.player.expect_prover_messages::<T>(messages.len());
        self.inner.prover_messages(messages);
    }

    pub fn prover_messages_iter<J>(&mut self, messages: J)
    where
        J: IntoIterator,
        J::Item: Encoding<[H::U]> + NargSerialize + 'static,
    {
        let collected: Vec<J::Item> = messages.into_iter().collect();
        self.player
            .expect_prover_messages::<J::Item>(collected.len());
        self.inner.prover_messages(&collected);
    }

    pub fn verifier_messages<T: Decoding<[H::U]> + 'static, const N: usize>(&mut self) -> [T; N] {
        self.player.expect_verifier_messages::<T>(N);
        self.inner.verifier_messages()
    }

    pub fn verifier_messages_vec<T: Decoding<[H::U]> + 'static>(&mut self, len: usize) -> Vec<T> {
        self.player.expect_verifier_messages::<T>(len);
        self.inner.verifier_messages_vec(len)
    }

    pub fn check_complete(self) -> ProverState<H, R> {
        self.player.check_complete();
        self.inner
    }
}
