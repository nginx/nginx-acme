// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Utilities for [`Future`]s.
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use super::Either;

pub fn race_with_delay<T, E, FL, FR, D>(left: FL, right: FR, delay: D) -> RaceWithDelay<FL, FR, D>
where
    FL: Future<Output = Result<T, E>>,
    FR: Future<Output = Result<T, E>>,
    D: Future,
{
    RaceWithDelay {
        left,
        right,
        delay,
        state: State::Initial,
    }
}

pin_project_lite::pin_project! {
pub struct RaceWithDelay<FL, FR, D> {
    #[pin]
    left: FL,
    #[pin]
    right: FR,
    #[pin]
    delay: D,
    state: State,
}
}

#[derive(PartialEq, Eq)]
enum State {
    Initial,
    PollBoth,
    PollLeft,
    PollRight,
}

impl<T, E, FL, FR, D> Future for RaceWithDelay<FL, FR, D>
where
    FL: Future<Output = Result<T, E>>,
    FR: Future<Output = Result<T, E>>,
    D: Future,
{
    type Output = Result<Either<T, T>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.state {
            State::Initial | State::PollBoth => {
                match this.left.poll(cx) {
                    Poll::Ready(Ok(x)) => return Poll::Ready(Ok(Either::Left(x))),
                    // Stop polling Left on error
                    Poll::Ready(Err(_)) => *this.state = State::PollRight,
                    _ => (),
                }

                if *this.state == State::Initial {
                    let _ = core::task::ready!(this.delay.poll(cx));
                    *this.state = State::PollBoth;
                }

                match this.right.poll(cx) {
                    Poll::Ready(Ok(x)) => return Poll::Ready(Ok(Either::Right(x))),
                    // Stop polling Right on error
                    Poll::Ready(Err(_)) => *this.state = State::PollLeft,
                    _ => (),
                }

                Poll::Pending
            }
            State::PollLeft => this.left.poll(cx).map_ok(Either::Left),
            State::PollRight => this.right.poll(cx).map_ok(Either::Right),
        }
    }
}
