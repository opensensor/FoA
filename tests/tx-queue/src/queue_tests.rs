mod tests {
    use super::*;
    use crate::TX_BUFFER_SIZE;
    use core::future::Future;
    use core::pin::{Pin, pin};
    use core::task::{Context, Poll, Waker};
    use esp_wifi_hal::Radio;
    use std::sync::{Arc, atomic::AtomicUsize};
    use std::task::Wake;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn counting_waker() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount::default());
        (count.clone(), Waker::from(count))
    }

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }
    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        match poll_once(future.as_mut()) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("queue operation did not complete"),
        }
    }

    struct Fixture {
        queue: &'static TxQueue,
        pool: &'static TxBufferManager<'static>,
        radio: &'static Radio,
        endpoint: TxEndpoint<'static>,
    }
    impl Fixture {
        fn new() -> Self {
            let buffers = Box::leak(Box::new([[0; TX_BUFFER_SIZE]; TX_BUFFER_COUNT]));
            let pool = Box::leak(Box::new(TxBufferManager::new(buffers)));
            let queue = Box::leak(Box::new(TxQueue::new()));
            let radio = Box::leak(Box::new(Radio::default()));
            let beacon = Box::leak(Box::new(Mutex::new(TxQueueEndpoint::new(radio))));
            Self {
                queue,
                pool,
                radio,
                endpoint: TxEndpoint {
                    beacon_tx_endpoint: beacon,
                    dyn_tx_buffer_manager: pool,
                    edca_tx_endpoints: [queue; 4],
                    interface: 0,
                },
            }
        }
        fn enqueue(&self, marker: u8) -> PendingTransmission<'static> {
            let mut frame = self.pool.try_alloc().expect("TX pool stalled");
            frame[..3].copy_from_slice(&[marker, 0x55, 0xaa]);
            self.endpoint.transmit_edca(
                EdcaAccessCategory::default(),
                frame,
                3,
                Default::default(),
                Default::default(),
                RetryBehaviour::RetryUntil(7),
            )
        }
        fn finish_next(&self, result: Result<u8, TxError>) {
            let (active, pending) = TxQueueRunner::try_receive(self.queue).expect("pending TX");
            let mut endpoint = TxQueueEndpoint::new(self.radio);
            self.radio.complete(result);
            ready(active.transmit(pending, &mut endpoint));
        }
        fn assert_pool_recovered(&self) {
            self.queue.inner.lock(|state| {
                let state = state.borrow();
                assert_eq!(state.capacity, TX_BUFFER_COUNT);
                assert!(state.is_empty());
            });
            let buffers: Vec<_> = (0..TX_BUFFER_COUNT)
                .map(|_| {
                    self.pool
                        .try_alloc()
                        .expect("cancelled/completed frame was not returned")
                })
                .collect();
            assert!(self.pool.try_alloc().is_none());
            for buffer in &buffers {
                assert!(buffer.iter().all(|byte| *byte == 0));
            }
            drop(buffers);
            // Exercise asynchronous allocation and a new awaited TX after recovery.
            drop(ready(self.pool.alloc()));
            let handle = self.enqueue(0xfe);
            self.finish_next(Ok(2));
            let result =
                ready(handle.wait_for_completion()).expect("new awaited TX lost completion");
            assert_eq!(result.result, Ok(2));
            assert_eq!(&result.frame[..3], &[0xfe, 0x55, 0xaa]);
            drop(result);
        }
    }

    #[test]
    fn exactly_n_occupied_slots_keep_every_handle_current() {
        let f = Fixture::new();
        let handles: Vec<_> = (0..TX_BUFFER_COUNT).map(|i| f.enqueue(i as u8)).collect();
        assert!(f.pool.try_alloc().is_none());
        for handle in &handles {
            assert!(matches!(
                handle.status(),
                PendingTransmissionStatus::Pending
            ));
        }
        let (active, pending) = TxQueueRunner::try_receive(f.queue).unwrap();
        assert!(matches!(
            handles[0].status(),
            PendingTransmissionStatus::InProgress
        ));
        let mut endpoint = TxQueueEndpoint::new(f.radio);
        f.radio.complete(Ok(0));
        ready(active.transmit(pending, &mut endpoint));
        for _ in 1..TX_BUFFER_COUNT {
            f.finish_next(Ok(0));
        }
        for (i, handle) in handles.into_iter().enumerate() {
            let result =
                ready(handle.wait_for_completion()).expect("full queue invalidated live handle");
            assert_eq!(result.frame[0], i as u8);
        }
        f.assert_pool_recovered();
    }

    #[test]
    fn awaited_transmissions_keep_completions_after_multiple_slot_wraps() {
        let f = Fixture::new();
        for i in 0..(3 * TX_BUFFER_COUNT + 1) {
            let handle = f.enqueue(i as u8);
            f.finish_next(Ok((i % 7) as u8));
            let returned =
                ready(handle.wait_for_completion()).expect("reused slot forgot its waiter");
            assert_eq!(returned.frame[0], i as u8);
            assert_eq!(returned.result, Ok((i % 7) as u8));
        }
        f.assert_pool_recovered();
    }

    #[test]
    fn stale_handle_drop_cannot_cancel_new_pending_occupant() {
        let f = Fixture::new();
        let old = f.enqueue(0);
        f.finish_next(Ok(0));
        for i in 1..TX_BUFFER_COUNT {
            drop(f.enqueue(i as u8));
            f.finish_next(Ok(0));
        }
        let current = f.enqueue(99);
        assert!(matches!(
            old.status(),
            PendingTransmissionStatus::SlotNoLongerValid
        ));
        drop(old);
        f.finish_next(Ok(0));
        let result =
            ready(current.wait_for_completion()).expect("old handle cancelled new generation");
        assert_eq!(result.frame[0], 99);
        drop(result);
        f.assert_pool_recovered();
    }

    #[test]
    fn delayed_completed_future_drop_cannot_cancel_new_occupant() {
        let f = Fixture::new();
        let mut old_future = Box::pin(f.enqueue(0).wait_for_completion());
        f.finish_next(Ok(0));
        let Poll::Ready(Some(result)) = poll_once(old_future.as_mut()) else {
            panic!("completion");
        };
        drop(result);
        for i in 1..TX_BUFFER_COUNT {
            let handle = f.enqueue(i as u8);
            f.finish_next(Ok(0));
            drop(ready(handle.wait_for_completion()).unwrap());
        }
        let current = f.enqueue(99);
        drop(old_future);
        f.finish_next(Ok(0));
        assert_eq!(ready(current.wait_for_completion()).unwrap().frame[0], 99);
        f.assert_pool_recovered();
    }

    #[test]
    fn cancelled_before_pickup_still_transmits_and_returns_all_buffers() {
        let f = Fixture::new();
        for i in 0..TX_BUFFER_COUNT {
            drop(f.enqueue(i as u8));
        }
        assert!(
            f.pool.try_alloc().is_none(),
            "fire-and-forget still owns frames until TX"
        );
        for _ in 0..TX_BUFFER_COUNT {
            f.finish_next(Ok(0));
        }
        assert_eq!(f.radio.frames.borrow().len(), TX_BUFFER_COUNT);
        f.assert_pool_recovered();
    }

    #[test]
    fn cancellation_during_radio_wait_returns_all_buffers() {
        let f = Fixture::new();
        for i in 0..TX_BUFFER_COUNT {
            let handle = f.enqueue(i as u8);
            let (active, pending) = TxQueueRunner::try_receive(f.queue).unwrap();
            let mut endpoint = TxQueueEndpoint::new(f.radio);
            let mut transmitting = Box::pin(active.transmit(pending, &mut endpoint));
            assert!(poll_once(transmitting.as_mut()).is_pending());
            drop(handle);
            // Cancelling a waiter must not recycle memory still borrowed by
            // the radio/DMA operation. Only the other N-1 buffers are free.
            let spare: Vec<_> = (0..TX_BUFFER_COUNT - 1)
                .map(|_| f.pool.try_alloc().expect("unrelated buffer retained"))
                .collect();
            assert!(
                f.pool.try_alloc().is_none(),
                "active radio buffer reclaimed early"
            );
            f.radio.complete(Ok(0));
            assert!(poll_once(transmitting.as_mut()).is_ready());
            drop(spare);
        }
        f.assert_pool_recovered();
    }

    #[test]
    fn cancellation_after_finish_releases_unclaimed_completion_buffers() {
        let f = Fixture::new();
        for i in 0..TX_BUFFER_COUNT {
            let handle = f.enqueue(i as u8);
            f.finish_next(Ok(0));
            assert!(matches!(
                handle.status(),
                PendingTransmissionStatus::ReturnDataAvailable
            ));
            drop(handle);
        }
        f.assert_pool_recovered();
    }

    #[test]
    fn mixed_fire_and_forget_and_waiters_preserve_results_and_ownership() {
        let f = Fixture::new();
        for round in 0..3 {
            let mut waiters = Vec::new();
            for i in 0..TX_BUFFER_COUNT {
                let handle = f.enqueue((round * TX_BUFFER_COUNT + i) as u8);
                if i % 2 == 0 {
                    waiters.push((i, handle));
                } else {
                    drop(handle);
                }
            }
            for i in 0..TX_BUFFER_COUNT {
                f.finish_next(if i == 2 {
                    Err(TxError::AckTimeout)
                } else {
                    Ok(0)
                });
            }
            for (i, handle) in waiters {
                let result = ready(handle.wait_for_completion()).expect("waited mixed TX");
                assert_eq!(result.frame[0], (round * TX_BUFFER_COUNT + i) as u8);
                assert_eq!(result.frame_length, 3);
                assert_eq!(
                    result.result,
                    if i == 2 {
                        Err(TxError::AckTimeout)
                    } else {
                        Ok(0)
                    }
                );
            }
        }
        f.assert_pool_recovered();
    }

    #[test]
    fn overwritten_completion_returns_none_without_harming_new_generation() {
        let f = Fixture::new();
        let old = f.enqueue(0);
        f.finish_next(Ok(0));
        for i in 1..TX_BUFFER_COUNT {
            drop(f.enqueue(i as u8));
            f.finish_next(Ok(0));
        }
        let current = f.enqueue(99);
        assert!(ready(old.wait_for_completion()).is_none());
        f.finish_next(Ok(0));
        assert_eq!(ready(current.wait_for_completion()).unwrap().frame[0], 99);
        f.assert_pool_recovered();
    }

    #[test]
    fn aborting_active_runner_releases_frame_and_resolves_waiter() {
        for poll_first in [false, true] {
            let f = Fixture::new();
            let handle = f.enqueue(0);
            let (active, pending) = TxQueueRunner::try_receive(f.queue).unwrap();
            let mut endpoint = TxQueueEndpoint::new(f.radio);
            let mut transmitting = Box::pin(active.transmit(pending, &mut endpoint));
            if poll_first {
                assert!(poll_once(transmitting.as_mut()).is_pending());
            }
            drop(transmitting);
            assert!(ready(handle.wait_for_completion()).is_none());
            f.assert_pool_recovered();
        }
    }

    #[test]
    fn cancelling_wait_future_while_in_progress_releases_pool() {
        let f = Fixture::new();
        for i in 0..TX_BUFFER_COUNT {
            let mut waiter = Box::pin(f.enqueue(i as u8).wait_for_completion());
            assert!(poll_once(waiter.as_mut()).is_pending());
            let (active, pending) = TxQueueRunner::try_receive(f.queue).unwrap();
            drop(waiter);
            let mut endpoint = TxQueueEndpoint::new(f.radio);
            f.radio.complete(Err(TxError::AckTimeout));
            ready(active.transmit(pending, &mut endpoint));
        }
        f.assert_pool_recovered();
    }

    #[test]
    fn generation_counter_exhaustion_fails_before_slot_or_capacity_mutation() {
        let f = Fixture::new();
        f.queue
            .inner
            .lock(|state| state.borrow_mut().counter = u64::MAX);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.enqueue(1)));
        assert!(result.is_err());
        f.queue.inner.lock(|state| {
            let mut state = state.borrow_mut();
            assert_eq!(state.counter, u64::MAX);
            assert_eq!(state.capacity, TX_BUFFER_COUNT);
            for (slot, _, _) in &mut state.queue_items {
                assert!(matches!(slot.get_mut(), TxQueueSlot::Empty));
            }
        });
        let buffers: Vec<_> = (0..TX_BUFFER_COUNT)
            .map(|_| f.pool.try_alloc().unwrap())
            .collect();
        assert!(f.pool.try_alloc().is_none());
        drop(buffers);
    }

    #[test]
    fn enqueue_wakes_an_empty_runner() {
        let f = Fixture::new();
        let runner = TxQueueRunner {
            tx_queue: f.queue,
            tx_endpoint: TxQueueEndpoint::new(f.radio),
        };
        let mut waiting = pin!(runner.wait_queue_not_empty());
        let (count, waker) = counting_waker();
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let handle = f.enqueue(1);
        assert_eq!(
            count.0.load(Ordering::Relaxed),
            1,
            "enqueue did not wake runner"
        );
        assert!(poll_once(waiting.as_mut()).is_ready());
        f.finish_next(Ok(0));
        drop(ready(handle.wait_for_completion()).unwrap());
        f.assert_pool_recovered();
    }

    #[test]
    fn completed_transmission_wakes_its_waiter() {
        let f = Fixture::new();
        let mut waiting = Box::pin(f.enqueue(1).wait_for_completion());
        let (count, waker) = counting_waker();
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        f.finish_next(Err(TxError::AckTimeout));
        assert_eq!(
            count.0.load(Ordering::Relaxed),
            1,
            "completion did not wake caller"
        );
        let Poll::Ready(Some(result)) = poll_once(waiting.as_mut()) else {
            panic!("completion");
        };
        assert_eq!(result.result, Err(TxError::AckTimeout));
        drop(result);
        drop(waiting);
        f.assert_pool_recovered();
    }

    #[test]
    fn dropping_unclaimed_completion_wakes_a_blocked_pool_allocator() {
        let f = Fixture::new();
        let mut handles: Vec<_> = (0..TX_BUFFER_COUNT).map(|i| f.enqueue(i as u8)).collect();
        for _ in 0..TX_BUFFER_COUNT {
            f.finish_next(Ok(0));
        }
        assert!(f.pool.try_alloc().is_none());
        let mut allocating = pin!(f.pool.alloc());
        let (count, waker) = counting_waker();
        assert!(
            allocating
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(handles.pop());
        assert_eq!(
            count.0.load(Ordering::Relaxed),
            1,
            "released buffer did not wake allocator"
        );
        let Poll::Ready(buffer) = poll_once(allocating.as_mut()) else {
            panic!("pool stayed blocked");
        };
        assert!(buffer.iter().all(|byte| *byte == 0));
        drop(buffer);
        drop(handles);
        f.assert_pool_recovered();
    }
}
