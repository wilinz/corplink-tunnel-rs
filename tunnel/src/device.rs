//! smoltcp virtual device bridging to the WireGuard datapath via in-memory queues.
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::collections::VecDeque;

pub struct VirtDevice {
    pub rx: VecDeque<Vec<u8>>, // decrypted IP packets coming from the tunnel
    pub tx: VecDeque<Vec<u8>>, // IP packets to be encrypted and sent to the tunnel
    pub mtu: usize,
}

impl VirtDevice {
    pub fn new(mtu: usize) -> Self {
        Self { rx: VecDeque::new(), tx: VecDeque::new(), mtu }
    }
}

pub struct RxTok(Vec<u8>);
pub struct TxTok<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl<'a> TxToken for TxTok<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for VirtDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(pkt) = self.rx.pop_front() {
            // SAFETY: split borrows — rx already popped, tx is a separate field
            let tx: &mut VecDeque<Vec<u8>> = unsafe { &mut *(&mut self.tx as *mut _) };
            Some((RxTok(pkt), TxTok(tx)))
        } else {
            None
        }
    }
    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}
