use smtlib::{BitVec, Bool, Sorted};

pub(crate) trait BitVecExt<'st, const M: usize> {
    fn get_bit(self, i: usize) -> Bool<'st>;
    fn ctz(self) -> BitVec<'st, M>;
    fn clz(self) -> BitVec<'st, M>;
    fn popcnt(self) -> BitVec<'st, M>;
    fn uext<const N: usize, const O: usize>(self) -> BitVec<'st, O>;
    fn sext<const N: usize, const O: usize>(self) -> BitVec<'st, O>;
    fn rol(self, shift: BitVec<'st, M>) -> BitVec<'st, M>;
    fn ror(self, shift: BitVec<'st, M>) -> BitVec<'st, M>;
    fn from_bool(val: Bool<'st>) -> BitVec<'st, M>;
}

impl<'st, const M: usize> BitVecExt<'st, M> for BitVec<'st, M> {
    fn get_bit(self, i: usize) -> Bool<'st> {
        let mask = BitVec::<M>::new(self.st(), 1 << i);
        self.bvand(mask)._neq(0)
    }

    fn ctz(self) -> BitVec<'st, M> {
        let mut cnt = BitVec::<M>::new(self.st(), 0);
        let mut seen = Bool::new(self.st(), false);
        for i in 0..M {
            seen |= self.get_bit(i);
            cnt = cnt.bvadd(BitVec::<M>::from_bool(!seen));
        }
        cnt
    }

    fn clz(self) -> BitVec<'st, M> {
        let mut cnt = BitVec::<M>::new(self.st(), 0);
        let mut seen = Bool::new(self.st(), false);
        for i in (0..M).rev() {
            seen |= self.get_bit(i);
            cnt = cnt.bvadd(BitVec::<M>::from_bool(!seen));
        }
        cnt
    }

    fn popcnt(self) -> BitVec<'st, M> {
        let mut cnt = BitVec::<M>::new(self.st(), 0);
        for i in 0..M {
            let bit = self.get_bit(i);
            cnt = cnt.bvadd(BitVec::<M>::from_bool(bit));
        }
        cnt
    }

    fn uext<const N: usize, const O: usize>(self) -> BitVec<'st, O> {
        assert_eq!(M + N, O);
        // BitVec::<N>::new(self.st(), 0).concat_dynamic(self)
        self.zero_extend_(N)
    }

    fn sext<const N: usize, const O: usize>(self) -> BitVec<'st, O> {
        assert_eq!(M + N, O);
        // let zeros = BitVec::<N>::new(self.st(), 0);
        // let ones = !zeros;
        // self.get_bit(M - 1).ite(ones, zeros).concat_(self)
        self.sign_extend_(N)
    }

    fn rol(self, _val: BitVec<'st, M>) -> BitVec<'st, M> {
        todo!()
    }

    fn ror(self, _val: BitVec<'st, M>) -> BitVec<'st, M> {
        todo!()
    }

    fn from_bool(val: Bool<'st>) -> BitVec<'st, M> {
        let zero = BitVec::<M>::new(val.st(), 0);
        let one = BitVec::<M>::new(val.st(), 1);
        val.ite(one, zero)
    }
}
