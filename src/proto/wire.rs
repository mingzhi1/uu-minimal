//! protobuf wire 读取器：按字段号切开报文，不解释语义。
//! 终端 RPC 与端口映射都只用字段号定位；载荷内容一律不进日志。

/// 一个字段的取值（只覆盖 protobuf 的四种非 group 类型）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    Varint(u64),
    Fixed64([u8; 8]),
    Bytes(&'a [u8]),
    Fixed32([u8; 4]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    pub number: u32,
    pub value: Value<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// 报文在读完一个字段之前就结束了。
    Cut,
    /// varint 超过 64 位。
    Overflow,
    /// 字段号 0 或超过 protobuf 上限（2^29-1）。
    Reserved,
    /// group 类型（3/4）以及不存在的类型 6/7。
    WireType(u8),
}

impl<'a> Field<'a> {
    pub fn blob(&self) -> Option<&'a [u8]> {
        match self.value {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// 目前只有终端 RPC 会按 varint 取值；`--no-default-features` 时没有使用者。
    #[cfg_attr(not(feature = "terminal"), allow(dead_code))]
    pub fn int(&self) -> Option<u64> {
        match self.value {
            Value::Varint(value) => Some(value),
            _ => None,
        }
    }
}

/// 读指针；越界一律返回 `Fault::Cut`，不 panic。
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn next_byte(&mut self) -> Result<u8, Fault> {
        let byte = *self.bytes.get(self.at).ok_or(Fault::Cut)?;
        self.at += 1;
        Ok(byte)
    }

    fn varint(&mut self) -> Result<u64, Fault> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = self.next_byte()?;
            if index == 9 {
                // 第 10 个字节只剩 1 位可用。
                if byte > 1 {
                    return Err(Fault::Overflow);
                }
                return Ok(value | (u64::from(byte) << 63));
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Fault::Overflow)
    }

    fn slice(&mut self, length: usize) -> Result<&'a [u8], Fault> {
        let end = self.at.checked_add(length).ok_or(Fault::Cut)?;
        let slice = self.bytes.get(self.at..end).ok_or(Fault::Cut)?;
        self.at = end;
        Ok(slice)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Fault> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.slice(N)?);
        Ok(out)
    }
}

/// 解析一条完整消息；嵌套的字节串保持原样，由调用方按需再解。
pub fn read_fields(input: &[u8]) -> Result<Vec<Field<'_>>, Fault> {
    let mut cursor = Cursor { bytes: input, at: 0 };
    let mut fields = Vec::new();
    while cursor.at < input.len() {
        let key = cursor.varint()?;
        let number = key >> 3;
        if number == 0 || number > 0x1fff_ffff {
            return Err(Fault::Reserved);
        }
        let value = match (key & 7) as u8 {
            0 => Value::Varint(cursor.varint()?),
            1 => Value::Fixed64(cursor.fixed::<8>()?),
            2 => {
                let length = usize::try_from(cursor.varint()?).map_err(|_| Fault::Cut)?;
                Value::Bytes(cursor.slice(length)?)
            }
            5 => Value::Fixed32(cursor.fixed::<4>()?),
            other => return Err(Fault::WireType(other)),
        };
        fields.push(Field { number: number as u32, value });
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::{read_fields, Fault, Field, Value};

    #[test]
    fn splits_varint_bytes_and_fixed32_in_order() {
        let raw = [8, 150, 1, 18, 2, 8, 3, 29, 1, 2, 3, 4];
        assert_eq!(
            read_fields(&raw),
            Ok(vec![
                Field { number: 1, value: Value::Varint(150) },
                Field { number: 2, value: Value::Bytes(&[8, 3]) },
                Field { number: 3, value: Value::Fixed32([1, 2, 3, 4]) },
            ])
        );
    }

    #[test]
    fn accessors_only_answer_for_their_own_type() {
        let fields = read_fields(&[8, 7, 18, 1, b'x']).unwrap();
        assert_eq!(fields[0].int(), Some(7));
        assert_eq!(fields[0].blob(), None);
        assert_eq!(fields[1].blob(), Some(&b"x"[..]));
        assert_eq!(fields[1].int(), None);
    }

    #[test]
    fn reports_truncation_overflow_and_bad_keys() {
        assert_eq!(read_fields(&[18, 4, 1]), Err(Fault::Cut));
        assert_eq!(read_fields(&[8, 128]), Err(Fault::Cut));
        // 10 个字节都是 0xff：第 10 字节已经超出 u64。
        let mut overlong = vec![8];
        overlong.extend_from_slice(&[255; 10]);
        assert_eq!(read_fields(&overlong), Err(Fault::Overflow));
        assert_eq!(read_fields(&[0]), Err(Fault::Reserved));
        assert_eq!(read_fields(&[11]), Err(Fault::WireType(3)));
    }

    #[test]
    fn empty_input_has_no_fields() {
        assert_eq!(read_fields(&[]), Ok(vec![]));
    }
}
