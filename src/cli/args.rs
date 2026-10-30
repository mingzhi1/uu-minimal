//! 极简参数解析：`--flag [value]` 加位置参数，没有短选项与 `--` 分隔符。

/// 不带值的开关：解析位置参数时只跳过它本身，不吞下一个词。
const BOOLEAN_FLAGS: [&str; 4] = ["--login", "--help", "--version", "--json"];

pub struct Args<'a> {
    items: &'a [String],
}

impl<'a> Args<'a> {
    pub fn new(items: &'a [String]) -> Self {
        Self { items }
    }

    pub fn flag(&self, name: &str) -> bool {
        self.items.iter().any(|item| item == name)
    }

    pub fn value(&self, name: &str) -> Option<&'a str> {
        self.items
            .iter()
            .position(|item| item == name)
            .and_then(|index| self.items.get(index + 1))
            .filter(|value| !value.starts_with("--"))
            .map(String::as_str)
    }

    pub fn require_device(&self) -> Result<&'a str, String> {
        self.value("--device")
            .ok_or_else(|| "缺少 --device <设备 id>（先用 `uu-minimal list` 查）".to_string())
    }

    pub fn positionals(&self) -> Vec<&'a str> {
        let mut out = Vec::new();
        let mut index = 0;
        while index < self.items.len() {
            let item = self.items[index].as_str();
            if item.starts_with("--") {
                index += if BOOLEAN_FLAGS.contains(&item) { 1 } else { 2 };
                continue;
            }
            out.push(item);
            index += 1;
        }
        out
    }
}
