//! 终端交互：排版与输入。只做显示和读取，不碰网络与协议。
//!
//! 颜色只在 stdout 是终端且没设 `NO_COLOR` 时启用，管道/脚本拿到的是纯文本。

use std::io::Write;
use std::sync::OnceLock;

/// stdin 是否是终端：决定要不要进交互菜单。
pub fn is_tty() -> bool {
    stdin_is_tty()
}

#[cfg(unix)]
pub fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

#[cfg(not(unix))]
pub fn stdin_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

fn color_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var_os("NO_COLOR").is_none()
            && {
                #[cfg(unix)]
                {
                    unsafe { libc::isatty(1) == 1 }
                }
                #[cfg(not(unix))]
                {
                    use std::io::IsTerminal;
                    std::io::stdout().is_terminal()
                }
            }
    })
}

fn paint(text: &str, code: &str) -> String {
    if color_enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

pub fn bold(text: &str) -> String {
    paint(text, "1")
}

pub fn dim(text: &str) -> String {
    paint(text, "2")
}

pub fn warn(text: &str) -> String {
    paint(text, "33")
}

pub fn error_text(text: &str) -> String {
    paint(text, "31")
}

fn rule() -> String {
    dim(&"─".repeat(52))
}

/// 一级标题：命令输出的顶部。
pub fn banner(title: &str) {
    println!("{}", bold(title));
    println!("{}", rule());
}

/// 段落标题。
pub fn section(title: &str) {
    println!("\n{}", bold(title));
    println!("{}", rule());
}

pub fn hint(text: &str) {
    println!("{}", dim(text));
}

pub fn error(what: &str) {
    println!("{} {what}", error_text("错误:"));
}

/// 按终端显示宽度右补空格（CJK 算 2 列）。
pub fn pad(text: &str, width: usize) -> String {
    let used = width_of(text);
    if used >= width {
        text.to_owned()
    } else {
        format!("{text}{}", " ".repeat(width - used))
    }
}

fn width_of(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

fn char_width(c: char) -> usize {
    match c as u32 {
        0x1100..=0x115F | 0x2E80..=0x303E | 0x3041..=0x33FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF | 0xAC00..=0xD7A3 | 0xF900..=0xFAFF | 0xFE30..=0xFE6F | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6 | 0x1F300..=0x1F64F | 0x1F900..=0x1F9FF | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

/// 单行输入。返回值已 trim；回车取默认值。
pub fn prompt(question: &str, default: &str) -> String {
    if default.is_empty() {
        print!("{question}: ");
    } else {
        print!("{question} {}: ", dim(&format!("[{default}]")));
    }
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return default.to_owned();
    }
    let text = line.trim();
    if text.is_empty() {
        default.to_owned()
    } else {
        text.to_owned()
    }
}

pub fn port(question: &str, default: u16) -> Result<u16, String> {
    let text = prompt(question, &default.to_string());
    text.parse().map_err(|_| format!("{question} 不是有效端口: {text}"))
}

/// 编号菜单。空行或输入结束返回 `None`。
pub fn pick<T>(title: &str, items: &[T], label: impl Fn(&T) -> String) -> Option<usize> {
    loop {
        println!("\n{}", bold(title));
        for (index, item) in items.iter().enumerate() {
            println!("  {} {}", dim(&format!("{})", index + 1)), label(item));
        }
        print!("{} ", dim("编号:"));
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return None;
        }
        let text = line.trim();
        if text.is_empty() {
            return None;
        }
        if let Ok(number) = text.parse::<usize>() {
            if (1..=items.len()).contains(&number) {
                return Some(number - 1);
            }
        }
        println!("{}", warn("无效输入"));
    }
}

#[cfg(test)]
mod tests {
    use super::{char_width, pad};

    #[test]
    fn padding_counts_wide_characters_as_two_columns() {
        assert_eq!(pad("abc", 6), "abc   ");
        assert_eq!(char_width('中'), 2);
        assert_eq!(char_width('a'), 1);
        // "工作机" = 6 列，补到 8 列 → 2 个空格。
        assert_eq!(pad("工作机", 8), "工作机  ");
        // 已经超过宽度就原样返回，不截断。
        assert_eq!(pad("very-long-name", 4), "very-long-name");
    }
}
