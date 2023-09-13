pub trait Obj2Str {
    fn to_str(&self, tab_num: i8, brief_depth: i8) -> String;

    fn indent(string: &mut String, tab_num: i8) {
        if tab_num > 0 {
            string.push('\n');
            for _ in 0..tab_num {
                string.push('\t');
            }
        } else {
            string.push(' ');
        }
    }

    fn indent_last(string: &mut String, tab_num: i8) {
        if tab_num > 0 {
            string.push('\n');
            for _ in 0..(tab_num - 1) {
                string.push('\t');
            }
        } else {
            string.push(' ');
        }
    }

    fn intern_tab_num(tab_num: i8) -> i8 {
        if tab_num > 0 {
            tab_num + 1
        } else {
            0
        }
    }
}
