pub(crate) fn print_input_hexdump(input: &[u8]) {
    use hexyl::{BorderStyle, PrinterBuilder};
    use std::io;
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let mut printer = PrinterBuilder::new(&mut handle)
        .show_color(true)
        .show_char_panel(true)
        .show_position_panel(true)
        .with_border_style(BorderStyle::Unicode)
        .enable_squeezing(false)
        .num_panels(2)
        .group_size(1)
        .build();
    printer.print_all(input).unwrap();
}
