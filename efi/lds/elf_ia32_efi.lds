OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)
SECTIONS
{
  . = 0;
  ImageBase = .;
  /* .hash and/or .gnu.hash MUST come first! */
  .hash : { *(.hash) }
  .gnu.hash : { *(.gnu.hash) }
  .eh_frame : { *(.eh_frame) }
  .gcc_except_table : { *(.gcc_except_table*) }
  . = ALIGN(4096);
  .text :
  {
   _text = .;
   *(.text)
   *(.text.*)
   *(.gnu.linkonce.t.*)
   *(.plt)
   . = ALIGN(16);
  }
  _etext = .;
  _text_size = _etext - _text;
  . = ALIGN(4096);
  .data :
  {
   _data = .;
   *(.got.plt)
   *(.got)
   *(.data)
   *(.data1)
   *(.data.*)

   /* the EFI loader doesn't seem to like a .bss section, so we stick
      it all into .data: */
   *(.dynbss)
   *(.bss*)
   *(COMMON)
  }
  .note.gnu.build-id : { *(.note.gnu.build-id) }

  . = ALIGN(4096);
  .dynamic  : { *(.dynamic) }
  . = ALIGN(4096);
  .rel :
  {
    *(.rel.text*)
    *(.rel.data*)
    *(.rel.got)
    *(.rel.dyn)
    *(.rel.stab)
    *(.data.rel.ro.local)
    *(.data.rel.local)
    *(.data.rel.ro)
    *(.data.rel*)
  }
  . = ALIGN(4096);
  .rel.plt : { *(.rel.plt) }
  . = ALIGN(4096);
  .rodata : { *(.rodata*) }
  /*
   * Note that _sbat must be the beginning of the data, and _esbat must be the
   * end and must be before any section padding.  The sbat self-check uses
   * _esbat to find the bounds of the data, and if the padding is included, the
   * CSV parser (correctly) rejects the data as having NUL values in one of the
   * required columns.
   */
  . = ALIGN(4096);
  .sbat :
  {
    _sbat = .;
    *(.sbat)
    *(.sbat.*)
    _esbat = .;
    . = ALIGN(4096);
    _epsbat = .;
  }
  _sbat_size = _epsbat - _sbat;
  _sbat_vsize = _esbat - _sbat;
  _edata = .;
  _data_size = _edata - _etext;
  . = ALIGN(4096);
  .sbom : { *(.sbom) }
  . = ALIGN(4096);
  .reloc :		/* This is the PECOFF .reloc section! */
  {
    KEEP (*(.reloc))
  }
  . = ALIGN(4096);
  .dynsym   : { *(.dynsym) }
  . = ALIGN(4096);
  .dynstr   : { *(.dynstr) }
  /DISCARD/ :
  {
    *(.rel.reloc)
    *(.note.GNU-stack)
  }
  .comment 0 : { *(.comment) }
}
