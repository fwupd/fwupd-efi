OUTPUT_FORMAT("elf64-littleaarch64", "elf64-littleaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)
SECTIONS
{
  .text 0 : {
    *(.text.head)
    . = ALIGN(4096);
    _text = .;
    *(.text)
    *(.text.*)
    *(.gnu.linkonce.t.*)
    *(.plt)
    . = ALIGN(16);
    _evtext = .;
    . = ALIGN(4096);
    _etext = .;
  } =0
  _text_vsize = _evtext - _text;
  _text_size = _etext - _text;
  . = ALIGN(4096);
  _reloc = .;
  .reloc : {
    *(.reloc)
    _evreloc = .;
    . = ALIGN(4096);
    _ereloc = .;
  } =0
  _reloc_vsize = _evreloc - _reloc;
  _reloc_size = _ereloc - _reloc;
  . = ALIGN(65536);
  _data = .;
  .dynamic  : { *(.dynamic) }
  . = ALIGN(4096);
  .data :
  {
   *(.sdata)
   *(.data)
   *(.data1)
   *(.data.*)
   *(.got.plt)
   *(.got)


   /* the EFI loader doesn't seem to like a .bss section, so we stick
      it all into .data: */
   . = ALIGN(16);
   _bss = .;
   *(.sbss)
   *(.scommon)
   *(.dynbss)
   *(.bss)
   *(.bss.*)
   *(COMMON)
   . = ALIGN(16);
   _bss_end = .;
   _evdata = .;
   . = ALIGN(4096);
   _edata = .;
  } =0
  _data_vsize = _evdata - _data;
  _data_size = _edata - _data;

  . = ALIGN(4096);
  _rodata = .;
  .rela :
  {
    *(.rela.text*)
    *(.rela.data*)
    *(.rela.got)
    *(.rela.dyn)
    *(.rela.stab)

  }
  . = ALIGN(4096);
  .rela.plt : { *(.rela.plt) }
  . = ALIGN(4096);
  .rodata : {
    *(.rodata*)
    _evrodata = .;
    . = ALIGN(4096);
    _erodata = .;
  } =0
  _rodata_vsize = _evrodata - _rodata;
  _rodata_size = _erodata - _rodata;
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
  } =0
  _sbat_size = _epsbat - _sbat;
  _sbat_vsize = _esbat - _sbat;
  _image_end = .;
  _alldata_size = _image_end - _reloc;

  . = ALIGN(4096);
  .dynsym   : { *(.dynsym) }
  . = ALIGN(4096);
  .dynstr   : { *(.dynstr) }
  . = ALIGN(4096);
  .note.gnu.build-id : { *(.note.gnu.build-id) }
  . = ALIGN(4096);
  .hash : { *(.hash) }
  . = ALIGN(4096);
  .gnu.hash : { *(.gnu.hash) }
  . = ALIGN(4096);
  .eh_frame : { *(.eh_frame) }
  . = ALIGN(4096);
  .gcc_except_table : { *(.gcc_except_table*) }
  /DISCARD/ :
  {
    *(.rela.reloc)
    *(.note.GNU-stack)
  }
  .comment 0 : { *(.comment) }
}

