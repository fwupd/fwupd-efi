OUTPUT_FORMAT("elf32-littlearm", "elf32-littlearm", "elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(_start)
SECTIONS
{
  .text 0 : {
    *(.text.head)
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
  .areloc : {
    *(.areloc)
    _evreloc = .;
    . = ALIGN(4096);
    _ereloc = .;
  } =0
  _reloc_vsize = _evreloc - _reloc;
  _reloc_size = _ereloc - _reloc;
  . = ALIGN(4096);
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
  .rel :
  {
    *(.rel.text*)
    *(.rel.data*)
    *(.rel.got)
    *(.rel.dyn)
    *(.rel.stab)

  }
  . = ALIGN(4096);
  .rel.plt : { *(.rel.plt) }
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
  . = ALIGN(4096);
  .sbom :
  {
    _sbom = .;
    *(.sbom)
    _esbom = .;
    . = ALIGN(4096);
    _epsbom = .;
  } =0
  _sbom_size = _epsbom - _sbom;
  _sbom_vsize = _esbom - _sbom;
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
  .ARM.exidx : { *(.ARM.exidx*) }
  .ARM.extab : { *(.ARM.extab*) }
  /DISCARD/ :
  {
    *(.rel.areloc)
    *(.note.GNU-stack)
  }
  .comment 0 : { *(.comment) }
}
