OUTPUT_FORMAT("elf64-littleaarch64", "elf64-littleaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)
SECTIONS
{
  . = 0;
  ImageBase = .;
  /* .hash and/or .gnu.hash MUST come first! */
  .hash : { *(.hash) }
  .gnu.hash : { *(.gnu.hash) }
  . = ALIGN(4096);
  .eh_frame : { *(.eh_frame) }
  .eh_frame_hdr : { *(.eh_frame_hdr) }
  .gcc_except_table : { *(.gcc_except_table*) }
  . = ALIGN(4096);
  .text : {
    _text = .;
    *(.text)
    *(.text.*)
    *(.gnu.linkonce.t.*)
    *(.plt)
    . = ALIGN(16);
    _etext = .;
  }
  _text_size = _etext - _text;
  . = ALIGN(65536);
  _reloc = .;
  .reloc : {
    *(.reloc)
    _ereloc = .;
  }
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
   
   /*
    * Note that these aren't the using the GNU "CONSTRUCTOR" output section
    * command, so they don't start with a size.  Because of p2align and the
    * end/END definitions, and the fact that they're mergeable, they can also
    * have NULLs which aren't guaranteed to be at the end.
    */
   . = ALIGN(16);
   __init_array_start = .;
   *(SORT(.init_array.*))
   *(.init_array)
   __init_array_end = .;
  . = ALIGN(16);
   __CTOR_LIST__ = .;
   *(SORT(.ctors.*))
   *(.ctors)
   __CTOR_END__ = .;
  . = ALIGN(16);
   __DTOR_LIST__ = .;
   *(SORT(.dtors.*))
   *(.dtors)
   __DTOR_END__ = .;
   . = ALIGN(16);
   __fini_array_start = .;
   *(SORT(.fini_array.*))
   *(.fini_array)
   __fini_array_end = .;

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
   _edata = .;
  }
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
    *(.rela.init_array*)
    *(.rela.fini_array*)
    *(.rela.ctors*)
    *(.rela.dtors*)

  }
  . = ALIGN(4096);
  .rela.plt : { *(.rela.plt) }
  . = ALIGN(4096);
  .rodata : {
    *(.rodata*)
    _erodata = .;
  }
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
  }
  _sbat_size = _epsbat - _sbat;
  _sbat_vsize = _esbat - _sbat;
  . = ALIGN(4096);
  .sbom :
  {
    _sbom = .;
    *(.sbom)
    _epsbom = .;
  }
  _sbom_size = _epsbom - _sbom;
  _image_end = .;
  _alldata_size = _image_end - _reloc;

  . = ALIGN(4096);
  .dynsym   : { *(.dynsym) }
  . = ALIGN(4096);
  .dynstr   : { *(.dynstr) }
  . = ALIGN(4096);
  .note.gnu.build-id : { *(.note.gnu.build-id) }
  /DISCARD/ :
  {
    *(.rela.reloc)
    *(.note.GNU-stack)
  }
  .comment 0 : { *(.comment) }
}
