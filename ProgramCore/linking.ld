
/* Documentation: https://sourceware.org/binutils/docs/ld/Scripts.html */


OUTPUT_FORMAT(elf32-i386)   /* x86 format */
ENTRY(_start)               /* The entry point of the executable */


/*
   Segments layout.

   All of the code is in the first segment 'seg_text', which simplifies the disassembly process.
   The 'seg_other' segment contains data needed to run the executable on real computers.
 */
PHDRS
{
    seg_text    PT_LOAD;
    seg_other   PT_LOAD;
    seg_rodata  PT_LOAD;
    seg_data    PT_LOAD;
}


/* 
   Memory layout.
   
   Note that only the TEXT memory block is executable, since it is the only one which will hold decoded fetchable instructions.
   The RAM is also allocatable.
 */
MEMORY
{
    TEXT (rx) : ORIGIN = 0x010000, LENGTH = 32k
    ROM  (r)  : ORIGIN = 0x200000, LENGTH = 1M
    RAM  (aw) : ORIGIN = 0x300000, LENGTH = 1M
}


/*
    ELF file layout.
    
    The following symbols are defined:
     - rodata_start: address of the start of the read-only data section
     - rodata_end:   address of the end of the read-only data section
     - labels_pos:   address of the start of the labels section in the read-only data section
     - data_start:   address of the start of the data section
     - data_end (not exported): address of the end of the data section
     - data_size: size of the data and bss sections
 */
SECTIONS
{
    . = 0x0;

    .text : {
        *(.text)            /* Put all code sections here */
    } > TEXT                /* Put in the TEXT memory block */
      :seg_text

    .eh_frame : {
        *(.eh_frame)        /*  */
    } > TEXT
      :seg_other

    .rodata : {
        rodata_start = .;
        *(.rodata)          /* Read only data sections */
        labels_pos = .;
        *(.labels)          /* Custom sections containing labels to instructions. Placed in .rodata, else weird things happen */
        rodata_end = .;
    } > ROM
      :seg_rodata

    .data : AT(rodata_end) {
        data_start = .;
        *(.data)            /* Data sections */
        HIDDEN(data_end = .);
    } > RAM
      :seg_data

    .bss : AT(data_end) {   /* Place after the .data section */
        *(.bss)             /* Uninitialized data sections */
    } > RAM
      :seg_data

    data_size = SIZEOF(.data) + SIZEOF(.bss);

    /DISCARD/ : {           /* Discarded sections */
        *(.note.gnu.build-id)
        *(.comment)
    }
}
