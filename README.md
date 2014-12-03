ParseELF
========

Allows a user to inject an elf executable with shellcode.


**About**:  Injects shellcode using the method described in silvio's paper here: http://vxheaven.org/lib/vsc01.html

###Caveats
* Only supports 32-bit elf files
* The amount of padding between segments is limited. You might run out of space to insert shellcode.

###Use:

```
  ./elf-inject [Name of Elf file to inject] [Shellcode to inject]
```
