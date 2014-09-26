ParseELF
========

Demuxes an elf file for working at the binary level.


**About**: This program parses through the header of a linux file and prints out the diffrent parts of an elf executable. It is meant to be a simplified version of the linux program *readelf*.

###Caveats
* I only built support for 32-bit elf files
* All the information about the elf is stored in a struct called *ELF* this could be useful if you wanted to remove the prints and reuse the code elsewhere.

###Use:

```
  ./elfheader [Name of Elf file]
```
