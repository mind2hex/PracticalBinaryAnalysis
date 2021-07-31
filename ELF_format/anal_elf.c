/* Autor: mind2hex
   
   Description: 
   This file analyze ELF binaries thats the reason of his name
   honestly i guess anal_elf should be a better name but im still
   thinking about it.
   I developed this program to understand better the book Practical Binary Analysis
   
   Requirements:
   You need to have a copy of elf.h in your system, normally this file is in
   /usr/include/elf.h
*/

#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <stdint.h>

Elf32_Ehdr Elf32_Header;
Elf64_Ehdr Elf64_Header;

int Elf64_EH_Handler(FILE *elf_fptr){
  /* Reading e_ident */
  fread(&Elf64_Header.e_ident, sizeof(Elf64_Header.e_ident), 1, elf_fptr);

  /* Reading e_type */
  fread(&Elf64_Header.e_type, sizeof(Elf64_Header.e_type), 1, elf_fptr);

  /* Reading e_machine */
  fread(&Elf64_Header.e_machine, sizeof(Elf64_Header.e_machine), 1, elf_fptr);

  /* Reading e_version */
  fread(&Elf64_Header.e_version, sizeof(Elf64_Header.e_version), 1, elf_fptr);
  
  /* Reading e_entry   */
  fread(&Elf64_Header.e_entry, sizeof(Elf64_Header.e_entry), 1, elf_fptr);

  /* Reading e_phoff  */
  fread(&Elf64_Header.e_phoff, sizeof(Elf64_Header.e_phoff), 1, elf_fptr);
  
  /* Reading e_shoff  */
  fread(&Elf64_Header.e_shoff, sizeof(Elf64_Header.e_shoff), 1, elf_fptr);
  
  /* Reading e_flags  */
  fread(&Elf64_Header.e_flags, sizeof(Elf64_Header.e_flags), 1, elf_fptr);
  
  /* Reading e_ehsize */
  fread(&Elf64_Header.e_ehsize, sizeof(Elf64_Header.e_ehsize), 1, elf_fptr);
  
  /* Reading e_phentsize */
  fread(&Elf64_Header.e_phentsize, sizeof(Elf64_Header.e_phentsize), 1, elf_fptr);
  
  /* Reading e_phnum  */
  fread(&Elf64_Header.e_phnum, sizeof(Elf64_Header.e_phnum), 1, elf_fptr);

  /* Reading e_shentsize */
  fread(&Elf64_Header.e_shentsize, sizeof(Elf64_Header.e_shentsize), 1, elf_fptr);
  
  /* Reading e_shnum */
  fread(&Elf64_Header.e_shnum, sizeof(Elf64_Header.e_shnum), 1, elf_fptr);
  
  /* Reading e_shstrndx */
  fread(&Elf64_Header.e_shstrndx, sizeof(Elf64_Header.e_shstrndx), 1, elf_fptr);

  /* ------ Separator from reading to printing ------ */

  /* BANNER */
  printf("\n ================== ELF HEADER ==========================================================\n");
  printf(" %-25s ==== %-10s ==== %-30s\n", "e_*", "ByteIndex", "Value");
  printf(" %-25s      %-10s      ", "e_ident", "0-15");
  for(int i=0; i<16; i++){
    printf("%d ",Elf64_Header.e_ident[i]);
  }
  printf("\n");

  printf(" %-25s      %-10d      %x\n", "e_ident[EI_MAG0]",0, Elf64_Header.e_ident[0]);
  printf(" %-25s      %-10d      %c\n", "e_ident[EI_MAG1]",1, Elf64_Header.e_ident[1]);
  printf(" %-25s      %-10d      %c\n", "e_ident[EI_MAG2]",2, Elf64_Header.e_ident[2]);
  printf(" %-25s      %-10d      %c\n", "e_ident[EI_MAG3]",3, Elf64_Header.e_ident[3]);

  
  /* e_ident[EI_CLASS] */
  if ( Elf64_Header.e_ident[EI_CLASS] == ELFCLASSNONE )
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_CLASS]",4, "ELFCLASSNONE Invalid Class");

  if ( Elf64_Header.e_ident[EI_CLASS] == ELFCLASS32 )
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_CLASS]",4, "ELFCLASS32 32-bit objects");

  if ( Elf64_Header.e_ident[EI_CLASS] == ELFCLASS64 )
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_CLASS]",4, "ELFCLASS64 64-bit objects");
  
  /* e_ident[EI_DATA] */
  if ( Elf64_Header.e_ident[EI_DATA] == ELFDATANONE )
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_DATA]",5, "ELFDATANONE Invalid Data Encodin");

  if ( Elf64_Header.e_ident[EI_DATA] == ELFDATA2LSB )
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_DATA]",5, "ELFDATA2LSB 2's complement, little endian");

  if ( Elf64_Header.e_ident[EI_DATA] == ELFDATA2MSB )
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_DATA]",5, "ELFDATA2MSB 2's complement, big endian");  

  /* e_ident[EI_VERSION] */
  if ( !(Elf64_Header.e_ident[EI_VERSION] == EV_CURRENT) ){
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_VERSION]",6, "UNKNOWN|INVALID VERSION");
  }else{
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_VERSION]",6, "EV_CURRENT v1");
  }

  /* e_ident[EI_OSABI] */
  if ( Elf64_Header.e_ident[EI_OSABI] == ELFOSABI_SYSV )
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_OSABI]",7, "UNIX System V ABI");

  if ( Elf64_Header.e_ident[EI_OSABI] == ELFOSABI_HPUX )
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_OSABI]",7, "HP-UX");

  if ( Elf64_Header.e_ident[EI_OSABI] == ELFOSABI_NETBSD )
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_OSABI]",7, "NetBSD");  

  if ( Elf64_Header.e_ident[EI_OSABI] == ELFOSABI_GNU )
    printf(" %-25s      %-10d      %s\n", "e_ident[EI_OSABI]",7, "Object uses GNU ELF extensions");

  /* e_ident[EI_ABIVERSION] */
  printf(" %-25s      %-10d      %X\n", "e_ident[EI_ABIVERSION]",8, Elf64_Header.e_ident[EI_ABIVERSION]);

  /* e_ident[EI_PAD] */
  printf(" %-25s      %-10s      ", "e_ident[EI_PAD]","9-15");
  for(int i=9; i<16; i++){
    printf("%x ", Elf64_Header.e_ident[i]);
  }
  printf("\n");
  
  /* e_type */
  if ( Elf64_Header.e_type == ET_NONE)
    printf(" %-25s      %-10d      %s\n", "e_type",9, "ET_NONE No filetype");

  if ( Elf64_Header.e_type == ET_REL)
    printf(" %-25s      %-10d      %s\n", "e_type",9, "ET_REL Relocatable file");

  if ( Elf64_Header.e_type == ET_EXEC)
    printf(" %-25s      %-10d      %s\n", "e_type",9, "ET_EXEC Executable file");

  if ( Elf64_Header.e_type == ET_DYN)
    printf(" %-25s      %-10d      %s\n", "e_type",9, "ET_DYN Shared object file");

  if ( (Elf64_Header.e_type > ET_LOOS) && (Elf64_Header.e_type < ET_HIOS) )
    printf(" %-25s      %-10d      %s\n", "e_type",9, "OS-Specific");

  if ( (Elf64_Header.e_type > ET_LOPROC) && (Elf64_Header.e_type < ET_HIPROC) )
    printf(" %-25s      %-10d      %s\n", "e_type",9, "Processor-Specific");

  /* e_machine */
  if ( Elf64_Header.e_machine == EM_386 )
    printf(" %-25s      %-10d      %s\n", "e_machine",10, "EM_386 Intel 80386");

  if ( Elf64_Header.e_machine == EM_X86_64 )
    printf(" %-25s      %-10d      %s\n", "e_machine",10, "EM_X86_64 AMD X86-64 arch");

  /* e_version */
  if ( !(Elf64_Header.e_ident[EI_VERSION] == EV_CURRENT) ){
    printf(" %-25s      %-10d      %s\n", "e_version",11, "UNKNOWN|INVALID VERSION");
  }else{
    printf(" %-25s      %-10d      %s\n", "e_version",11, "EV_CURRENT v1");
  }

  /* e_entry */
  printf(" %-25s      %-10d      0x%x\n", "e_entry",12, Elf64_Header.e_entry);

  /* e_phoff */
  printf(" %-25s      %-10d      %d bytese\n", "e_phoff",13, Elf64_Header.e_phoff);

  /* e_shoff */
  printf(" %-25s      %-10d      %d bytese\n", "e_shoff",14, Elf64_Header.e_shoff);

  /* e_flags */
  printf(" %-25s      %-10d      0x%x\n", "e_flags",15, Elf64_Header.e_flags);

  /* e_ehsize */
  printf(" %-25s      %-10d      %d\n", "e_ehsize",15, Elf64_Header.e_ehsize);

  /* e_phentsize */
  printf(" %-25s      %-10d      %d\n", "e_phentsize",16, Elf64_Header.e_phentsize);

  /* e_phnum */
  printf(" %-25s      %-10d      %d\n", "e_phnum",17, Elf64_Header.e_phnum);

  /* e_shentsize */
  printf(" %-25s      %-10d      %d\n", "e_shentsize",18, Elf64_Header.e_shentsize);

  /* e_shnum */
  printf(" %-25s      %-10d      %d\n", "e_shnum",19, Elf64_Header.e_shnum);

  /* e_shstrndx */
  printf(" %-25s      %-10d      %d\n", "e_shstrndx",20, Elf64_Header.e_shstrndx);

  return 0;
}

int Elf64_SH_Handler(FILE *elf_fptr){
  fseek(elf_fptr, Elf64_Header.e_shoff, SEEK_SET);
  Elf64_Shdr Elf64_SH_Table[Elf64_Header.e_shnum];

  for( int i=0; i<Elf64_Header.e_shnum; i++){
    /* Reading sh_name */
    fread(&Elf64_SH_Table[i].sh_name, sizeof(Elf64_SH_Table[i].sh_name), 1, elf_fptr);

    /* Reading sh_type */
    fread(&Elf64_SH_Table[i].sh_type, sizeof(Elf64_SH_Table[i].sh_type), 1, elf_fptr);

    /* Reading sh_flags */
    fread(&Elf64_SH_Table[i].sh_flags, sizeof(Elf64_SH_Table[i].sh_flags), 1, elf_fptr);

    /* Reading sh_addr */
    fread(&Elf64_SH_Table[i].sh_addr, sizeof(Elf64_SH_Table[i].sh_addr), 1, elf_fptr);

    /* Reading sh_offset */
    fread(&Elf64_SH_Table[i].sh_offset, sizeof(Elf64_SH_Table[i].sh_offset), 1, elf_fptr);

    /* Reading sh_size */
    fread(&Elf64_SH_Table[i].sh_size, sizeof(Elf64_SH_Table[i].sh_size), 1, elf_fptr);

    /* Reading sh_link */
    fread(&Elf64_SH_Table[i].sh_link, sizeof(Elf64_SH_Table[i].sh_link), 1, elf_fptr);

    /* Reading sh_info */
    fread(&Elf64_SH_Table[i].sh_info, sizeof(Elf64_SH_Table[i].sh_info), 1, elf_fptr);

    /* Reading sh_addralign */
    fread(&Elf64_SH_Table[i].sh_addralign, sizeof(Elf64_SH_Table[i].sh_addralign), 1, elf_fptr);    

    /* Reading sh_entsize */
    fread(&Elf64_SH_Table[i].sh_entsize, sizeof(Elf64_SH_Table[i].sh_entsize), 1, elf_fptr);    }
  
  printf("\n ================== ELF SECTION HEADER TABLE ===========================================\n");
  printf(" [%-4s]\t%-20s %-10s %-10s %-10s\n\t%-20s %-10s %-10s\n",
	 "Indx", "Name", "Type", "Flags", "VirtAddr",
	 "Offset", "Size", "link");

  /* I guess maybe there is a better method to read a string from a file until reach
     null byte when reading the string at position
  */
  char sh_name[256];
  int position;
  size_t aux;
  for(int i=0; i<Elf64_Header.e_shnum; i++){
    /* Getting the section header name position */
    position = Elf64_SH_Table[Elf64_Header.e_shstrndx].sh_offset;
    position = position + Elf64_SH_Table[i].sh_name;
    fseek(elf_fptr, position, SEEK_SET);    // Now the file is at the correct position
    fgets(&sh_name, 256, elf_fptr);        //  but fgets maybe is not the best way to do it
    printf(" [%-04d]\t%-20s %-10d %-10d %-10d\n\t%-20d %-10d %-10d\n", i,
	   sh_name, Elf64_SH_Table[i].sh_type, Elf64_SH_Table[i].sh_flags,
	   Elf64_SH_Table[i].sh_addr, Elf64_SH_Table[i].sh_offset, Elf64_SH_Table[i].sh_size,
	   Elf64_SH_Table[i].sh_link);
  }
  
  return 0;
}

int Elf32_EH_Handler(FILE *elf_fptr){
  return 0;
}

int Elf32_SH_Handler(FILE *elf_fptr){
  return 0;
}

int main (int argc, char **argv) {

  /* Trying to open the binary file */
  FILE *fptr = fopen("./testing", "rb");
  if (!fptr){
    printf(" Error when opening the file\n");
    exit(0);
  }
  
  /* Detecting architecture [32|64] reading byte index EI_CLASS */
  uint8_t elf_arch;
  fseek(fptr, EI_CLASS, SEEK_SET);  // seeking to e_ident[EI_CLASS] --> index 4
  fread(&elf_arch, 1, 1, fptr);
  if ( !(elf_arch == ELFCLASS32) ){
    if ( !(elf_arch == ELFCLASS64) ){
      printf(" Unkown target arch of the binary: e_ident[EI_CLASS] = %d\n",elf_arch);
    }else{
      // call 64 bits elf handler
      fseek(fptr, 0, SEEK_SET);
      Elf64_EH_Handler(fptr);
      Elf64_SH_Handler(fptr);
    }
  }else{
    // Call 32 bits elf handler
    fseek(fptr, 0, SEEK_SET);    
    Elf32_EH_Handler(fptr);
    Elf32_SH_Handler(fptr);    
  }

  fclose(fptr);
  return 0;
}
