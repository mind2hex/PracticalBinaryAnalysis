#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

/*
  author [mind2hex - Johan Alexis]
  anpe v1.0
  Program to analyze PE files ( Portable Executable ) 
 

  STATUS CODES:
  1  -  File doesn't exist
  2  -  File isn't a PE

*/

int check_file_existence(int8_t *filename);

// DOS HEADER
int DOS_HEADER_emagic(FILE *fptr); // e_magic  MZ 0x4d 0x5a
int DOS_HEADER_lfanew(FILE *fptr); // l_fanew  read pointer from position 0x3c


int exception(int8_t *, int8_t);

int main(){
  int8_t program_status = 0;
  int8_t *filename = "EasyPass.exe";
  FILE *fptr = fopen(filename, "rb");

  
  program_status=check_file_existence(filename);
  if (program_status != 0)
    return program_status;

  
  puts("-----INSPECTING HEADER");
  program_status=DOS_HEADER_emagic(fptr);
  if (program_status != 0)
    return program_status;

  program_status=DOS_HEADER_lfanew(fptr);
  if (program_status != 0)
    return program_status;

  return 0;
}

int check_file_existence(int8_t *filename){
  if ( access(filename, F_OK) != 0 )
    // returning exit code 1 - File doesn't exist
    return exception("File doesn't exist", 1);
  
  return 0;
}

int DOS_HEADER_emagic(FILE *fptr){
  uint8_t *buffer = malloc(sizeof *buffer * 2);
  fread(buffer, 1, 2, fptr);
  if (strcmp("MZ", buffer) != 0){
    // returning exit code 2 - File isn't a PE
    return exception("File isn't a PE32", 2);
  }else{
    printf("[1] e_magic: ASCII(%s) HEX(4d 5a) (Mark Zbikowsky)\n", buffer);
    free(buffer);
    return 0;
  }
}

int DOS_HEADER_lfanew(FILE *fptr){
  uint8_t *buffer = malloc(sizeof *buffer * 2);
  fseek(fptr, 0x3c, 0);
  printf("Position of pointer: %x\n",ftell(fptr));
  fread(buffer, 1, 2, fptr);
  printf("Position of pointer: %x\n",ftell(fptr));

  printf(" %x \n", buffer);
  return 0;
}

int exception(int8_t *reason, int8_t status){
  printf("[X] ERROR: %s\n",reason);
  return status;
}
